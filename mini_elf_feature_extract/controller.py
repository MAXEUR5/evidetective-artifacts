#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import hashlib
import json
import shutil
import threading
import secrets
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from runner import (
    IDAConfig,
    RunnerEntity,
    chunked,
    copy_to_workdir,
    is_elf_file,
    parse_elf_bits,
)
from utils.logger import slog, get_logger

from tqdm import tqdm


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def filter_internal_funcs_by_reachable(
    internal_func_list: List[Dict[str, Any]],
    entry_point_func: str,
    reachable_names: List[str],
) -> List[Dict[str, Any]]:
    """Keep only entry-reachable internal funcs (plus entry itself)."""
    entry_point_func = (entry_point_func or "").strip()
    reachable_set = set((reachable_names or []))

    reachable_funcs: List[Dict[str, Any]] = []
    for it in list(internal_func_list or []):
        fn = (it or {}).get("name")
        if not fn:
            continue
        if fn == entry_point_func:
            reachable_funcs.append(it)
            continue
        if fn in reachable_set:
            reachable_funcs.append(it)
            continue
    return reachable_funcs


def slim_disasm_dict(disasm_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Keep only disasm-related fields; drop pcode to reduce size."""
    out: Dict[str, Any] = {}
    for fn, obj in (disasm_dict or {}).items():
        if not isinstance(obj, dict):
            continue
        out[fn] = {
            "disasm": obj.get("disasm", ""),
            "disasm_enhanced": obj.get("disasm_enhanced", ""),
            "demangle_name": obj.get("demangle_name", ""),
        }
    return out


def build_call_subgraph(
    func_call_dict: Dict[str, Any],
    internal_funcs: List[str],
) -> Dict[str, Any]:
    """Construct a compact call subgraph view from call_find output."""
    internal_set = set(internal_funcs)

    internal_edges: Dict[str, List[Dict[str, Any]]] = {}
    import_edges: Dict[str, List[Dict[str, Any]]] = {}
    used_imports: List[str] = []
    used_imports_set = set()

    for src in internal_funcs:
        calls = func_call_dict.get(src, []) if isinstance(func_call_dict, dict) else []
        if not isinstance(calls, list):
            calls = []

        for c in calls:
            if not isinstance(c, dict):
                continue
            dst = c.get("name")
            cat = c.get("cat")
            if not dst or not cat:
                continue

            if cat == "USER_DEF":
                if dst in internal_set:
                    internal_edges.setdefault(src, []).append(
                        {"dst": dst, "ln": c.get("ln", 0), "call_type": c.get("call_type", "")}
                    )
            elif cat == "IMPORT_API":
                import_edges.setdefault(src, []).append(
                    {"dst": dst, "ln": c.get("ln", 0), "call_type": c.get("call_type", "")}
                )
                if dst not in used_imports_set:
                    used_imports_set.add(dst)
                    used_imports.append(dst)

    for k in list(internal_edges.keys()):
        internal_edges[k].sort(key=lambda x: (x.get("ln", 0), x.get("dst", "")))
    for k in list(import_edges.keys()):
        import_edges[k].sort(key=lambda x: (x.get("ln", 0), x.get("dst", "")))

    return {
        "internal_funcs": internal_funcs,
        "used_imports": used_imports,
        "internal_edges": internal_edges,
        "import_edges": import_edges,
    }


def discover_elf_binaries(input_dir: Path, recursive: bool = True) -> List[Path]:
    cand = list(input_dir.rglob("*")) if recursive else list(input_dir.glob("*"))
    out: List[Path] = []
    for p in cand:
        if is_elf_file(p):
            out.append(p)
    out.sort(key=lambda x: str(x))  # deterministic
    return out


def extract_one_binary(
    idx: int,
    src_bin: Path,
    workdir: Path,
    ida_cfg: IDAConfig,
    chunk_calls: int = 200,
    chunk_disasm: int = 80,
    enable_disasm: bool = True,
    enable_imports: bool = True,
) -> Dict[str, Any]:
    bits = parse_elf_bits(src_bin)
    if bits not in (32, 64):
        return {"idx": idx, "path": str(src_bin), "error": "not_elf_or_unknown_class"}

    # Copy into *this* workdir, so IDA outputs are isolated.
    workdir.mkdir(parents=True, exist_ok=True)
    work_bin = copy_to_workdir(src_bin, workdir)

    runner = RunnerEntity(ida_cfg=ida_cfg, target_bin_path=str(work_bin), elf_bits=bits)

    runner.ext_clean()
    runner.funcname_clean()

    entry_obj = runner.get_entry_point() or {}
    entry_func = (entry_obj.get("entry_func") or "").strip()

    internal_func_list = runner.fetch_internal_func() or []

    import_api_list: List[Dict[str, Any]] = []
    if enable_imports:
        try:
            import_api_list = runner.fetch_import_api() or []
        except Exception:
            import_api_list = []

    cg: Dict[str, Any] = {}
    reachable_names: List[str] = []
    if entry_func:
        cg = runner.get_reachable_callgraph_from_entry(entry_func) or {}
        if isinstance(cg, dict):
            reachable_names = cg.get("reachable_funcs") or []
            if not isinstance(reachable_names, list):
                reachable_names = []

    internal_func_list = filter_internal_funcs_by_reachable(
        internal_func_list=internal_func_list,
        entry_point_func=entry_func,
        reachable_names=reachable_names,
    )

    internal_names = [d.get("name") for d in internal_func_list if isinstance(d, dict) and d.get("name")]
    internal_names = list(dict.fromkeys(internal_names))  # de-dup keep order

    func_call_dict: Dict[str, Any] = {}
    for part in chunked(internal_names, chunk_calls):
        part_res = runner.fetch_func_calls(part) or {}
        if isinstance(part_res, dict):
            func_call_dict.update(part_res)

    disasm_dict: Dict[str, Any] = {}
    if enable_disasm:
        for part in chunked(internal_names, chunk_disasm):
            part_res = runner.fetch_internal_disasm(part) or {}
            if isinstance(part_res, dict):
                disasm_dict.update(part_res)
    disasm_dict = slim_disasm_dict(disasm_dict)

    subgraph_obj = build_call_subgraph(func_call_dict=func_call_dict, internal_funcs=internal_names)

    meta = {
        "idx": idx,
        "path": str(src_bin),
        "file_name": src_bin.name,
        "sha256": sha256_file(src_bin),
        "elf_bits": bits,
    }

    return {
        "meta": meta,
        "entry": entry_obj,
        "reachable_callgraph": cg,
        "internal_func_list": internal_func_list,
        "import_api_list": import_api_list,
        "func_call_dict": func_call_dict,
        "disasm_dict": disasm_dict,
        "call_subgraph": subgraph_obj,
    }


# --------- Thread-local work root (one per worker thread) ---------
_thread_work_root_map: Dict[int, Path] = {}
_thread_work_root_lock = threading.Lock()


def get_thread_work_root(global_work_root: Path) -> Path:
    """
    Create a per-thread directory under global_work_root:
      _work/t<threadid>_<rand>/
    """
    tid = threading.get_ident()
    with _thread_work_root_lock:
        if tid in _thread_work_root_map:
            return _thread_work_root_map[tid]
        token = secrets.token_hex(4)
        p = global_work_root / f"t{tid}_{token}"
        p.mkdir(parents=True, exist_ok=True)
        _thread_work_root_map[tid] = p
        return p


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Mini ELF feature extractor (IDA batch, with isolated workdir per binary)"
    )
    ap.add_argument("--input", required=True, help="directory containing ELF binaries")
    ap.add_argument("--output", required=True, help="output JSON path")

    ap.add_argument("--ida32", required=True, help="IDA executable (unified ida also OK)")
    ap.add_argument(
        "--ida64", default="", help="IDA executable for 64-bit (optional; if empty uses ida32)"
    )
    ap.add_argument(
        "--ida_scripts", required=True, help="directory containing analysis_init/*.py (from ida.zip)"
    )

    ap.add_argument(
        "--log", default="./ida_batch.log", help="(legacy) log path; in threads we override per-workdir"
    )
    ap.add_argument("--timeout", type=int, default=600, help="IDA batch timeout per run (seconds)")

    ap.add_argument("--recursive", action="store_true", help="recursively scan input directory")
    ap.add_argument("--no_recursive", action="store_true", help="do not scan recursively")

    ap.add_argument(
        "--work_root",
        default="",
        help="where to create workdirs (default: ./_work in current directory)",
    )
    ap.add_argument("--keep_work", action="store_true", help="keep per-binary workdirs (for debugging)")

    ap.add_argument("--max_files", type=int, default=0, help="limit number of binaries (0=all)")

    ap.add_argument("--no_disasm", action="store_true", help="skip dump_dis_v4.py")
    ap.add_argument("--no_imports", action="store_true", help="skip imp_api_dump.py")

    ap.add_argument("--chunk_calls", type=int, default=200, help="batch size for call_find_v8")
    ap.add_argument("--chunk_disasm", type=int, default=80, help="batch size for dump_dis_v4")

    ap.add_argument(
        "--log_level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="log level",
    )

    ap.add_argument("--threads", type=int, default=1, help="number of worker threads (default: 1)")

    args = ap.parse_args()

    lvl = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40}[args.log_level]
    get_logger(level=lvl)

    input_dir = Path(args.input).resolve()
    if not input_dir.is_dir():
        raise FileNotFoundError(f"input dir not found: {input_dir}")

    out_path = Path(args.output).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    recursive = True
    if args.no_recursive:
        recursive = False
    if args.recursive:
        recursive = True

    # Work root default: current directory ./_work
    if args.work_root:
        global_work_root = Path(args.work_root).resolve()
    else:
        global_work_root = (Path.cwd() / "_work").resolve()
    global_work_root.mkdir(parents=True, exist_ok=True)

    ida32_path = str(Path(args.ida32).resolve())
    ida64_path = str(Path(args.ida64).resolve()) if args.ida64 else ""

    base_ida_cfg = IDAConfig(
        ida32_path=ida32_path,
        ida64_path=ida64_path if ida64_path else None,
        ida_scripts_dir=str(Path(args.ida_scripts).resolve()),
        log_path=str(Path(args.log).resolve()),
        timeout_sec=int(args.timeout),
    )

    bins = discover_elf_binaries(input_dir, recursive=recursive)
    if args.max_files and args.max_files > 0:
        bins = bins[: args.max_files]

    slog.info(f"discovered {len(bins)} ELF files under: {input_dir}")
    if not bins:
        out_path.write_text(
            json.dumps(
                {
                    "meta": {
                        "input_dir": str(input_dir),
                        "total_files": 0,
                        "generated_at": datetime.now(timezone.utc).isoformat(),
                    },
                    "items": {},
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        slog.info(f"done (no input). output -> {out_path}")
        return 0

    threads = max(1, int(args.threads))

    result: Dict[str, Any] = {
        "meta": {
            "input_dir": str(input_dir),
            "total_files": len(bins),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "items": {},
    }

    # 总进度条
    pbar = tqdm(total=len(bins), desc="ALL", unit="bin", dynamic_ncols=True, file=sys.stdout)

    def worker(i: int, bin_path: Path) -> Dict[str, Any]:
        # Per-thread root
        thread_root = get_thread_work_root(global_work_root)
        # Per-binary workdir under per-thread root
        workdir = thread_root / f"{i:05d}"

        # Per-binary log to avoid multi-thread file IO contention
        ida_log = workdir / "ida.log"
        ida_cfg = IDAConfig(
            ida32_path=base_ida_cfg.ida32_path,
            ida64_path=base_ida_cfg.ida64_path,
            ida_scripts_dir=base_ida_cfg.ida_scripts_dir,
            log_path=str(ida_log),
            timeout_sec=base_ida_cfg.timeout_sec,
        )

        try:
            item = extract_one_binary(
                idx=i,
                src_bin=bin_path,
                workdir=workdir,
                ida_cfg=ida_cfg,
                chunk_calls=int(args.chunk_calls),
                chunk_disasm=int(args.chunk_disasm),
                enable_disasm=(not args.no_disasm),
                enable_imports=(not args.no_imports),
            )
        except Exception as e:
            item = {
                "meta": {"idx": i, "path": str(bin_path)},
                "error": f"extract_failed: {type(e).__name__}: {e}",
            }
        finally:
            if not args.keep_work:
                try:
                    shutil.rmtree(workdir, ignore_errors=True)
                except Exception:
                    pass

        return item

    # 用映射把 future 和 idx 绑定，避免从结果里再猜 idx
    future_to_idx: Dict[Any, int] = {}

    with ThreadPoolExecutor(max_workers=threads) as ex:
        for i, bin_path in enumerate(bins, start=1):
            fut = ex.submit(worker, i, bin_path)
            future_to_idx[fut] = i

        for fut in as_completed(future_to_idx):
            i = future_to_idx[fut]
            item = fut.result()
            # 主线程写 result，避免 dict 并发写
            result["items"][str(i)] = item
            pbar.update(1)

    pbar.close()

    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    slog.info(f"done. output -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
