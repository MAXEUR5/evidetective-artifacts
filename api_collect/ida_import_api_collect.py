#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, List

from tqdm import tqdm


def is_executable_sample(path: Path) -> bool:

    if not path.is_file():
        return False
    if "." in path.name:
        return False
    try:
        return os.access(str(path), os.X_OK)
    except OSError:
        return False


def iter_samples(root: Path, recursive: bool = True) -> List[Path]:

    samples: List[Path] = []
    if recursive:
        for dirpath, _, filenames in os.walk(root):
            d = Path(dirpath)
            for name in filenames:
                p = d / name
                if is_executable_sample(p):
                    samples.append(p)
    else:
        for p in root.iterdir():
            if is_executable_sample(p):
                samples.append(p)
    return samples


def pick_better(old: Dict[str, str], new: Dict[str, str]) -> Dict[str, str]:

    old_proto = (old.get("proto") or "").strip()
    new_proto = (new.get("proto") or "").strip()
    old_lib = (old.get("lib") or "").strip()
    new_lib = (new.get("lib") or "").strip()

    if not old_proto and new_proto:
        return new
    if old_proto and new_proto and len(new_proto) > len(old_proto):
        return new
    if old_lib in ("dynsym", ".dynsym") and new_lib and new_lib not in ("dynsym", ".dynsym"):
        return new
    return old


def chunk_list(lst: List[Path], num_chunks: int) -> List[List[Path]]:

    n = len(lst)
    if n == 0 or num_chunks <= 1:
        return [lst]
    if num_chunks > n:
        num_chunks = n
    base = n // num_chunks
    rem = n % num_chunks
    chunks: List[List[Path]] = []
    start = 0
    for i in range(num_chunks):
        size = base + (1 if i < rem else 0)
        end = start + size
        chunks.append(lst[start:end])
        start = end
    return chunks


def run_ida_on_sample(
    ida_path: Path,
    script_path: Path,
    sample_src: Path,
    sample_dst_dir: Path,
    timeout_sec: int,
) -> List[dict]:

    sample_dst_dir.mkdir(parents=True, exist_ok=True)
    dst_bin = sample_dst_dir / sample_src.name

    shutil.copy2(str(sample_src), str(dst_bin))

    log_path = sample_dst_dir / "ida.log"
    json_path = sample_dst_dir / "import_api_with_proto.json"

    for p in (log_path, json_path):
        try:
            p.unlink()
        except FileNotFoundError:
            pass

    ida_exe = ida_path.resolve()
    script = script_path.resolve()

    # ida -A -L"xxx.log" -S"imp_api_dump.py" "binary"
    cmd = (
        f'"{ida_exe}" -A '
        f'-L"{log_path}" '
        f'-S"{script}" '
        f'"{dst_bin}"'
    )

    try:
        subprocess.run(
            cmd,
            check=True,
            timeout=timeout_sec,
            shell=True,
            cwd=str(sample_dst_dir),
        )
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"IDA timeout: {sample_src}") from e
    except subprocess.CalledProcessError as e:
        log_txt = ""
        if log_path.exists():
            try:
                log_txt = log_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                pass
        raise RuntimeError(
            f"IDA failed for {sample_src}\n"
            f"cmd={cmd}\n"
            f"--- ida.log (head 4000) ---\n{log_txt[:4000]}"
        ) from e

    if not json_path.exists():
        log_txt = ""
        if log_path.exists():
            try:
                log_txt = log_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                pass
        raise RuntimeError(
            f"Output JSON not found: {json_path}\n"
            f"cmd={cmd}\n"
            f"--- ida.log (head 4000) ---\n{log_txt[:4000]}"
        )

    try:
        data = json.loads(json_path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        raise RuntimeError(f"JSON decode error in {json_path}: {e}") from e

    if not isinstance(data, list):
        raise RuntimeError(f"Unexpected JSON format in {json_path}: {type(data)}")

    return data


def worker_thread(
    worker_id: int,
    samples: List[Path],
    ida_path: Path,
    script_path: Path,
    work_dir: Path,
    timeout_sec: int,
    api_map: Dict[str, Dict[str, str]],
    errors: List[Dict[str, str]],
    api_lock: threading.Lock,
    err_lock: threading.Lock,
    overall_bar: "tqdm",
    overall_lock: threading.Lock,
    stop_event: threading.Event,
) -> None:

    if not samples:
        return

    thread_bar = tqdm(
        total=len(samples),
        desc=f"Worker-{worker_id}",
        position=worker_id + 1,
        leave=False,
        unit="file",
    )

    for sample in samples:
        if stop_event.is_set():
            break

        sample_dir_name = f"t{worker_id}_{sample.name}"
        sample_dst_dir = work_dir / sample_dir_name

        try:
            records = run_ida_on_sample(
                ida_path=ida_path,
                script_path=script_path,
                sample_src=sample,
                sample_dst_dir=sample_dst_dir,
                timeout_sec=timeout_sec,
            )

            for rec in records:
                func = (rec.get("func") or "").strip()
                if not func:
                    continue
                cand = {
                    "lib": (rec.get("lib") or "").strip(),
                    "proto": (rec.get("proto") or "").strip(),
                }
                with api_lock:
                    if func not in api_map:
                        api_map[func] = cand
                    else:
                        api_map[func] = pick_better(api_map[func], cand)
        except Exception as e:

            print(f"[!] ERROR [{sample}]: {e}", flush=True)
            with err_lock:
                errors.append({"binary": str(sample), "error": str(e)})

        thread_bar.update(1)
        with overall_lock:
            overall_bar.update(1)

    thread_bar.close()


def write_outputs(
    api_map: Dict[str, Dict[str, str]],
    errors: List[Dict[str, str]],
    out_path: Path,
    as_list: bool,
) -> None:

    out_path.parent.mkdir(parents=True, exist_ok=True)


    if as_list:
        data = [
            {"func": k, "lib": v.get("lib", ""), "proto": v.get("proto", "")}
            for k, v in api_map.items()
        ]
        data.sort(key=lambda x: x["func"])
    else:

        data = dict(sorted(api_map.items(), key=lambda kv: kv[0]))

    out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    err_path = out_path.with_suffix(out_path.suffix + ".errors.json")
    err_path.write_text(json.dumps(errors, indent=2, ensure_ascii=False), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="FETCH APIs"
    )
    ap.add_argument("input_dir", help="Directory to scan (containing samples)")
    ap.add_argument("--ida", required=True, help="Path to IDA main executable (your ida 9.1 executable)")
    ap.add_argument("--script", required=True, help="Path to IDAPython script (imp_api_dump.py)")
    ap.add_argument("--out", required=True, help="Output JSON path (aggregated unique API set)")
    ap.add_argument("--work-dir", default=None, help="Base path for work_dir (default is randomly created in current directory)")
    ap.add_argument("--no-recursive", action="store_true", help="Do not recurse into subdirectories, only process input_dir level")
    ap.add_argument("--as-list", action="store_true", help="Output as list[{func,lib,proto}] instead of dict")
    ap.add_argument("--timeout", type=int, default=900, help="IDA timeout per sample (seconds)")
    ap.add_argument("--workers", type=int, default=4, help="Number of threads for parallel IDA runs (default 4)")

    args = ap.parse_args()

    root = Path(args.input_dir).resolve()
    if not root.exists():
        raise SystemExit(f"input_dir not exists: {root}")

    ida_path = Path(args.ida).resolve()
    script_path = Path(args.script).resolve()
    out_path = Path(args.out).resolve()

    if args.work_dir:
        work_dir = Path(args.work_dir).resolve()
    else:
        ts = int(time.time())
        work_dir = Path.cwd() / f"work_dir_{ts}_{os.getpid()}"
    work_dir.mkdir(parents=True, exist_ok=True)

    recursive = not args.no_recursive
    print(f"[+] input_dir : {root}")
    print(f"[+] ida       : {ida_path}")
    print(f"[+] script    : {script_path}")
    print(f"[+] out       : {out_path}")
    print(f"[+] work_dir  : {work_dir}")
    print(f"[+] recursive : {recursive}")
    print(f"[+] workers   : {args.workers}")
    print("[-] Scanning samples (filenames without dots and executable)...")

    samples = iter_samples(root, recursive=recursive)
    if not samples:
        print("[!] No matching samples found (filenames without '.' and executable).")
        api_map: Dict[str, Dict[str, str]] = {}
        errors: List[Dict[str, str]] = []
        write_outputs(api_map, errors, out_path, as_list=bool(args.as_list))
        return 0

    print(f"[+] Found samples: {len(samples)}")

    num_workers = max(1, int(args.workers))
    if num_workers > len(samples):
        num_workers = len(samples)
    chunks = chunk_list(samples, num_workers)

    api_map: Dict[str, Dict[str, str]] = {}
    errors: List[Dict[str, str]] = []
    api_lock = threading.Lock()
    err_lock = threading.Lock()
    overall_lock = threading.Lock()
    stop_event = threading.Event()

    def handle_signal(signum, frame):
        print(f"\n[!] Received signal {signum}, stopping, waiting for threads to finish and saving existing results...", flush=True)
        stop_event.set()

    try:
        signal.signal(signal.SIGINT, handle_signal)
    except Exception:
        pass
    try:
        signal.signal(signal.SIGTERM, handle_signal)
    except Exception:
        pass

    overall_bar = tqdm(
        total=len(samples),
        desc="Total",
        position=0,
        unit="file",
    )

    threads: List[threading.Thread] = []
    try:
        for idx, chunk in enumerate(chunks):
            t = threading.Thread(
                target=worker_thread,
                args=(
                    idx,
                    chunk,
                    ida_path,
                    script_path,
                    work_dir,
                    int(args.timeout),
                    api_map,
                    errors,
                    api_lock,
                    err_lock,
                    overall_bar,
                    overall_lock,
                    stop_event,
                ),
                daemon=True,
            )
            threads.append(t)
            t.start()

        for t in threads:
            t.join()
    finally:
        overall_bar.close()
        with api_lock:
            api_snapshot = dict(api_map)
        with err_lock:
            err_snapshot = list(errors)
        write_outputs(api_snapshot, err_snapshot, out_path, as_list=bool(args.as_list))

    print(f"[+] unique APIs : {len(api_map)}")
    print(f"[+] result      : {out_path}")
    print(f"[+] errors      : {len(errors)}  (详见 {out_path}.errors.json)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
