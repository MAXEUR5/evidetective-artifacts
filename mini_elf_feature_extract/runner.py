import json
import os
import re
import shutil
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from utils.logger import slog


def _log_clean(log_path: str) -> None:
    try:
        p = Path(log_path)
        if p.is_file():
            p.unlink()
    except Exception:
        pass


def _read_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8", errors="ignore") as fp:
        return json.load(fp)


def _safe_unlink(p: Path) -> bool:
    try:
        p.unlink()
        return True
    except PermissionError:
        try:
            os.chmod(p, os.stat(p).st_mode | stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
            p.unlink()
            return True
        except Exception:
            return False
    except Exception:
        return False


@dataclass
class IDAConfig:
    ida32_path: str
    ida64_path: Optional[str] = None
    ida_scripts_dir: str = ""
    log_path: str = "./ida_batch.log"
    timeout_sec: int = 600
    sleep_gap_sec: float = 0.02

    def pick_ida_path(self, elf_bits: int) -> str:
        """Choose ida executable by ELF class (32/64)."""
        if elf_bits == 64 and self.ida64_path:
            return self.ida64_path
        return self.ida32_path


class RunnerEntity:
    """A minimal runner that reuses existing IDAPython scripts (no new scripts)."""

    def __init__(self, ida_cfg: IDAConfig, target_bin_path: str, elf_bits: int) -> None:
        self.ida_cfg = ida_cfg
        self.target_bin_path = str(Path(target_bin_path).resolve())
        self.elf_bits = int(elf_bits)

        scripts_dir = Path(self.ida_cfg.ida_scripts_dir).resolve()
        self.analysis_init_dir = scripts_dir / "analysis_init"
        if not self.analysis_init_dir.is_dir():
            raise FileNotFoundError(f"analysis_init dir not found: {self.analysis_init_dir}")

    # -------------------- housekeeping --------------------

    def ext_clean(self) -> None:
        """Clean IDA-generated artifacts in the binary directory."""
        suffixes = {
            ".json",
            ".til",
            ".o",
            ".s",
            ".i64",
            ".i32",
            ".id0",
            ".id1",
            ".id2",
            ".id3",
            ".nam",
        }

        target_dir = Path(self.target_bin_path).resolve().parent
        if not target_dir.is_dir():
            slog.warning(f"ext_clean: target_dir missing: {target_dir}")
            return

        deleted = 0
        failed = 0
        for p in target_dir.iterdir():
            try:
                if not p.is_file():
                    continue
                if p.suffix.lower() not in suffixes:
                    continue
            except Exception:
                continue

            if _safe_unlink(p):
                deleted += 1
            else:
                failed += 1

        if deleted or failed:
            slog.debug(f"ext_clean: deleted={deleted}, failed={failed}, dir={target_dir}")

    # -------------------- IDA exec core --------------------

    def _run_ida_script(self, script_name: str, script_args: str = "", output_json_name: Optional[str] = None) -> Any:
        """Run an IDAPython script in batch mode and optionally read back a JSON result."""
        ida_path = self.ida_cfg.pick_ida_path(self.elf_bits)
        script_path = (self.analysis_init_dir / script_name).resolve()
        if not script_path.is_file():
            raise FileNotFoundError(f"IDA script not found: {script_path}")

        # -S expects one string: "script.py arg1=..."
        script_with_args = str(script_path)
        if script_args:
            script_with_args = f"{script_with_args} {script_args}".strip()

        target_dir = Path(self.target_bin_path).resolve().parent
        target_dir.mkdir(parents=True, exist_ok=True)

        _log_clean(self.ida_cfg.log_path)

        # NOTE:
        # - Use cwd=target_dir so scripts that write to os.getcwd() behave as expected.
        cmd = [
            ida_path,
            "-A",
            f"-L{self.ida_cfg.log_path}",
            f"-S{script_with_args}",
            self.target_bin_path,
        ]

        slog.debug("IDA cmd: %s", " ".join(cmd))

        try:
            subprocess.run(
                cmd,
                check=True,
                timeout=self.ida_cfg.timeout_sec,
                cwd=str(target_dir),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            raise
        except Exception as e:
            # One simple retry can help when IDA auto-analysis stalls.
            time.sleep(self.ida_cfg.sleep_gap_sec)
            subprocess.run(
                cmd,
                check=True,
                timeout=self.ida_cfg.timeout_sec,
                cwd=str(target_dir),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

        time.sleep(self.ida_cfg.sleep_gap_sec)

        if output_json_name is None:
            return None

        out_path = target_dir / output_json_name
        if not out_path.exists():
            raise FileNotFoundError(f"IDA output JSON missing: {out_path}")
        return _read_json(out_path)

    # -------------------- wrappers (reuse existing scripts) --------------------

    def funcname_clean(self) -> None:
        self._run_ida_script("fn_clean_v1.py")

    def get_entry_point(self) -> Dict[str, Any]:
        return self._run_ida_script("entry_find_v1.py", output_json_name="entry_point.json")

    def fetch_internal_func(self) -> List[Dict[str, Any]]:
        return self._run_ida_script("dump_all_internal_v2.py", output_json_name="func_internal_list.json")

    def fetch_import_api(self) -> List[Dict[str, Any]]:
        return self._run_ida_script("imp_api_dump.py", output_json_name="import_api_with_proto.json")

    def get_reachable_callgraph_from_entry(self, entry_func: str) -> Dict[str, Any]:
        entry_func = (entry_func or "").strip()
        if not entry_func:
            return {}
        return self._run_ida_script(
            "reachable_callgraph_from_entry.py",
            script_args=f"start_func={entry_func}",
            output_json_name="cc_reachable_callgraph.json",
        )

    def fetch_func_calls(self, func_names: List[str]) -> Dict[str, Any]:
        if not func_names:
            return {}
        # call_find_v8 supports both "funcs_list=foo,bar" and JSON list
        funcs_arg = ",".join(func_names)
        return self._run_ida_script(
            "call_find_v8.py",
            script_args=f"funcs_list={funcs_arg}",
            output_json_name="func_call.json",
        )

    def fetch_internal_disasm(self, func_names: List[str]) -> Dict[str, Any]:
        if not func_names:
            return {}
        # dump_dis_v4 expects funcs_list=[a,b,c]
        fn_list = "[" + ",".join(func_names) + "]"
        return self._run_ida_script(
            "dump_dis_v4.py",
            script_args=f"funcs_list={fn_list}",
            output_json_name="func_dis.json",
        )

    def fetch_func_local_vars(self, func_names: List[str]) -> Dict[str, Any]:
        if not func_names:
            return {}
        funcs_arg = ",".join(func_names)
        return self._run_ida_script(
            "func_stack_dump_v6.py",
            script_args=f"funcs_list={funcs_arg}",
            output_json_name="func_stack_varmatch.json",
        )

    def fetch_global_var(self) -> Dict[str, Any]:
        return self._run_ida_script("global_find_v6.py", output_json_name="global_var_ctree_refs.json")


# -------------------- filesystem helpers (controller uses) --------------------


def is_elf_file(path: Path) -> bool:
    try:
        if not path.is_file():
            return False
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except Exception:
        return False


def parse_elf_bits(path: Path) -> int:
    """Return 32/64 by ELF EI_CLASS; 0 if not an ELF."""
    try:
        with open(path, "rb") as f:
            hdr = f.read(5)
        if len(hdr) < 5 or hdr[0:4] != b"\x7fELF":
            return 0
        ei_class = hdr[4]
        return 32 if ei_class == 1 else 64 if ei_class == 2 else 0
    except Exception:
        return 0


def copy_to_workdir(src_bin: Path, workdir: Path) -> Path:
    workdir.mkdir(parents=True, exist_ok=True)
    dst = workdir / src_bin.name
    if dst.exists():
        dst.unlink()
    shutil.copy2(src_bin, dst)
    # ensure writable (IDA will create .i64/.i32)
    try:
        os.chmod(dst, os.stat(dst).st_mode | stat.S_IWUSR)
    except Exception:
        pass
    return dst


def chunked(items: List[str], n: int) -> List[List[str]]:
    return [items[i : i + n] for i in range(0, len(items), n)]
