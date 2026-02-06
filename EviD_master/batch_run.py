#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
batch_run.py
  python batch_run.py -i /path/to/bins --cwe 121
  python batch_run.py -i /path/to/bins --cwe 121 --no-recursive
  python batch_run.py -i /path/to/bins --cwe 121 --limit 100
"""

from __future__ import annotations

import argparse
import atexit
import builtins
import json
import logging
import os
import shutil
import signal
import sys
import time
import traceback
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from tqdm import tqdm

from Core.Controller import main_process
from Utils.Logger import slog


class TqdmLoggingHandler(logging.Handler):

    def __init__(self, stream=None, level: int = logging.NOTSET):
        super().__init__(level)
        self.stream = stream or sys.stderr

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            tqdm.write(msg, file=self.stream)
        except Exception:
            self.handleError(record)


def _patch_logger_stream_handlers_to_tqdm(logger: logging.Logger, fallback_stream=None) -> None:

    fallback_stream = fallback_stream or sys.stderr
    new_handlers: List[logging.Handler] = []

    for h in list(logger.handlers):

        if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler):
            th = TqdmLoggingHandler(stream=getattr(h, "stream", fallback_stream))
            th.setLevel(h.level)
            if h.formatter:
                th.setFormatter(h.formatter)
            for flt in getattr(h, "filters", []):
                th.addFilter(flt)
            new_handlers.append(th)
        else:
            new_handlers.append(h)

    logger.handlers = new_handlers


def patch_all_existing_loggers_for_tqdm(stream=None) -> None:

    stream = stream or sys.stderr

    # root
    _patch_logger_stream_handlers_to_tqdm(logging.getLogger(), fallback_stream=stream)

    for _, obj in logging.root.manager.loggerDict.items():
        if isinstance(obj, logging.Logger):
            _patch_logger_stream_handlers_to_tqdm(obj, fallback_stream=stream)


class TqdmPrintRedirect:

    def __init__(self, stream=None):
        self.stream = stream or sys.stderr
        self._orig_print = builtins.print

    def __enter__(self):
        def _print(*args, **kwargs):
            file = kwargs.get("file", None)
            sep = kwargs.get("sep", " ")
            end = kwargs.get("end", "\n")
            flush = kwargs.get("flush", False)

            if file is None or file in (sys.stdout, sys.stderr):
                text = sep.join(str(a) for a in args)
                tqdm.write(text, file=self.stream, end=end)
                if flush:
                    try:
                        self.stream.flush()
                    except Exception:
                        pass
            else:
                self._orig_print(*args, **kwargs)

        builtins.print = _print
        return self

    def __exit__(self, exc_type, exc, tb):
        builtins.print = self._orig_print
        return False


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def make_run_id() -> str:
    return f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def is_candidate_binary(p: Path) -> bool:

    try:
        return p.is_file() and ("." not in p.name) and os.access(p, os.X_OK)
    except OSError:
        return False


def gather_samples(input_path: Path, recursive: bool = True) -> List[Path]:

    if input_path.is_file():
        return [input_path] if is_candidate_binary(input_path) else []

    samples: List[Path] = []
    if recursive:
        for root, _, files in os.walk(input_path):
            for fn in files:
                fp = Path(root) / fn
                if is_candidate_binary(fp):
                    samples.append(fp)
    else:
        for fp in input_path.iterdir():
            if is_candidate_binary(fp):
                samples.append(fp)

    samples.sort(key=lambda x: str(x))
    return samples


def copy_sample_to_isolated_workdir(sample: Path, work_root: Path, idx: int) -> Path:

    sample_name = sample.name
    sample_dir = work_root / f"{idx:06d}_{sample_name}"
    ensure_dir(sample_dir)

    dst = sample_dir / sample_name
    shutil.copy2(sample, dst)


    try:
        dst.chmod(sample.stat().st_mode)
    except Exception:
        try:
            dst.chmod(dst.stat().st_mode | 0o111)
        except Exception:
            pass

    return dst


@dataclass
class SampleResult:
    idx: int
    sample_name: str
    original_path: str
    work_path: str
    cwe_type: str
    ok: bool
    start_time: str
    end_time: str
    duration_sec: float
    vuln_count: Optional[int] = None
    status_record: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None


class BatchCollector:
    def __init__(self, run_id: str, input_path: str, cwe_type: str, work_dir: Path, out_json: Path):
        self.run_id = run_id
        self.input_path = input_path
        self.cwe_type = cwe_type
        self.work_dir = str(work_dir)
        self.out_json = out_json

        self.start_time = now_iso()
        self.end_time: Optional[str] = None
        self.exit_reason: Optional[str] = None
        self.interrupted: bool = False

        self.candidates_total: int = 0
        self.processed_total: int = 0

        self.results: List[Dict[str, Any]] = []
        self._saved: bool = False

    def add(self, r: SampleResult) -> None:
        self.results.append(asdict(r))
        self.processed_total = len(self.results)

    def build_summary(self) -> Dict[str, Any]:
        ok_cnt = sum(1 for r in self.results if r.get("ok"))
        fail_cnt = self.processed_total - ok_cnt
        vuln_total = sum(int(r.get("vuln_count") or 0) for r in self.results if r.get("ok"))
        vuln_samples = sum(1 for r in self.results if r.get("ok") and int(r.get("vuln_count") or 0) > 0)

        err_types: Dict[str, int] = {}
        for r in self.results:
            if r.get("ok"):
                continue
            et = ((r.get("error") or {}).get("type")) or "UnknownError"
            err_types[et] = err_types.get(et, 0) + 1

        return {
            "candidates_total": self.candidates_total,
            "processed_total": self.processed_total,
            "success_total": ok_cnt,
            "failed_total": fail_cnt,
            "vuln_total": vuln_total,
            "vuln_samples": vuln_samples,
            "error_types": err_types,
            "interrupted": self.interrupted,
        }

    def to_json_obj(self) -> Dict[str, Any]:
        end_time = self.end_time or now_iso()
        meta = {
            "run_id": self.run_id,
            "start_time": self.start_time,
            "end_time": end_time,
            "exit_reason": self.exit_reason,
            "input_path": self.input_path,
            "cwe_type": self.cwe_type,
            "work_dir": self.work_dir,
            "argv": sys.argv,
            "python": sys.version,
        }
        return {
            "meta": meta,
            "summary": self.build_summary(),
            "results": self.results,
        }

    def save(self, reason: str = "normal") -> Optional[str]:

        if self._saved:
            return str(self.out_json)

        self.exit_reason = reason
        self.end_time = self.end_time or now_iso()

        ensure_dir(self.out_json.parent)

        obj = self.to_json_obj()
        tmp = self.out_json.with_suffix(self.out_json.suffix + ".tmp")
        try:
            with tmp.open("w", encoding="utf-8") as f:
                json.dump(obj, f, ensure_ascii=False, indent=2)
            tmp.replace(self.out_json)
            self._saved = True
            return str(self.out_json)
        except Exception:

            try:
                traceback.print_exc()
            except Exception:
                pass
            return None


_GLOBAL_COLLECTOR: Optional[BatchCollector] = None


def _graceful_sig_handler(signum, frame):

    raise KeyboardInterrupt(f"Received signal: {signum}")


def run_batch(input_path: Path, cwe_type: str, recursive: bool, limit: int) -> None:
    run_id = make_run_id()
    work_dir = Path.cwd() / f"work_dir_{run_id}"
    ensure_dir(work_dir)

    out_json = Path.cwd() / "Log" / f"batch_results_{run_id}.json"
    collector = BatchCollector(
        run_id=run_id,
        input_path=str(input_path),
        cwe_type=cwe_type,
        work_dir=work_dir,
        out_json=out_json,
    )

    global _GLOBAL_COLLECTOR
    _GLOBAL_COLLECTOR = collector

    atexit.register(lambda: collector.save(reason="atexit"))

    try:

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, _graceful_sig_handler)
            except Exception:
                pass


        patch_all_existing_loggers_for_tqdm(stream=sys.stderr)

        samples = gather_samples(input_path, recursive=recursive)
        if limit > 0:
            samples = samples[:limit]
        collector.candidates_total = len(samples)

        slog.info(f"[BATCH] run_id={run_id}")
        slog.info(f"[BATCH] input={input_path} recursive={recursive} cwe={cwe_type} candidates={len(samples)}")
        slog.info(f"[BATCH] work_dir={work_dir}")

        if not samples:
            collector.exit_reason = "no_candidates"
            out_path = collector.save(reason="no_candidates")
            slog.warning("[BATCH] no candidates found, exit.")
            slog.info(f"[BATCH] saved: {out_path}")
            return

        ok_cnt = 0
        fail_cnt = 0
        vuln_count = 0

        with TqdmPrintRedirect(stream=sys.stderr):
            pbar = tqdm(
                total=len(samples),
                desc=f"CWE-{cwe_type}",
                unit="bin",
                dynamic_ncols=True,
                leave=True,
                file=sys.stderr,
            )

            try:
                for idx, sample in enumerate(samples, start=1):
                    t0 = time.time()
                    st = now_iso()

                    sample_name = sample.name
                    work_path = ""

                    try:
                        work_bin = copy_sample_to_isolated_workdir(sample, work_dir, idx)
                        work_path = str(work_bin)

                        per_sample_vuln_count, status_record = main_process(
                            str(work_bin),
                            cwe_type=cwe_type,
                        )
                        # ====================================================================

                        et = now_iso()
                        dur = time.time() - t0

                        ok_cnt += 1

                        if int(per_sample_vuln_count or 0) > 0:
                            vuln_count += 1

                        collector.add(
                            SampleResult(
                                idx=idx,
                                sample_name=sample_name,
                                original_path=str(sample),
                                work_path=work_path,
                                cwe_type=cwe_type,
                                ok=True,
                                start_time=st,
                                end_time=et,
                                duration_sec=dur,
                                vuln_count=int(per_sample_vuln_count or 0),
                                status_record=status_record,
                                error=None,
                            )
                        )

                    except KeyboardInterrupt as e:
                        collector.interrupted = True
                        et = now_iso()
                        dur = time.time() - t0

                        collector.add(
                            SampleResult(
                                idx=idx,
                                sample_name=sample_name,
                                original_path=str(sample),
                                work_path=work_path,
                                cwe_type=cwe_type,
                                ok=False,
                                start_time=st,
                                end_time=et,
                                duration_sec=dur,
                                error={
                                    "type": "KeyboardInterrupt",
                                    "msg": str(e),
                                    "traceback": traceback.format_exc(),
                                },
                            )
                        )


                        pbar.update(1)
                        pbar.set_postfix({"ok": ok_cnt, "fail": fail_cnt, "vuln_count": vuln_count})
                        break

                    except Exception as e:
                        fail_cnt += 1
                        et = now_iso()
                        dur = time.time() - t0

                        collector.add(
                            SampleResult(
                                idx=idx,
                                sample_name=sample_name,
                                original_path=str(sample),
                                work_path=work_path,
                                cwe_type=cwe_type,
                                ok=False,
                                start_time=st,
                                end_time=et,
                                duration_sec=dur,
                                error={
                                    "type": type(e).__name__,
                                    "msg": str(e),
                                    "traceback": traceback.format_exc(),
                                },
                            )
                        )

                    pbar.update(1)
                    pbar.set_postfix({"ok": ok_cnt, "fail": fail_cnt, "vuln_count": vuln_count})

            finally:
                pbar.close()

        out_path = collector.save(reason="interrupted" if collector.interrupted else "normal")
        summary = collector.build_summary()

        slog.white(json.dumps(summary, ensure_ascii=False, indent=2))
        slog.info(f"[BATCH] saved: {out_path}")

    finally:
        try:
            shutil.rmtree(work_dir)
            slog.info(f"[BATCH] cleaned work_dir: {work_dir}")
        except Exception as e:
            slog.warning(f"[BATCH] failed to clean work_dir={work_dir}: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Batch wrapper for Core.Controller.main_process (direct_flag=False, no static_sinks)."
    )
    parser.add_argument("-i", "--input", required=True, help="PATH")
    parser.add_argument("--cwe", required=True, help='CWE type, e.g. "121"')
    parser.add_argument("--no-recursive", action="store_true", help="Do not recursively scan subdirectories")
    parser.add_argument("--limit", type=int, default=0, help="Process at most the first N samples (0 means no limit)")
    args = parser.parse_args()

    input_path = Path(args.input).expanduser().resolve()
    cwe_type = str(args.cwe).strip()
    recursive = not args.no_recursive
    limit = int(args.limit or 0)

    if not input_path.exists():
        raise SystemExit(f"[FATAL] input path not exists: {input_path}")

    try:
        run_batch(input_path=input_path, cwe_type=cwe_type, recursive=recursive, limit=limit)
    except Exception as e:
        global _GLOBAL_COLLECTOR
        if _GLOBAL_COLLECTOR is not None:
            _GLOBAL_COLLECTOR.interrupted = True
            _GLOBAL_COLLECTOR.save(reason=f"fatal:{type(e).__name__}")
        raise


if __name__ == "__main__":
    main()
