#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import sys
import signal
import logging
import random
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic, sleep
from threading import Thread, Lock

# -- Configure this before importing pwntools to disable terminal control sequences -- #
os.environ.setdefault("PWNLIB_NOTERM", "1")

from pwn import context, process, PTY, STDOUT  # Use pwntools only
from tqdm import tqdm

# -- Stay completely quiet -- #
context.log_level = "CRITICAL"
logging.getLogger("pwnlib").setLevel(logging.CRITICAL)

# Payload collection
PAYLOADS = [
    ("C1",            b"C" * 1),
    ("C64",           b"C" * 64),
    ("C101",          b"C" * 101),
    ("C512",          b"C" * 512),
    ("C2048",         b"C" * 2048),
    ("C4096",         b"C" * 4096),
    ("C1024",         b"C" * 1024),

    ("N_n1",          b"-1"),
    ("N_0",           b"0"),
    ("N_11",          b"11"),
    ("N_101",         b"101"),
    ("N_1024",        b"1024"),
    ("N_65535",       b"65535"),
    ("N_2147483647",  b"2147483647"),
    ("N_n2147483646", b"-2147483646"),
    ("N_1073741824",  b"1073741824"),
    ("N_n1073741824", b"-1073741824"),

    ("NS_11_C11",          b"11 " + b"C"*11),
    ("NS_64_C64",          b"64 " + b"C"*64),
    ("NS_101_C101",        b"101 " + b"C"*101),
    ("NS_64_C1024",        b"64 " + b"C"*1024),
    ("NS_64_C2048",        b"64 " + b"C"*2048),
    ("NS_128_C128",        b"128 " + b"C"*128),
    ("NS_1024_C1024",      b"1024 " + b"C"*1024),
    ("NS_2048_C2048",      b"2048 " + b"C"*2048),
    ("NS_n1_C2048",        b"-1 " + b"C"*2048),
    ("NS_8192_C16",        b"8192 " + b"C"*16),
    ("NS_8192_C8192",      b"8192 " + b"C"*8192),
    ("NS_n1_C128",         b"-1 " + b"C"*128),
    ("NS_n1073741824_C2048", b"-1073741824 " + b"C"*2048),
    ("NS_1_C4096",         b"1 " + b"C"*4096),
    ("NS_2_C4096",         b"2 " + b"C"*4096),

    ("NS_0_C4096",   b"0 "  + b"C"*4096),
    ("NL_0_C4096",   b"0\n" + b"C"*4096),

    ("NL_64_C64",        b"64\n"   + b"C"*64),
    ("NL_101_C101",      b"101\n"  + b"C"*101),
    ("NL_1024_C1024",    b"1024\n" + b"C"*1024),
    ("NL_4096_C4096",    b"4096\n" + b"C"*4096),
    ("NL_n1_C4096",      b"-1\n"   + b"C"*4096),
    ("NL_1_C4096",       b"1\n"    + b"C"*4096),
    ("NL_2_C4096",       b"2\n"    + b"C"*4096),
]


def is_elf_no_suffix(p: Path) -> bool:
    """No extension + executable bit + ELF magic."""
    # Uncomment for debugging visibility
    # print(f"[DEBUG] checking: {p.name}")

    # Must be a regular file with execute permission
    if not (p.is_file() and os.access(str(p), os.X_OK)):
        return False

    # Reject files whose names contain '.'
    if "." in p.name:
        return False

    # Check the ELF magic
    try:
        with p.open("rb") as f:   # Intentionally stick with a single "rb"
            return f.read(4) == b"\x7fELF"
    except Exception as e:
        # Uncomment to see why it failed during debugging
        # print(f"[DEBUG] failed to read {p}: {e}")
        return False


def sig_name(sig_num: int) -> str:
    """Signal number -> name."""
    try:
        return signal.Signals(sig_num).name
    except Exception:
        return f"SIG{sig_num}"


def run_once_repeating_payload(
    bin_path: Path,
    payload: bytes,
    timeout_sec: float,
    step_interval: float,
    workdir: Path,
):
        """
        Run a single "continuous interaction" test with one payload:
            - Launch the target (PTY enabled to avoid line buffering)
            - While still running: sendline(payload) -> try recv -> poll
            - If the overall timeout hits: kill and return ('timeout', None)
            - If it exits with rc < 0: return ('signal', SIG*)
            - If it exits with rc >= 0: return ('normal', None)
        """
    pr = None
    with context.local(log_level="CRITICAL"):
        try:
            pr = process(
                [str(bin_path)],
                cwd=str(workdir),
                env=dict(os.environ, LC_ALL="C", LANG="C"),
                stdin=PTY,
                stdout=PTY,
                stderr=STDOUT,
            )
            deadline = monotonic() + timeout_sec
            last_send = 0.0

            while True:
                rc = pr.poll()
                if rc is not None:
                    if rc < 0:
                        return ("signal", sig_name(-rc))
                    return ("normal", None)

                now = monotonic()
                if now >= deadline:
                    try:
                        pr.kill()
                    except Exception:
                        pass
                    return ("timeout", None)

                if now - last_send >= step_interval:
                    try:
                        pr.sendline(payload)
                    except EOFError:
                        # Child already exited or closed stdin
                        pass
                    last_send = now

                try:
                    _ = pr.recv(timeout=0.02)
                except EOFError:
                    pass
                except Exception:
                    pass

                sleep(0.01)
        finally:
            if pr is not None:
                try:
                    pr.close()
                except Exception:
                    pass


def test_one_binary(
    bin_path: Path,
    tries_per_payload: int,
    timeout_sec: float,
    step_interval: float,
    workdir: Path,
):
    """
    Iterate through all payloads on a single sample.
    Return result_entry(dict):
    {
      "path": "...",
      "status": "normal"|"timeout"|"signal",
      "attempts_executed": int,
      "timeouts_total": int,
    ["signal": str, "payload_tag": str]  # Present only when status=="signal"
    }
    """
    total_runs_planned = len(PAYLOADS) * tries_per_payload

    any_signal = False
    signal_name_caught = None
    signal_payload_tag = None

    timeouts_total = 0
    attempts_executed = 0

    for tag, payload in PAYLOADS:
        for _try in range(tries_per_payload):
            attempts_executed += 1
            status, sname = run_once_repeating_payload(
                bin_path=bin_path,
                payload=payload,
                timeout_sec=timeout_sec,
                step_interval=step_interval,
                workdir=workdir,
            )

            if status == "signal":
                any_signal = True
                signal_name_caught = sname
                signal_payload_tag = tag
                break
            elif status == "timeout":
                timeouts_total += 1
            else:
                # normal / other cases remain unclassified
                pass

        if any_signal:
            break

    if any_signal:
        final_status = "signal"
    elif timeouts_total == total_runs_planned:
        final_status = "timeout"
    else:
        final_status = "normal"

    result_entry = {
        "path": str(bin_path),
        "status": final_status,
        "attempts_executed": attempts_executed,
        "timeouts_total": timeouts_total,
    }
    if final_status == "signal":
        result_entry["signal"] = signal_name_caught
        result_entry["payload_tag"] = signal_payload_tag

    return result_entry


def chunk_list(items, num_chunks):
    """Split items into num_chunks parts (last chunk may be longer)."""
    n = len(items)
    if num_chunks <= 0:
        return [items]
    base, extra = divmod(n, num_chunks)
    chunks = []
    start = 0
    for i in range(num_chunks):
        size = base + (1 if i < extra else 0)
        end = start + size
        chunks.append(items[start:end])
        start = end
    return chunks


def worker_thread(
    thread_idx: int,
    bins_slice,
    args,
    tdir: Path,
    results: dict,
    lock: Lock,
    thread_pbar: tqdm,
    all_pbar: tqdm,
):
    """
    Worker thread: process every sample in the assigned slice sequentially.
    - Per-thread progress bar: thread_pbar
    - Global progress bar: all_pbar
    Updates to results and progress bars share the same Lock to avoid I/O races.
    """
    for bin_path in bins_slice:
        entry = test_one_binary(
            bin_path=bin_path,
            tries_per_payload=args.tries,
            timeout_sec=args.timeout,
            step_interval=args.step_interval,
            workdir=tdir,
        )
        with lock:
            results[bin_path.name] = entry
            thread_pbar.update(1)
            all_pbar.update(1)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Multithreaded interactive batch tester: character/number payloads; stop on signals and record them; "
            "only if every attempt times out do we label the result as timeout, otherwise normal. "
            "Temporarily skip samples whose filenames contain 'socket'. Uses pwntools with PTY."
        )
    )
    parser.add_argument("target_dir", type=str, help="Target directory containing extension-less ELF samples")
    parser.add_argument("--tries", type=int, default=3, help="Attempts per payload (default: 3)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Overall timeout per run in seconds (default: 2.0)")
    parser.add_argument("--step-interval", type=float, default=0.5, help="Minimum interval between two inputs in seconds (default: 0.5)")
    parser.add_argument("--threads", type=int, default=4, help="Number of worker threads (default: 4)")
    parser.add_argument("--seed", type=int, default=0, help="Random seed for assigning slices to threads (default: 0; set to -1 for a new shuffle each run)")
    args = parser.parse_args()

    tdir = Path(args.target_dir).resolve()
    if not tdir.is_dir():
        raise SystemExit(f"Target directory does not exist or is inaccessible: {tdir}")

    # Select candidate samples
    candidates_all = [p for p in sorted(tdir.iterdir()) if is_elf_no_suffix(p)]
    sockets = [p for p in candidates_all if "socket" in p.name.lower()]
    nonsockets = [p for p in candidates_all if "socket" not in p.name.lower()]
    targets = list(nonsockets)
    
    print(f"[+] Directory: {tdir}")
    print(f"[+] Candidate ELF files   : {len(candidates_all)}")
    print(f"[+] Names containing 'socket': {len(sockets)}")
    print(f"[+] Samples selected      : {len(targets)}")

    if not targets:
        print("[!] No samples matched the testing criteria.")
        print("    Requirements: no extension + executable + ELF magic + filename without 'socket'.")
        print("    Please verify the directory and filtering rules.")
        return

    # Shuffle once before slicing for distribution
    if args.seed == -1:
        random.shuffle(targets)
    else:
        random.Random(args.seed).shuffle(targets)

    results = {}
    lock = Lock()

    threads_num = max(1, args.threads)
    slices = chunk_list(targets, threads_num)

    # Global progress bar: tracks every non-socket sample
    all_pbar = tqdm(
        total=len(targets),
        desc="ALL",
        unit="bin",
        dynamic_ncols=True,
        position=0,
        leave=True,
        file=sys.stdout,
    )

    # Per-thread progress bars: T1..Tn
    threads = []
    pbars = []
    for idx, bins_slice in enumerate(slices):
        thread_pbar = tqdm(
            total=len(bins_slice),
            desc=f"T{idx+1}",
            unit="bin",
            dynamic_ncols=True,
            position=idx + 1,  # Reserve position 0 for ALL
            leave=True,
            file=sys.stdout,
        )
        pbars.append(thread_pbar)
        th = Thread(
            target=worker_thread,
            args=(idx, bins_slice, args, tdir, results, lock, thread_pbar, all_pbar),
            daemon=True,
        )
        threads.append(th)

    try:
        for th in threads:
            th.start()
        for th in threads:
            th.join()
    finally:
        # Ensure progress bars shut down cleanly to avoid terminal glitches
        try:
            all_pbar.close()
        except Exception:
            pass

        for p in pbars:
            try:
                p.close()
            except Exception:
                pass

        out = {
            "target_dir": str(tdir),
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "tries_per_payload": args.tries,
            "payload_count": len(PAYLOADS),
            "timeout_sec": args.timeout,
            "step_interval": args.step_interval,
            "threads": threads_num,
            "runner": "pwntools+PTY+threads",
            "programs": results,
            "skipped_sockets": [p.name for p in sockets],
        }

        out_file = tdir / "signal_report.json"
        with out_file.open("w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)

        print("\n\n\n---------")
        print(f"[+] FINISHED, SAVE TO : {out_file}")
        print("---------")


if __name__ == "__main__":
    main()
