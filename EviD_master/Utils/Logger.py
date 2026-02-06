import logging
from colorama import Fore, Style, init

init(autoreset=False, strip=False, convert=False)
ALIGN_COL = 12


WHITE_LEVEL_NUM = 25
logging.addLevelName(WHITE_LEVEL_NUM, "WHITE")


def _white(self, msg, *args, **kwargs):

    if self.isEnabledFor(WHITE_LEVEL_NUM):
        self._log(WHITE_LEVEL_NUM, msg, args, **kwargs)


class SpanFormatter(logging.Formatter):
    LEVEL_COLOR = {
        "DEBUG":    Fore.CYAN,
        "INFO":     Fore.GREEN,
        "WARNING":  Fore.YELLOW,
        "ERROR":    Fore.RED,
        "CRITICAL": Fore.MAGENTA,
        "WHITE":    Fore.WHITE,
    }

    def format(self, record: logging.LogRecord) -> str:
        prefix_plain = f"[{record.levelname}]"
        gap_len = max(1, ALIGN_COL - len(prefix_plain))
        gap = " " * gap_len

        color = self.LEVEL_COLOR.get(record.levelname, Fore.WHITE)

        if record.levelname == "WHITE":
            return (
                f"{color}{prefix_plain}{Style.RESET_ALL}\n"
                f"{record.getMessage()}{Style.RESET_ALL}"
            )

        return f"{color}{prefix_plain}{gap}{record.getMessage()}{Style.RESET_ALL}"


def get_logger(name="span_logger", level=logging.DEBUG):
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(SpanFormatter())
        logger.addHandler(handler)

    if not hasattr(logger, "white"):
        logger.white = _white.__get__(logger, logging.Logger)

    return logger


# ================== DEMO ==================
slog = get_logger(__name__)
""" slog.info("init")
slog.white("this is a white message without leading spaces after newline")
slog.debug("var x=42")
slog.warning("disk < 5%")
slog.error("sql error") """


import hashlib
import re
from dataclasses import is_dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping, Union

class ObjectLogger:
    counter = 0

    def __init__(self, target_bin_path: Union[str, Path], logs_prefix: str = "Logs"):
        self.TARGET_BIN_PATH = Path(target_bin_path)
        self.target_dir = Path(self.TARGET_BIN_PATH).resolve().parent

        self.counter = 0

        ts_dir = datetime.now().strftime("%Y%m%d-%H%M%S")
        base = self.target_dir / f"{logs_prefix}-{ts_dir}"
        self.logs_dir = self._make_unique_dir(base)
        self.logs_dir.mkdir(parents=True, exist_ok=True)

    # ---------------- Public API ----------------

    def save_log(self, obj: Any, label: str | None = None, log_type: str = "default") -> Path:

        self.counter += 1

        ts_file = datetime.now().strftime("%m%d%H%M%S")
        pretty_body = self._pretty(obj)

        digest = self._digest64(pretty_body)
        counter_hex = self._format_counter_hex(self.counter)
        safe_log_type = self._sanitize_for_filename(log_type) or "default"

        filename = f"log-{counter_hex}-{safe_log_type}-{ts_file}-{digest}.txt"
        path = self.logs_dir / filename

        header_lines = [
            "----- Object Log -----",
            f"Timestamp : {datetime.now().isoformat(timespec='seconds')}",
            f"Type      : {type(obj).__name__}",
            f"Digest    : {digest}",
            f"Log-Type  : {safe_log_type}",
        ]
        if label:
            header_lines.append(f"Label     : {label}")

        header = "\n".join(header_lines)
        content = f"{header}\n\n{pretty_body}\n"

        path.write_text(content, encoding="utf-8")
        return path

    # ---------------- Internals ----------------

    def _make_unique_dir(self, base: Path) -> Path:

        if not base.exists():
            return base
        i = 1
        while True:
            cand = base.parent / f"{base.name}-{i}"
            if not cand.exists():
                return cand
            i += 1

    def _digest64(self, text: str) -> str:

        h = hashlib.blake2b(text.encode("utf-8"), digest_size=8)  # 64-bit
        return h.hexdigest()

    def _format_counter_hex(self, n: int) -> str:

        return f"{n:04X}"

    def _sanitize_for_filename(self, name: str) -> str:

        return re.sub(r"[^A-Za-z0-9._-]+", "_", name.strip())

    # --------------- Pretty Printer ---------------

    def _pretty(self, obj: Any) -> str:

        seen_ids = set()
        lines = self._format(obj, indent=0, seen=seen_ids)
        return "\n".join(lines)

    def _format(self, obj: Any, indent: int, seen: set[int]) -> list[str]:
        IND = "  " * indent
        lines: list[str] = []

        def mark_seen(o: Any) -> bool:
            oid = id(o)
            if oid in seen:
                lines.append(f"{IND}<Recursion: {type(o).__name__} at 0x{oid:x}>")
                return True
            seen.add(oid)
            return False

        if obj is None or isinstance(obj, (bool, int, float, complex)):
            lines.append(f"{IND}{obj!s}")
            return lines

        if isinstance(obj, str):
            if "\n" in obj or len(obj) > 80:
                lines.append(f"{IND}String(len={len(obj)})")
                lines.append(f"{IND}'''")
                for ln in obj.splitlines():
                    lines.append(f"{IND}{ln}")
                lines.append(f"{IND}'''")
            else:

                lines.append(f'{IND}"{obj}"')
            return lines

        if isinstance(obj, (bytes, bytearray, memoryview)):
            b = bytes(obj)
            preview = b[:32].hex()
            suffix = "..." if len(b) > 32 else ""
            lines.append(f"{IND}Bytes(len={len(b)}): 0x{preview}{suffix}")
            return lines

        # datetime
        if hasattr(obj, "isoformat") and callable(getattr(obj, "isoformat")):
            try:
                iso = obj.isoformat()
                lines.append(f"{IND}{type(obj).__name__}({iso})")
                return lines
            except Exception:
                pass

        # Path
        if isinstance(obj, Path):
            lines.append(f"{IND}Path({str(obj)})")
            return lines


        if isinstance(obj, BaseException):
            lines.append(f"{IND}{type(obj).__name__}: {obj}")
            return lines


        if is_dataclass(obj):
            if mark_seen(obj):
                return lines
            data = asdict(obj)
            lines.append(f"{IND}Dataclass {type(obj).__name__} ({len(data)} fields)")
            lines.extend(self._format_mapping(data, indent + 1, seen))
            return lines


        if isinstance(obj, Mapping):
            if mark_seen(obj):
                return lines
            lines.append(f"{IND}Dict({len(obj)})")

            for k in sorted(obj.keys(), key=lambda x: str(x)):
                key_str = self._key_to_str(k)
                lines.append(f"{IND}  - {key_str}:")
                lines.extend(self._format(obj[k], indent + 2, seen))
            return lines


        if isinstance(obj, Iterable):
            if mark_seen(obj):
                return lines
            typename = type(obj).__name__
            try:
                seq = list(obj)
            except Exception:
                lines.append(f"{IND}{typename}(...)")
                return lines
            lines.append(f"{IND}{typename}({len(seq)})")
            for idx, it in enumerate(seq):
                lines.append(f"{IND}  - [{idx}]")
                lines.extend(self._format(it, indent + 2, seen))
            return lines


        if hasattr(obj, "__dict__"):
            if mark_seen(obj):
                return lines
            fields = vars(obj)
            lines.append(f"{IND}Object {type(obj).__name__} ({len(fields)} attrs)")
            lines.extend(self._format_mapping(fields, indent + 1, seen))
            return lines

        lines.append(f"{IND}{str(obj)}")
        return lines

    def _format_mapping(self, mp: Mapping[str, Any], indent: int, seen: set[int]) -> list[str]:
        IND = "  " * indent
        out: list[str] = []
        for k in sorted(mp.keys(), key=lambda x: str(x)):
            key_str = self._key_to_str(k)
            out.append(f"{IND}- {key_str}:")
            out.extend(self._format(mp[k], indent + 1, seen))
        return out

    def _key_to_str(self, key: Any) -> str:
        if isinstance(key, str):
            return key
        return str(key)