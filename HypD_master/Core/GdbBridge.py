import sys
import time
from typing import Any, Dict, List, Optional, Union

from pygdbmi.gdbcontroller import GdbController


GdbMessages = List[Dict[str, Any]]


class GdbDebugger:
    def __init__(
        self,
        pid: int,
        entry_function: str,
        symbol_path: str,
        base_addr: Union[int, str],
        plugin_path: str,
        *,
        timeout: float = 5.0,
        gdb_path: str = "gdb",
    ) -> None:
        if sys.platform != "linux":
            raise OSError("GdbDebugger no windows support yet")

        self.pid = int(pid)
        self.entry_function = str(entry_function)
        self.symbol_path = str(symbol_path)
        self.base_addr = self._format_base_addr(base_addr)
        self.plugin_path=plugin_path
        self.timeout = float(timeout)

        self.gdb = GdbController([gdb_path, "--quiet", "--interpreter=mi2"])
        self._drain_startup()

    def _drain_startup(self) -> None:
        while self.gdb.get_gdb_response(timeout_sec=0.2, raise_error_on_timeout=False):
            pass

    @staticmethod
    def _format_base_addr(addr: Union[int, str]) -> str:
        if isinstance(addr, int):
            return hex(addr)
        return str(addr)

    @staticmethod
    def _has_result_terminator(m: Dict[str, Any]) -> bool:
        return m.get("type") == "result" and m.get("message") in {"done", "running", "error"}

    @staticmethod
    def _contains_stopped(msgs: GdbMessages) -> bool:
        return any(m.get("type") == "notify" and m.get("message") == "stopped" for m in msgs)

    def _read_until_result(self, deadline: float) -> GdbMessages:
        buf: GdbMessages = []
        while time.time() < deadline:
            batch = self.gdb.get_gdb_response(timeout_sec=0.2, raise_error_on_timeout=False)
            if batch:
                buf.extend(batch)
                if any(self._has_result_terminator(m) for m in batch):
                    break
        return buf

    def _mi(self, cmd: str) -> GdbMessages:
        msgs = self.gdb.write(cmd, read_response=True, timeout_sec=self.timeout)
        if any(self._has_result_terminator(m) for m in msgs):
            return msgs

        deadline = time.time() + self.timeout
        msgs.extend(self._read_until_result(deadline))
        if not any(self._has_result_terminator(m) for m in msgs):
            raise TimeoutError(f"GDB produced no result record for '{cmd}' within {self.timeout}s")
        return msgs

    @staticmethod
    def _escape_for_console(s: str) -> str:
        return s.replace("\\", "\\\\").replace('"', r"\"")

    def _console(self, cmd: str) -> GdbMessages:

        quoted = self._escape_for_console(cmd)
        return self._mi(f'-interpreter-exec console "{quoted}"')
    
    @staticmethod
    def _collect_stdout(msgs: list[dict], cmd: str | None = None) -> str:

        lines: list[str] = []
        if cmd:
            lines.append(f"\n===== {cmd} =====")

        has_stream_output = any(
            (m.get("type") in {"console", "log", "target"}) and m.get("payload")
            for m in msgs
        )

        for m in msgs:
            t = m.get("type")

            if t == "console":
                lines.append(str(m.get("payload", "")).rstrip())

            elif t == "log":
                lines.append("(log) " + str(m.get("payload", "")).rstrip())

            elif t == "target":
                lines.append(str(m.get("payload", "")).rstrip())

            elif t == "notify":
                lines.append(f"{m.get('message', '')} {m.get('payload', '')}")

            elif t == "result":
                msg = m.get("message", "")
                payload = m.get("payload", "")

                if msg == "done" and has_stream_output and (payload is None or payload == ""):
                    continue

                lines.append(f"{msg} {payload}")
        return "\n".join(lines)

    def attach_and_setup(self) -> None:

        # 1) attach
        attach_msgs = self._mi(f"-target-attach {self.pid}")
        if not self._contains_stopped(attach_msgs):
            deadline = time.time() + self.timeout
            while time.time() < deadline:
                batch = self.gdb.get_gdb_response(timeout_sec=0.2, raise_error_on_timeout=False)
                if self._contains_stopped(batch):
                    break
            else:
                raise TimeoutError(f"PID {self.pid} NOT =stopped ")

        entry_point = f"break *{self.entry_function}"
        symbol_add = f'add-symbol-file "{self.symbol_path}" {self.base_addr}'
        plugin_add= f"source {self.plugin_path}"
        cmds = [
            "set confirm off",
            "set pagination off",
            plugin_add,
            symbol_add,
            "handle SIGSTOP noprint nostop pass",
            "set breakpoint pending on",
            entry_point,
            "continue"
        ]
        for c in cmds:
            cmd_ans=self._console(c)
            print(cmd_ans)

    def interact(self, cmd: str, *, wait_for_stop: bool = False) -> Dict[str, Any]:

        msgs = self._console(cmd)

        if wait_for_stop:
            if any(m.get("type") == "result" and m.get("message") == "running" for m in msgs):
                stop_msgs = self.wait_for_stop()
                msgs.extend(stop_msgs)

        return {"messages": msgs, "stdout": self._collect_stdout(msgs)}

    def wait_for_stop(self, timeout: Optional[float] = None) -> GdbMessages:

        end = time.time() + (timeout if timeout is not None else self.timeout)
        acc: GdbMessages = []
        while time.time() < end:
            batch = self.gdb.get_gdb_response(timeout_sec=0.2, raise_error_on_timeout=False)
            if batch:
                acc.extend(batch)
                if self._contains_stopped(batch):
                    break
        if not self._contains_stopped(acc):
            raise TimeoutError("WAIT =stopped TIMEOUT")
        return acc

    def close(self) -> None:
        try:
            self.gdb.exit()
        except Exception:
            pass
    def __enter__(self) -> "GdbDebugger":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class GdbTimeoutError(Exception):
    """Placeholder for GDB timeout exceptions."""
    pass