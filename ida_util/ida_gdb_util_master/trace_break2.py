# trace_break.py 2025-10-04 (patch)

import gdb
from typing import List, Optional, List, Tuple

# ---------- TraceBreak -------------------------------------------------
class TraceBreak(gdb.Breakpoint):
    def __init__(self, spec: str, func_name: str):
        super().__init__(spec, gdb.BP_BREAKPOINT, internal=True, temporary=False)
        self.silent = True
        self.func_name = func_name
        self.hits: int = 0

    def stop(self):
        self.hits += 1
        gdb.write(f"[trace] hit {self.func_name}\n")
        return False

# ---------- TraceManager ----------------------------------------------
class TraceManager:
    registry: List[TraceBreak] = []
    _protect_enabled = True

    # 新增：保存上一轮运行的统计快照（编号, 名称, 命中, 位置）
    last_snapshot: List[Tuple[int, str, int, str]] = []

    @classmethod
    def add(cls, loc: str, fn: str) -> TraceBreak:
        for tb in cls.registry:
            if tb.location == loc:
                return tb
        tb = TraceBreak(loc, fn)
        cls.registry.append(tb)
        return tb

    @classmethod
    def get_by_num(cls, num: int) -> Optional[TraceBreak]:
        return next((tb for tb in cls.registry if tb.number == num), None)

    @classmethod
    def remove(cls, tb: TraceBreak):
        cls._protect_enabled = False
        try:
            tb.delete()
            cls.registry.remove(tb)
        finally:
            cls._protect_enabled = True

    @classmethod
    def remove_all(cls):
        for tb in list(cls.registry):
            cls.remove(tb)

    # -------- 快照/清零/打印 -------------------------------------------
    @classmethod
    def snapshot(cls):
        cls.last_snapshot = [(tb.number, tb.func_name, tb.hits, tb.location) for tb in cls.registry]

    @classmethod
    def reset_hits(cls):
        for tb in cls.registry:
            tb.hits = 0

    @classmethod
    def print_table(cls, rows: List[Tuple[int, str, int]]):
        gdb.write("编号  命中  位置\n----  ----  ---------------------------\n")
        for num, name, hits in rows:
            mark = "✓" if hits else "✗"
            gdb.write(f"{num:<4}  {hits:<4}  {name} {mark}\n")

    @classmethod
    def print_snapshot(cls, snap: Optional[List[Tuple[int, str, int, str]]] = None):
        data = snap if snap is not None else cls.last_snapshot
        if not data:
            gdb.write("[tracelog] 无上一轮快照\n")
            return
        rows = [(num, name, hits) for num, name, hits, _ in data]
        cls.print_table(rows)

    # -------- 退出收口（关键） ----------------------------------------
    @classmethod
    def exit_cleanup(cls, reason: str):
        _sync_registry()
        cls.snapshot()
        gdb.write(f"[trace-exit] 目标进程已退出：{reason}\n")
        # 退出时打印本轮统计，随后清零，为下一轮 run 做准备
        cls.print_snapshot(cls.last_snapshot)
        cls.reset_hits()

    # -------- 误删保护（兼容多形态事件） -------------------------------
    @classmethod
    def _on_bp_deleted(cls, event):
        if not cls._protect_enabled:
            return
        try:
            # 形态 A：BreakpointsEvent，带 .breakpoints 列表
            candidates = list(getattr(event, "breakpoints"))
        except Exception:
            candidates = []

        # 形态 B：某些版本直接传单个 gdb.Breakpoint
        if not candidates and isinstance(event, gdb.Breakpoint):
            candidates = [event]

        # 防御：如果还是拿不到，就直接返回，避免影响 GDB 自身行为
        if not candidates:
            return

        for bp in candidates:
            # 只保护我们自定义的 TraceBreak；普通断点一律忽略
            if not isinstance(bp, TraceBreak):
                continue

            # 兜底拿位置表达式，避免某些版本删除后 location 为空
            loc = getattr(bp, "location", None) or getattr(bp, "expression", None) or getattr(bp, "spec", None)
            func = getattr(bp, "func_name", None) or "<unknown>"
            hits = getattr(bp, "hits", 0)

            # 恢复为新的 TraceBreak，并继承 hits
            new_tb = TraceBreak(loc, func)
            new_tb.hits = hits
            try:
                cls.registry.remove(bp)
            except ValueError:
                pass
            cls.registry.append(new_tb)
            gdb.write(f"[trace-protect] 已恢复 {func} ({loc})\n")

gdb.events.breakpoint_deleted.connect(TraceManager._on_bp_deleted)

# ---------- 同步辅助 ----------------------------------------------------
def _sync_registry():
    """确保 registry 与实际存在的 TraceBreak 保持一致（防热重载 / 清空）"""
    current_ids = {id(tb) for tb in TraceManager.registry}
    for bp in gdb.breakpoints() or []:
        if isinstance(bp, TraceBreak) and id(bp) not in current_ids:
            TraceManager.registry.append(bp)

# ---------- 进程退出事件（新增） ---------------------------------------
def _on_exited(event):
    # 兼容不同 GDB 的 ExitedEvent 字段
    reason = "exited"
    try:
        if getattr(event, "exit_code", None) is not None:
            reason = f"exit_code={event.exit_code}"
        sig = getattr(event, "signal", None) or getattr(event, "sig", None)
        if sig:
            reason = f"signal={sig}"
    except Exception:
        pass
    TraceManager.exit_cleanup(reason)

gdb.events.exited.connect(_on_exited)

# ---------- GDB Commands ----------------------------------------------
class TraceSet(gdb.Command):
    """traceset <addr|symbol> [func_name]"""
    def __init__(self):
        super().__init__("traceset", gdb.COMMAND_BREAKPOINTS)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        if not argv:
            raise gdb.GdbError("用法: traceset <addr|symbol> [func_name]")

        loc_expr = argv[0]
        if loc_expr.count('*') > 1:
            raise gdb.GdbError("地址格式错误：请去掉多余的 '*'")

        if len(argv) == 2:
            fn_name = argv[1]
        else:
            try:
                info = gdb.execute(f"info symbol {loc_expr}", to_string=True).strip()
                fn_name = info.split()[0] if info else None
            except gdb.error:
                fn_name = None
            if not fn_name:
                raise gdb.GdbError("缺少函数名：traceset *0xADDR func_name")

        tb = TraceManager.add(loc_expr, fn_name)
        gdb.write(f"[traceset] tracepoint #{tb.number} -> {fn_name} ({loc_expr})\n")


class TraceLog(gdb.Command):
    """tracelog [last] : 列出追踪点或上一轮快照"""
    def __init__(self):
        super().__init__("tracelog", gdb.COMMAND_STATUS)

    def invoke(self, arg, _tty):
        _sync_registry()
        argv = gdb.string_to_argv(arg)
        if argv and argv[0] == "last":
            TraceManager.print_snapshot()  # 打印上一轮快照
            return

        if not TraceManager.registry:
            gdb.write("[tracelog] 当前没有 tracepoint\n")
            return
        rows = [(tb.number, tb.func_name, tb.hits) for tb in TraceManager.registry]
        TraceManager.print_table(rows)


class TraceClear(gdb.Command):
    """traceclear <id|all> : 删除追踪点"""
    def __init__(self):
        super().__init__("traceclear", gdb.COMMAND_BREAKPOINTS)

    def invoke(self, arg, from_tty):
        _sync_registry()
        argv = gdb.string_to_argv(arg)
        if not argv:
            raise gdb.GdbError("用法: traceclear <id|all>")

        if argv[0] == "all":
            TraceManager.remove_all()
            gdb.write("[traceclear] 已删除全部 tracepoint\n")
            return

        try:
            num = int(argv[0])
        except ValueError:
            raise gdb.GdbError("traceclear 需要数字编号或 all")

        tb = TraceManager.get_by_num(num)
        if not tb:
            raise gdb.GdbError(f"编号 {num} 不是 tracepoint")
        TraceManager.remove(tb)
        gdb.write(f"[traceclear] 已删除 tracepoint #{num}\n")

TraceSet()
TraceLog()
TraceClear()

# EOF
