# --- IDA 库 (忽略类型检查) -------------------------------------------------
import idaapi          # type: ignore
import ida_auto        # type: ignore
import ida_hexrays     # type: ignore
import ida_funcs       # type: ignore
import ida_xref        # type: ignore
import idautils        # type: ignore
import idc             # type: ignore
import ida_bytes       # type: ignore

# --- 标准库 ---------------------------------------------------------------
import json, os
from typing import List, Dict, Set, Optional

OUT_FILE = "cc_path.json"          # 固定输出文件名

# --------------------------------------------------------------------------
def parse_args() -> tuple[str, str]:
    start = end = None
    for a in idc.ARGV:
        if "=" in a:
            k, v = a.split("=", 1)
            k, v = k.strip(), v.strip()
            if k == "start_func":
                start = v
            elif k == "end_func":
                end = v
    if not (start and end):
        idc.msg('Usage: -S"path_dfs.py start_func=<name> end_func=<name>"\n')
        idaapi.qexit(1)
    return start, end

# --------------------------------------------------------------------------
def resolve(name: str) -> int:
    ea = idc.get_name_ea_simple(name)
    f = ida_funcs.get_func(ea) if ea != idc.BADADDR else None
    if not f:
        idc.msg(f"[!] Function '{name}' not found!\n")
        idaapi.qexit(1)
    return f.start_ea

# --------------------------------------------------------------------------
def is_internal(ea: int) -> bool:
    """过滤导入、PLT、库函数；仅留下用户代码函数"""
    if not isinstance(ea, int):
        return False
    f = ida_funcs.get_func(ea)
    if not f:
        return False
    seg = idaapi.getseg(ea)
    if seg and seg.type in (idaapi.SEG_XTRN, idaapi.SEG_GRP):
        return False
    if f.flags & ida_funcs.FUNC_LIB:
        return False
    return True

# --------------------------------------------------------------------------
def is_tail_jump(insn_ea: int, target_ea: int) -> bool:
    """
    判定尾调用：
      1) 指令不是 call
      2) 指令执行后无 flow
      3) 目标地址是某函数入口
    """
    if idaapi.is_call_insn(insn_ea):
        return False

    # 2) 无落入：使用 ida_bytes.is_flow
    if ida_bytes.is_flow(idaapi.get_full_flags(insn_ea)):
        return False

    tgt_func = ida_funcs.get_func(target_ea)
    return tgt_func is not None and tgt_func.start_ea == target_ea

# --------------------------------------------------------------------------
def collect_callees_from_hexrays(func_ea: int) -> List[int]:
    """
    通过反编译后的 ctree 遍历，找到在函数体内出现的所有“函数调用”目标，
    包括对函数指针的调用。如果能解析到具体地址且 is_internal，则返回。
    """
    result = set()
    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        return []

    class CallVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
        def visit_expr(self, expr):
            if expr.op == ida_hexrays.cot_call:
                # 在 IDA 9.1 中, expr.x 才是被调用者
                # expr.a 是参数列表 carglist_t
                callee_expr = expr.x
                tgt = try_resolve_callee(callee_expr)
                if tgt is not None and is_internal(tgt):
                    result.add(tgt)
            return 0

    cv = CallVisitor()
    cv.apply_to(cfunc.body, None)
    return list(result)

def try_resolve_callee(callee_expr) -> Optional[int]:
    """
    针对 ctree 中的被调用对象（可能是一系列嵌套表达式），尝试解析出目标函数地址。
    - 若能静态确定函数地址，则返回地址，否则返回 None
    """
    if callee_expr.op == ida_hexrays.cot_obj:
        ea = callee_expr.obj_ea
        if ea != idc.BADADDR:
            return ea
    elif callee_expr.op == ida_hexrays.cot_cast:
        return try_resolve_callee(callee_expr.x)
    elif callee_expr.op == ida_hexrays.cot_ref:
        return try_resolve_callee(callee_expr.x)
    # 这里可加更多规则: cot_var / cot_memref 等
    return None

# --------------------------------------------------------------------------
callees_cache: Dict[int, List[int]] = {}

def direct_callees(func_ea: int) -> List[int]:
    """返回 func_ea 直接可能到达的内部函数列表（去重），包含正常call + 尾调用 + thunk + 反编译检测到的指针调用"""
    if func_ea in callees_cache:
        return callees_cache[func_ea]

    res: Set[int] = set()

    # (1) 正常 / 间接 call（基于汇编层扫描）
    for insn in idautils.FuncItems(func_ea):
        if idaapi.is_call_insn(insn):
            for xr in idautils.XrefsFrom(insn, ida_xref.XREF_FAR):
                if not xr.iscode:
                    continue
                tgt_func = ida_funcs.get_func(xr.to)
                if tgt_func and tgt_func.start_ea != func_ea and is_internal(tgt_func.start_ea):
                    res.add(tgt_func.start_ea)
            continue  # 处理完 call

        # (2) 尾调用 / 远跳
        first_xref = next(idautils.XrefsFrom(insn, ida_xref.XREF_FAR), None)
        if first_xref and is_tail_jump(insn, first_xref.to):
            tgt = first_xref.to
            if is_internal(tgt) and tgt != func_ea:
                res.add(tgt)

    # (3) 整函数 thunk
    f = ida_funcs.get_func(func_ea)
    if f and (f.flags & ida_funcs.FUNC_THUNK):
        tgt = ida_funcs.calc_thunk_func_target(f)  # 可能 None
        if isinstance(tgt, int) and is_internal(tgt):
            res.add(tgt)

    # (4) 通过 反编译 ctree 检查指针调用
    #     只有在 ida_hexrays 初始化成功时才有效
    if ida_hexrays.init_hexrays_plugin():
        hexrays_callees = collect_callees_from_hexrays(func_ea)
        for hx in hexrays_callees:
            if hx != func_ea:  # 避免自调用
                res.add(hx)

    callees_cache[func_ea] = sorted(res)
    return callees_cache[func_ea]

# --------------------------------------------------------------------------
good_paths: Dict[int, List[List[int]]] = {}
bad_funcs:  Set[int] = set()

def dfs(ea: int, end_ea: int, visiting: Set[int]) -> List[List[int]]:
    """记忆化 DFS，保证单条路径中函数不重复"""
    if ea in good_paths:
        return good_paths[ea]
    if ea in bad_funcs or ea in visiting:
        return []

    paths: List[List[int]] = []
    for cal in direct_callees(ea):
        if cal == end_ea:
            paths.append([ea, end_ea])
        else:
            for sub in dfs(cal, end_ea, visiting | {ea}):
                paths.append([ea] + sub)

    if paths:
        good_paths[ea] = paths
    else:
        bad_funcs.add(ea)
    return paths

# --------------------------------------------------------------------------
def main() -> None:
    ida_auto.auto_wait()

    if ida_hexrays.init_hexrays_plugin():
        idc.msg(f"Hex‑Rays {ida_hexrays.get_hexrays_version()} loaded\n")

    start_name, end_name = parse_args()
    idc.msg(f"[+] start_func = {start_name}\n")
    idc.msg(f"[+] end_func   = {end_name}\n")
    idc.msg(f"[+] output     = {OUT_FILE}\n")

    start_ea = resolve(start_name)
    end_ea   = resolve(end_name)

    paths_ea = dfs(start_ea, end_ea, set())

    # 去重（理论上 DFS 已去重，保险再做一次）
    unique = {tuple(p) for p in paths_ea}
    paths_ea = [list(p) for p in unique]

    paths_name = [[idc.get_func_name(ea) or f"{ea:#x}" for ea in p]
                  for p in paths_ea]

    with open(OUT_FILE, "w", encoding="utf-8") as fp:
        json.dump(paths_name, fp, ensure_ascii=False, indent=2)

    idc.msg(f"[+] {len(paths_name)} paths written to {os.path.abspath(OUT_FILE)}\n")
    idaapi.qexit(0)

# --------------------------------------------------------------------------
# 在 IDA 的 execfile 环境下 __name__ 不是 "__main__"，直接调用 main()
main()
