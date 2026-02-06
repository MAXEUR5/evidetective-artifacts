# --------------------------------------------------------------------------
#  IDA 9.1  ‑  Path DFS  v3
#  功能 : 端到端函数调用链搜索（支持常量/表异或等混淆后的函数指针）
#  作者 : 2025‑04‑11  @ChatGPT‑o3
# --------------------------------------------------------------------------
# ./ida.exe -A -L"output.log" -S"G:\ida_util\analysis_init\path_dfs_v3.py start_func=entry end_func=endpoint4" G:\vuln_test\test_cc\test_ccx.elf

import idaapi          # type: ignore
import ida_auto        # type: ignore
import ida_hexrays     # type: ignore
import ida_funcs       # type: ignore
import ida_xref        # type: ignore
import idautils        # type: ignore
import idc             # type: ignore
import ida_bytes       # type: ignore

import json, os
from typing import List, Dict, Set, Optional, Iterable, Tuple

OUT_FILE = "cc_dfs_path.json"          # 固定输出文件名
MAX_DEF_SEARCH = 1000              # 反向切片时遍历语句条数上限（安全阈）

# --------------------------------------------------------------------------
def parse_args() -> Tuple[str, str]:
    start = end = None
    for a in idc.ARGV:
        if "=" in a:
            k, v = map(str.strip, a.split("=", 1))
            if k == "start_func":
                start = v
            elif k == "end_func":
                end = v
    if not (start and end):
        idc.msg('Usage: -S"path_dfs_v3.py start_func=<name> end_func=<name>"\n')
        idaapi.qexit(1)
    return start, end


# --------------------------------------------------------------------------
def resolve(name: str) -> int:
    ea = idc.get_name_ea_simple(name)
    f  = ida_funcs.get_func(ea) if ea != idc.BADADDR else None
    if not f:
        idc.msg(f"[!] Function '{name}' not found!\n")
        idaapi.qexit(1)
    return f.start_ea


# --------------------------------------------------------------------------
def is_internal(ea: int) -> bool:
    """过滤导入、PLT、库函数，仅保留用户代码函数"""
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
    """判定尾调用"""
    if idaapi.is_call_insn(insn_ea):
        return False
    if ida_bytes.is_flow(idaapi.get_full_flags(insn_ea)):
        return False
    tgt_func = ida_funcs.get_func(target_ea)
    return tgt_func is not None and tgt_func.start_ea == target_ea


# --------------------------------------------------------------------------
# ----------  v3  :  反向数据切片辅助函数  -----------------------------------

def collect_func_objs(expr) -> Set[int]:
    """
    在表达式树中搜集直接出现的函数地址（cot_obj）
    """
    found: Set[int] = set()

    class _Visitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_obj:
                if is_internal(e.obj_ea):
                    found.add(e.obj_ea)
            return 0

    _Visitor().apply_to(expr, None)
    return found


def expr_uses_lvar(expr, lvar_idx_set: Set[int]) -> bool:
    """
    判断表达式是否直接或间接使用了指定局部变量
    """
    class _Chk(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
            self.hit = False

        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_var and e.v.idx in lvar_idx_set:
                self.hit = True
                return 1  # 终止
            return 0

    c = _Chk()
    c.apply_to(expr, None)
    return c.hit


def resolve_callee_via_defs(cfunc, callee_expr) -> List[int]:
    """
    当无法直接确定 callee 时，执行一次“轻量反向切片”：
      • 找到 callee_expr 中涉及的 lvar / 全局地址
      • 回溯其最近的赋值语句，检查 RHS 是否含函数地址
    仅在同一函数体内分析，复杂度可控
    """
    results: Set[int] = set()

    # 1) 收集本调用表达式中用到的局部变量 idx
    lvar_idx_set: Set[int] = set()

    class _VarGrab(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_var:
                lvar_idx_set.add(e.v.idx)
            return 0

    _VarGrab().apply_to(callee_expr, None)
    if not lvar_idx_set:
        return []

    # 2) 在 cfunc.body 内扫描赋值（cot_asg）语句，寻找 lhs 命中
    #    遍历次数做上限，避免极端大函数卡顿
    visited = 0

    class _DefFinder(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            nonlocal visited
            if visited > MAX_DEF_SEARCH:
                return 1                      # 终止遍历

            if e.op == ida_hexrays.cot_asg:
                lhs, rhs = e.x, e.y          # ← 这里改成 x / y
                if expr_uses_lvar(lhs, lvar_idx_set):
                    objs = collect_func_objs(rhs)
                    results.update(objs)
            visited += 1
            return 0

    _DefFinder().apply_to(cfunc.body, None)
    return list(results)


# --------------------------------------------------------------------------
# ----------  v3  :  直接从 Hex‑Rays 收集被调函数  ---------------------------

def collect_callees_from_hexrays(func_ea: int) -> List[int]:
    """
    反编译后 ctree 遍历，提取调用目标（支持表 + 异或等混淆）
    """
    if not ida_hexrays.init_hexrays_plugin():
        return []

    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        return []

    found: Set[int] = set()

    class _CallVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            if e.op != ida_hexrays.cot_call:
                return 0

            callee_expr = e.x

            # ① 直接解析 (cast/ref/ptr/memref)
            direct = try_resolve_callee(callee_expr)
            if direct and is_internal(direct):
                found.add(direct)
            else:
                # ② 整棵表达式若仅含 1 个函数地址 ⇒ 采用
                inline_objs = collect_func_objs(callee_expr)
                if len(inline_objs) == 1:
                    found.update(inline_objs)

                # ③ 仍未解析 ⇒ 反向切片
                if not inline_objs:
                    for tgt in resolve_callee_via_defs(cfunc, callee_expr):
                        if is_internal(tgt):
                            found.add(tgt)
            return 0

    _CallVisitor().apply_to(cfunc.body, None)
    return list(found)


def try_resolve_callee(callee_expr) -> Optional[int]:
    """
    尝试在表达式树中直接解析出被调用函数地址
    """
    if callee_expr.op == ida_hexrays.cot_obj:
        return callee_expr.obj_ea
    elif callee_expr.op in (ida_hexrays.cot_cast,
                            ida_hexrays.cot_ref,
                            ida_hexrays.cot_ptr,
                            ida_hexrays.cot_memptr,
                            ida_hexrays.cot_memref):
        return try_resolve_callee(callee_expr.x)
    return None


# --------------------------------------------------------------------------
# ----------  v2 逻辑保留（汇编层 + thunk + 尾调用） -------------------------

callees_cache: Dict[int, List[int]] = {}


def direct_callees(func_ea: int) -> List[int]:
    """
    返回 func_ea 直接可能到达的内部函数列表（v3 = v2 + 混淆指针调用）
    """
    if func_ea in callees_cache:
        return callees_cache[func_ea]

    res: Set[int] = set()

    # (1) 正常 / 间接 call（汇编扫描）
    for insn in idautils.FuncItems(func_ea):
        if idaapi.is_call_insn(insn):
            for xr in idautils.XrefsFrom(insn, ida_xref.XREF_FAR):
                if not xr.iscode:
                    continue
                tgt_func = ida_funcs.get_func(xr.to)
                if tgt_func and tgt_func.start_ea != func_ea and is_internal(tgt_func.start_ea):
                    res.add(tgt_func.start_ea)
            continue

        # (2) 尾调用
        first_xref = next(idautils.XrefsFrom(insn, ida_xref.XREF_FAR), None)
        if first_xref and is_tail_jump(insn, first_xref.to):
            tgt = first_xref.to
            if is_internal(tgt) and tgt != func_ea:
                res.add(tgt)

    # (3) thunk
    f = ida_funcs.get_func(func_ea)
    if f and (f.flags & ida_funcs.FUNC_THUNK):
        tgt = ida_funcs.calc_thunk_func_target(f)
        if isinstance(tgt, int) and is_internal(tgt):
            res.add(tgt)

    # (4) Hex‑Rays 反编译检测（含混淆表指针）
    res.update(collect_callees_from_hexrays(func_ea))

    callees_cache[func_ea] = sorted(res)
    return callees_cache[func_ea]


# --------------------------------------------------------------------------
# ----------  DFS + 记忆化  -------------------------------------------------

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

    # 去重
    paths_ea = [list(t) for t in {tuple(p) for p in paths_ea}]

    paths_name = [[idc.get_func_name(ea) or f"{ea:#x}" for ea in p]
                  for p in paths_ea]

    with open(OUT_FILE, "w", encoding="utf-8") as fp:
        json.dump(paths_name, fp, ensure_ascii=False, indent=2)

    idc.msg(f"[+] {len(paths_name)} paths written to {os.path.abspath(OUT_FILE)}\n")
    idaapi.qexit(0)


# --------------------------------------------------------------------------
main()
# ./ida -A -L"output.log" -S"/home/workspace/ida_util/analysis_init/path_dfs_v3.py start_func=main end_func=sub_1329" /home/workspace/Testcase/test3/vuln_n