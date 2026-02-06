# --------------------------------------------------------------------------
#  IDA 9.1  -  Reachable Callgraph From Entry
#
#  功能:
#    以入口函数为根，沿“可能的调用边”一次性遍历整个可达子图（有向图，可带环），
#    输出：
#      - reachable_funcs: 入口可达的内部函数列表（含入口）
#      - edges:           内部调用图邻接表（仅保留内部函数边）
#
#  设计目标:
#    替代 controller 中逐函数 get_dfs_call_chains(entry, fn) 的 O(N * DFS)
#    模式；改为单次 DFS/BFS + 记忆化缓存，显著降低 IDA 批处理次数与重复反编译开销。
#
#  调用示例:
#    ida -A -L"output.log" -S"reachable_callgraph_from_entry.py start_func=main" ./a.out
#
#  输出文件:
#    cc_reachable_callgraph.json  (默认写到输入二进制所在目录)
# --------------------------------------------------------------------------

import idaapi          # type: ignore
import ida_auto        # type: ignore
import ida_hexrays     # type: ignore
import ida_funcs       # type: ignore
import ida_xref        # type: ignore
import idautils        # type: ignore
import idc             # type: ignore
import ida_bytes       # type: ignore

import json
import os
from typing import Dict, List, Optional, Set, Tuple


OUT_FILE = "cc_reachable_callgraph.json"

# 反向切片时遍历语句条数上限（防止极端大函数卡住）
MAX_DEF_SEARCH = 2000


# --------------------------------------------------------------------------
# Args / IO helpers

def parse_args() -> str:
    start = None
    for a in idc.ARGV:
        if "=" in a:
            k, v = map(str.strip, a.split("=", 1))
            if k == "start_func":
                start = v
    if not start:
        idc.msg('Usage: -S"reachable_callgraph_from_entry.py start_func=<name>"\n')
        idaapi.qexit(1)
    return start


def get_output_path() -> str:
    """尽量把输出写到输入二进制所在目录，方便 runner 读取。"""
    try:
        in_path = idaapi.get_input_file_path()
    except Exception:
        in_path = ""
    if in_path:
        out_dir = os.path.dirname(os.path.abspath(in_path))
        return os.path.join(out_dir, OUT_FILE)
    return os.path.abspath(OUT_FILE)


def resolve_func_start_ea(name: str) -> int:
    ea = idc.get_name_ea_simple(name)
    if ea == idc.BADADDR:
        idc.msg(f"[!] Function '{name}' not found!\n")
        idaapi.qexit(1)
    f = ida_funcs.get_func(ea)
    if not f:
        idc.msg(f"[!] EA {ea:#x} is not inside a function: '{name}'\n")
        idaapi.qexit(1)
    return f.start_ea


# --------------------------------------------------------------------------
# Internal / thunk helpers


def is_plt_segment(seg) -> bool:
    return seg is not None and (idaapi.get_segm_name(seg) or "").startswith(".plt")


def get_thunk_target_ea(func: ida_funcs.func_t) -> Optional[int]:
    if func and (func.flags & ida_funcs.FUNC_THUNK):
        tgt = ida_funcs.calc_thunk_func_target(func)
        if isinstance(tgt, int) and tgt != idc.BADADDR:
            return tgt
    return None


def resolve_final_target(ea: int) -> int:
    """沿 thunk 链一路解引用到最终目标函数 EA。"""
    seen: Set[int] = set()
    while True:
        if ea in seen:
            return ea
        seen.add(ea)
        f = ida_funcs.get_func(ea)
        if not f or not (f.flags & ida_funcs.FUNC_THUNK):
            return ea
        tgt = ida_funcs.calc_thunk_func_target(f)
        if not isinstance(tgt, int) or tgt == idc.BADADDR:
            return ea
        ea = tgt


def is_internal(ea: int) -> bool:
    """过滤导入/PLT/库函数，仅保留用户代码函数（含用户 thunk，但会排除指向导入的 thunk）。"""
    if ea == idc.BADADDR or not isinstance(ea, int):
        return False

    f = ida_funcs.get_func(ea)
    if not f:
        return False

    seg = idaapi.getseg(ea)
    if seg:
        # 导入段 / 分组段
        if seg.type in (idaapi.SEG_XTRN, idaapi.SEG_GRP):
            return False
        # PLT stub
        if is_plt_segment(seg):
            return False

    # IDA 标记为库函数
    if f.flags & ida_funcs.FUNC_LIB:
        return False

    # thunk 指向外部导入/PLT 的也视为非内部
    if f.flags & ida_funcs.FUNC_THUNK:
        tgt = get_thunk_target_ea(f)
        if tgt is not None:
            seg2 = idaapi.getseg(tgt)
            if seg2 and (seg2.type == idaapi.SEG_XTRN or is_plt_segment(seg2)):
                return False
            ft = ida_funcs.get_func(tgt)
            if ft and (ft.flags & ida_funcs.FUNC_LIB):
                return False

    return True


def normalize_to_func_start(ea: int) -> int:
    f = ida_funcs.get_func(ea)
    return f.start_ea if f else ea


def is_tail_jump(insn_ea: int, target_ea: int) -> bool:
    """判定尾调用（jmp + 非 flow + 目标为函数入口）。"""
    if idaapi.is_call_insn(insn_ea):
        return False
    if ida_bytes.is_flow(idaapi.get_full_flags(insn_ea)):
        return False
    tgt_func = ida_funcs.get_func(target_ea)
    return tgt_func is not None and tgt_func.start_ea == target_ea


# --------------------------------------------------------------------------
# Hex-Rays based indirect call recovery (borrowed / adapted from call_find_v8)


def collect_func_objs(expr) -> Set[int]:
    """在给定表达式中收集所有 cot_obj（函数/对象 EA）。"""
    out: Set[int] = set()

    class V(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_obj:
                out.add(e.obj_ea)
            return 0

    V().apply_to(expr, None)
    return out


def expr_contains_call(expr) -> bool:
    """检查表达式中是否包含子调用，用于过滤运行时赋值。"""
    hit = False

    class V(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            nonlocal hit
            if e.op == ida_hexrays.cot_call:
                hit = True
                return 1
            return 0

    V().apply_to(expr, None)
    return hit


def expr_uses_lvar(expr, idxs: Set[int]) -> bool:
    """判断 expr 是否使用了给定的本地变量索引集合中的任意一个。"""
    hit = False

    class C(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            nonlocal hit
            if e.op == ida_hexrays.cot_var and e.v.idx in idxs:
                hit = True
                return 1
            return 0

    C().apply_to(expr, None)
    return hit


def resolve_callee_via_defs(cfunc, callee_expr) -> List[int]:
    """
    数据流回溯：从 callee_expr 所涉及的局部变量出发，回溯赋值，
    收集其中出现的函数对象（cot_obj），并过滤 RHS 中包含 call 的赋值。

    说明：
      - 仅在同一函数体内扫描（可控）
      - 过滤 RHS 含 call，可减少“运行时计算”导致的误报
    """
    lidx: Set[int] = set()

    class Grab(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_var:
                lidx.add(e.v.idx)
            return 0

    Grab().apply_to(callee_expr, None)
    if not lidx:
        return []

    res: Set[int] = set()
    visited = 0

    class DF(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            nonlocal visited
            if visited > MAX_DEF_SEARCH:
                return 1

            if e.op == ida_hexrays.cot_asg:
                if expr_uses_lvar(e.x, lidx):
                    rhs = e.y
                    # 过滤包含运行时调用的赋值
                    if expr_contains_call(rhs):
                        return 0
                    res.update(collect_func_objs(rhs))

            visited += 1
            return 0

    DF().apply_to(cfunc.body, None)
    return list(res)


def try_direct(expr) -> Optional[int]:
    """尝试直接从表达式里解析出函数对象 EA。"""
    if expr.op == ida_hexrays.cot_obj:
        return expr.obj_ea
    if expr.op in (
        ida_hexrays.cot_cast,
        ida_hexrays.cot_ref,
        ida_hexrays.cot_ptr,
        ida_hexrays.cot_memptr,
        ida_hexrays.cot_memref,
    ):
        return try_direct(expr.x)
    return None


def collect_callees_from_hexrays(func_ea: int) -> List[int]:
    """从 Hex-Rays ctree 中收集可能的被调函数（含函数指针/表/常量/异或等混淆场景）。"""
    if not ida_hexrays.init_hexrays_plugin():
        return []

    try:
        cfunc = ida_hexrays.decompile(func_ea)
    except Exception:
        return []
    if not cfunc:
        return []

    found: Set[int] = set()

    class CV(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            if e.op != ida_hexrays.cot_call:
                return 0

            callees: Set[int] = set()

            # 1) 直接从调用表达式得出的目标（如果有）
            d = try_direct(e.x)
            if d:
                callees.add(d)

            # 2) 表达式中出现的函数对象
            for x in collect_func_objs(e.x):
                callees.add(x)

            # 3) 数据流回溯函数指针定义得到的候选目标
            for x in resolve_callee_via_defs(cfunc, e.x):
                callees.add(x)

            for ea in callees:
                if ea == idc.BADADDR:
                    continue
                ea = resolve_final_target(ea)
                ea = normalize_to_func_start(ea)
                if is_internal(ea):
                    found.add(ea)
            return 0

    CV().apply_to(cfunc.body, None)
    return sorted(found)


# --------------------------------------------------------------------------
# Callgraph expansion (asm + tailcall + thunk + hexrays)


callees_cache: Dict[int, List[int]] = {}


def direct_callees(func_ea: int) -> List[int]:
    """返回 func_ea 直接可能到达的内部函数列表（带缓存）。"""
    if func_ea in callees_cache:
        return callees_cache[func_ea]

    res: Set[int] = set()

    f = ida_funcs.get_func(func_ea)
    if not f:
        callees_cache[func_ea] = []
        return []

    # (1) 正常 call（汇编扫描 + xref）
    for insn in idautils.FuncItems(func_ea):
        if idaapi.is_call_insn(insn):
            for xr in idautils.XrefsFrom(insn, ida_xref.XREF_FAR):
                if not xr.iscode:
                    continue
                tgt = resolve_final_target(xr.to)
                tgt = normalize_to_func_start(tgt)
                if tgt != func_ea and is_internal(tgt):
                    res.add(tgt)
            continue

        # (2) 尾调用 (jmp)
        first_xref = next(idautils.XrefsFrom(insn, ida_xref.XREF_FAR), None)
        if first_xref and is_tail_jump(insn, first_xref.to):
            tgt = resolve_final_target(first_xref.to)
            tgt = normalize_to_func_start(tgt)
            if tgt != func_ea and is_internal(tgt):
                res.add(tgt)

    # (3) thunk
    if f.flags & ida_funcs.FUNC_THUNK:
        tgt = ida_funcs.calc_thunk_func_target(f)
        if isinstance(tgt, int) and tgt != idc.BADADDR:
            tgt = resolve_final_target(tgt)
            tgt = normalize_to_func_start(tgt)
            if tgt != func_ea and is_internal(tgt):
                res.add(tgt)

    # (4) Hex-Rays (函数指针/混淆表等)
    try:
        for tgt in collect_callees_from_hexrays(func_ea):
            if tgt != func_ea and is_internal(tgt):
                res.add(tgt)
    except Exception:
        # 反编译失败时忽略，不让脚本整体失败
        pass

    out = sorted(res)
    callees_cache[func_ea] = out
    return out


def build_reachable_subgraph(entry_ea: int) -> Tuple[Set[int], Dict[int, List[int]]]:
    """从 entry_ea 出发遍历可达子图，返回(节点集合, 邻接表)。"""
    visited: Set[int] = set()
    edges: Dict[int, List[int]] = {}

    stack: List[int] = [entry_ea]
    while stack:
        cur = stack.pop()
        if cur in visited:
            continue
        visited.add(cur)

        nxt = direct_callees(cur)
        edges[cur] = nxt
        for n in nxt:
            if n not in visited:
                stack.append(n)

    return visited, edges


def ea_to_name(ea: int) -> str:
    return idc.get_func_name(ea) or idaapi.get_name(ea) or f"{ea:#x}"


# --------------------------------------------------------------------------
# main


def main() -> None:
    ida_auto.auto_wait()

    # 尽量初始化 Hex-Rays（失败也允许继续，仅影响间接调用恢复能力）
    try:
        if ida_hexrays.init_hexrays_plugin():
            idc.msg(f"Hex-Rays {ida_hexrays.get_hexrays_version()} loaded\n")
    except Exception:
        pass

    start_name = parse_args()
    entry_ea = resolve_func_start_ea(start_name)

    idc.msg(f"[+] start_func = {start_name}\n")
    idc.msg(f"[+] entry_ea   = {entry_ea:#x}\n")

    reachable_ea, edges_ea = build_reachable_subgraph(entry_ea)

    reachable_names = sorted({ea_to_name(ea) for ea in reachable_ea})

    edges_name: Dict[str, List[str]] = {}
    for src_ea, dst_list in edges_ea.items():
        src_name = ea_to_name(src_ea)
        edges_name[src_name] = sorted({ea_to_name(d) for d in dst_list})

    out_obj = {
        "entry": ea_to_name(entry_ea),
        "reachable_funcs": reachable_names,
        "edges": edges_name,
    }

    out_path = get_output_path()
    with open(out_path, "w", encoding="utf-8") as fp:
        json.dump(out_obj, fp, ensure_ascii=False, indent=2)

    idc.msg(
        f"[+] reachable={len(reachable_names)}  nodes, edges={sum(len(v) for v in edges_name.values())}\n"
    )
    idc.msg(f"[+] written -> {out_path}\n")

    idaapi.qexit(0)


if __name__ == "__main__":
    main()
