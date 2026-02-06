# -*- coding: utf-8 -*-
"""
call_find_final.py  –  IDA 9.1

按伪代码行号收集函数调用，过滤回溯时的运行时调用；
增加“调用方式”字段：DIRECT / INDIRECT。

调用示例：
    ida.exe -A -L"output.log" -S"call_find_final.py funcs_list=A1" target.elf
"""

import idaapi
import ida_auto
import ida_hexrays
import ida_funcs
import ida_xref
import idautils
import idc
import ida_bytes
import ida_ua        # 操作数类型 o_near / o_reg 等
import json
import os
from typing import List, Dict, Set, Optional, Tuple

OUT_FILE = "func_call.json"

# ---------- 通用辅助 ----------

def strip_dot_prefix(name: str) -> str:
    """去掉符号名前导 '.'，便于统一显示。"""
    return name[1:] if name.startswith('.') else name


def is_plt_segment(seg) -> bool:
    return seg is not None and (idaapi.get_segm_name(seg) or "").startswith(".plt")


def get_thunk_target_ea(func: ida_funcs.func_t) -> Optional[int]:
    """如果是 thunk 函数，则返回其真实目标 EA。"""
    if func and (func.flags & ida_funcs.FUNC_THUNK):
        tgt = ida_funcs.calc_thunk_func_target(func)
        if isinstance(tgt, int) and tgt != idc.BADADDR:
            return tgt
    return None


def resolve_final_target(ea: int) -> int:
    """沿 thunk 链一路解引用到最终目标函数 EA。"""
    seen = set()
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


def ea_category(ea: int) -> str:
    """根据 EA 粗略分类：IMPORT_API / USER_DEF / OTHER。"""
    if ea == idc.BADADDR:
        return "OTHER"

    f = ida_funcs.get_func(ea)
    if not f:
        seg = idaapi.getseg(ea)
        return "IMPORT_API" if seg and seg.type == idaapi.SEG_XTRN else "OTHER"

    seg = idaapi.getseg(ea)
    if seg and seg.type == idaapi.SEG_XTRN:
        return "IMPORT_API"
    if is_plt_segment(seg):
        return "IMPORT_API"

    # thunk 指向外部导入
    tgt = get_thunk_target_ea(f)
    if tgt is not None:
        seg2 = idaapi.getseg(tgt)
        if seg2 and seg2.type == idaapi.SEG_XTRN:
            return "IMPORT_API"

    if f.flags & ida_funcs.FUNC_LIB:
        return "IMPORT_API"

    return "USER_DEF"


def normalize_api_name(ea: int, raw: str) -> str:
    """规范化导入 API 名字，去掉前缀和 thunk 包装。"""
    for p in (".", "_imp_", "__imp_"):
        if raw.startswith(p):
            raw = raw[len(p):]
    f = ida_funcs.get_func(ea)
    if f and (f.flags & ida_funcs.FUNC_THUNK):
        tgt = get_thunk_target_ea(f)
        if tgt and tgt != idc.BADADDR:
            raw2 = idaapi.get_name(tgt) or raw
            return normalize_api_name(tgt, raw2)
    return raw

# ---------- 行号映射 ----------

def build_ea2line_map_via_eamap(cfunc):
    """通过 eamap 构建指令 EA -> 伪代码行号 映射。"""
    ea2line = {}
    if not cfunc:
        return ea2line
    _ = cfunc.get_pseudocode()
    em = cfunc.get_eamap()
    if not em:
        return ea2line
    for ea in list(em.keys()):
        best = None
        for it in em[ea]:
            try:
                _c, r = cfunc.find_item_coords(it)
                if r >= 0 and (best is None or r < best):
                    best = r
            except Exception:
                pass
        if best is not None:
            ea2line[ea] = best + 1
    return ea2line


def build_ea2line_map_via_ctree(cfunc):
    """退而求其次：按语句顺序给 ctree 里的 stmt 编行号。"""
    ea2line = {}
    ln = 1
    if not cfunc:
        return ea2line

    class W(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_stmt(self, s):
            nonlocal ln
            if s.ea != idc.BADADDR and s.ea not in ea2line:
                ea2line[s.ea] = ln
            ln += 1
            return 0

    W().apply_to(cfunc.body, None)
    return ea2line


def choose_ea2line_map_builder(cfunc):
    """优先用 eamap，不行再用 ctree 顺序。"""
    try:
        m = build_ea2line_map_via_eamap(cfunc)
        if m:
            return m
    except Exception:
        pass
    return build_ea2line_map_via_ctree(cfunc)

# ---------- 基于汇编的调用类型判定 ----------

def asm_call_type(insn_ea: int) -> str:
    """
    基于汇编指令判断调用类型：
    - 直接调用：call 0x12345678，操作数类型为 o_near/o_far -> "DIRECT"
    - 间接调用：call rax / call [rbp+...] / call [rax+8] 等 -> "INDIRECT"
    判不出来时，保守认为 INDIRECT。
    """
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, insn_ea) == 0:
        # 解码失败，宁可保守当作间接，避免把间接误判为直接
        return "INDIRECT"

    op0 = insn.ops[0]
    if op0.type in (ida_ua.o_near, ida_ua.o_far):
        return "DIRECT"
    # 其余类型（寄存器、内存、位移等）一律视为间接
    return "INDIRECT"

# ---------- 汇编层 ----------

def collect_callees_from_asm(func_ea, ea2line):
    """
    汇编层收集 callees：
    返回 (callee_ea, line, call_type)，
    这里的 call_type 完全由底层 call 指令形式决定。
    """
    out = []
    f = ida_funcs.get_func(func_ea)
    if not f:
        return out

    for insn_ea in idautils.FuncItems(func_ea):
        if not idaapi.is_call_insn(insn_ea):
            continue

        ln = ea2line.get(insn_ea, 0)
        ctype = asm_call_type(insn_ea)

        for xr in idautils.XrefsFrom(insn_ea, ida_xref.XREF_FAR):
            if xr.iscode:
                callee_ea = resolve_final_target(xr.to)
                out.append((callee_ea, ln, ctype))
    return out

# ---------- 反编译层辅助 ----------

def collect_func_objs(expr) -> Set[int]:
    """在给定表达式中收集所有 cot_obj（即函数/对象 EA）。"""
    s: Set[int] = set()

    class V(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_obj:
                s.add(e.obj_ea)
            return 0

    V().apply_to(expr, None)
    return s


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
    h = False

    class C(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            nonlocal h
            if e.op == ida_hexrays.cot_var and e.v.idx in idxs:
                h = True
                return 1
            return 0

    C().apply_to(expr, None)
    return h


def resolve_callee_via_defs(cfunc, callee_expr) -> List[int]:
    """
    数据流回溯：从 callee_expr 所涉及的局部变量出发，回溯赋值，
    收集其中出现的函数对象（cot_obj），但过滤掉 RHS 中包含 call 的赋值。
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
    MAX = 2000

    class DF(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            nonlocal visited
            if visited > MAX:
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
    """尝试直接从表达式里解析出函数对象 EA（不再用于直/间接判定，仅用于找目标）。"""
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


def get_row_of_call(cfunc, call_expr) -> int:
    """获取调用在伪代码中的行号（从 1 开始），失败则为 0。"""
    try:
        _c, r = cfunc.find_item_coords(call_expr)
        if r >= 0:
            return r + 1
    except Exception:
        pass
    return 0

# ---------- 反编译层 ----------

def collect_callees_from_hexrays(func_ea, cfunc):
    """
    从 Hex-Rays ctree 中收集调用：
    返回 (callee_ea, line, call_type)。
    关键点：call_type 仍然**优先参考底层汇编 call 指令**，
    即通过 e.ea 调回 asm_call_type()。
    """
    if not cfunc:
        return []
    out = []

    class CV(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            if e.op != ida_hexrays.cot_call:
                return 0

            ln = get_row_of_call(cfunc, e)

            # 优先通过对应的汇编 call 指令判断 DIRECT / INDIRECT
            if e.ea != idc.BADADDR and idaapi.is_call_insn(e.ea):
                ctype = asm_call_type(e.ea)
            else:
                # 非常规情况（没有可用 EA），退回到“能否直接解析出函数对象”的粗判
                dtmp = try_direct(e.x)
                ctype = "DIRECT" if dtmp is not None else "INDIRECT"

            callees: Set[int] = set()

            # 1) 直接从调用表达式得出的目标（如果有）
            d = try_direct(e.x)
            if d:
                callees.add(resolve_final_target(d))

            # 2) 表达式中出现的函数对象
            for x in collect_func_objs(e.x):
                callees.add(resolve_final_target(x))

            # 3) 数据流回溯函数指针定义得到的候选目标
            for x in resolve_callee_via_defs(cfunc, e.x):
                callees.add(resolve_final_target(x))

            for ea in callees:
                if ea != idc.BADADDR:
                    out.append((ea, ln, ctype))
            return 0

    CV().apply_to(cfunc.body, None)
    return out

# ---------- 汇总 ----------

def get_function_calls(func_ea):
    """对单个函数入口 EA 返回调用列表。"""
    if func_ea == idc.BADADDR:
        return []

    cfunc = ida_hexrays.decompile(func_ea)
    ea2line = choose_ea2line_map_builder(cfunc)

    asm_calls = collect_callees_from_asm(func_ea, ea2line)
    hr_calls = collect_callees_from_hexrays(func_ea, cfunc)

    # 按 (ea, ln) 聚合所有来源的 call_type
    call_map: Dict[Tuple[int, int], Set[str]] = {}

    for ea, ln, ctype in asm_calls + hr_calls:
        key = (ea, ln)
        s = call_map.get(key)
        if s is None:
            call_map[key] = {ctype}
        else:
            s.add(ctype)

    res = []
    for (ea, ln), types in call_map.items():
        # 如果同一 (ea, ln) 既有 DIRECT 又有 INDIRECT，统一按 INDIRECT 处理（间接优先）
        call_type = "INDIRECT" if "INDIRECT" in types else "DIRECT"

        cat = ea_category(ea)
        raw = idaapi.get_name(ea) or f"{ea:#x}"
        if cat == "IMPORT_API":
            name = normalize_api_name(ea, raw)
        else:
            name = strip_dot_prefix(raw)

        res.append({
            "name": name,
            "cat": cat,
            "ln": ln,
            "call_type": call_type
        })

    # 排序：先按行号，再按名称
    res.sort(key=lambda x: (x["ln"], x["name"]))
    return res

# ---------- CLI & main ----------

def parse_args():
    """
    从 idc.ARGV 解析 funcs_list 参数：
        funcs_list=foo,bar
        或 funcs_list=["foo","bar"]
    """
    lst = []
    for a in idc.ARGV:
        if a.startswith("funcs_list="):
            raw = a.split("=", 1)[1].strip()
            if raw.startswith("["):
                try:
                    lst = json.loads(raw)
                except Exception:
                    pass
            else:
                lst = [x.strip() for x in raw.split(",") if x.strip()]
    if not lst:
        idc.msg('Usage: -S"call_find_final.py funcs_list=funA,funB"\n')
        idaapi.qexit(1)
    return lst


def get_ea_by_name(name):
    """通过函数名拿到其函数起始 EA。"""
    ea = idc.get_name_ea_simple(name)
    if ea == idc.BADADDR:
        return idc.BADADDR
    f = ida_funcs.get_func(ea)
    return f.start_ea if f else idc.BADADDR


def main():
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()

    funcs = parse_args()
    result: Dict[str, list] = {}

    for fn in funcs:
        ea = get_ea_by_name(fn)
        if ea == idc.BADADDR:
            continue
        result[fn] = get_function_calls(ea)

    with open(OUT_FILE, "w", encoding="utf-8") as fp:
        json.dump(result, fp, ensure_ascii=False, indent=2)

    idc.msg(f"[+] Done -> {os.path.abspath(OUT_FILE)}\n")
    idaapi.qexit(0)


if __name__ == "__main__":
    main()
