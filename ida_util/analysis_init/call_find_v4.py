# -*- coding: utf-8 -*-
"""
call_find_v4.py  –  IDA 9.1 适用版本
自动收集函数内所有调用点（汇编+反编译）并标注伪代码行号
"""

import idaapi          # type: ignore
import ida_auto        # type: ignore
import ida_hexrays     # type: ignore
import ida_funcs       # type: ignore
import ida_xref        # type: ignore
import idautils        # type: ignore
import idc             # type: ignore
import ida_bytes       # type: ignore
import ida_name        # type: ignore

import json
import os
from typing import List, Dict, Set, Optional, Tuple

OUT_FILE = "cc_path.json"

# --------------------------------------------------------------------------
#   行号映射
# --------------------------------------------------------------------------

def build_ea2line_map_via_eamap(cfunc) -> Dict[int, int]:
    """
    使用 eamap + find_item_coords 获取 {ea: 行号}。
    注意：find_item_coords(item) 返回 (column, row)，列号在前！
    """
    ea2line: Dict[int, int] = {}
    if not cfunc:
        return ea2line

    _ = cfunc.get_pseudocode()           # 先生成伪代码行缓存
    eamap = cfunc.get_eamap()
    if not eamap or eamap.size() == 0:
        return ea2line

    for ea in list(eamap.keys()):
        vec = eamap[ea] if hasattr(eamap, "__getitem__") else eamap.at(ea)
        if not vec:
            continue

        min_row = None
        for item in vec:                 # 同一条指令可能映射多个 citem
            try:
                col, row = cfunc.find_item_coords(item)   # ← 关键：列在前
                if row >= 0 and (min_row is None or row < min_row):
                    min_row = row
            except Exception:
                continue

        if min_row is not None:
            ea2line[ea] = min_row + 1    # 行号改成 1‑based

    return ea2line


def build_ea2line_map_via_ctree(cfunc) -> Dict[int, int]:
    """旧版本回退方案：按 statement 顺序编号"""
    ea2line = {}
    if not cfunc:
        return ea2line

    line_no = 1

    class Walker(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
        def visit_stmt(self, s):
            nonlocal line_no
            if s.ea != idc.BADADDR and s.ea not in ea2line:
                ea2line[s.ea] = line_no
            line_no += 1
            return 0

    Walker().apply_to(cfunc.body, None)
    return ea2line


def choose_ea2line_map_builder(cfunc) -> Dict[int, int]:
    """优先 eamap，失败回退 ctree"""
    try:
        m = build_ea2line_map_via_eamap(cfunc)
        if m:
            return m
    except Exception as ex:
        idaapi.msg(f"[!] eamap builder failed: {ex}\n")

    idaapi.msg("[+] Fallback to ctree statement-based indexing.\n")
    return build_ea2line_map_via_ctree(cfunc)

# --------------------------------------------------------------------------
#   其他辅助函数（保持不变）
# --------------------------------------------------------------------------

def parse_args() -> List[str]:
    funcs_list = []
    for a in idc.ARGV:
        if a.startswith("funcs_list="):
            raw_str = a.split("=", 1)[1].strip()
            if raw_str.startswith("["):
                try:
                    funcs_list = json.loads(raw_str)
                except Exception:
                    pass
            else:
                funcs_list = [x.strip() for x in raw_str.split(",") if x.strip()]
    if not funcs_list:
        idc.msg('Usage: -S"path_dfs_v4.py funcs_list=funA,funB"\n')
        idaapi.qexit(1)
    return funcs_list


def get_ea_by_name(name: str) -> int:
    ea = idc.get_name_ea_simple(name)
    if ea == idc.BADADDR:
        return idc.BADADDR
    f = ida_funcs.get_func(ea)
    return f.start_ea if f else idc.BADADDR


def strip_dot_prefix(name: str) -> str:
    return name[1:] if name.startswith('.') else name


def is_plt_segment(seg) -> bool:
    return seg is not None and (idaapi.get_segm_name(seg) or "").startswith(".plt")


def get_thunk_target_ea(func: ida_funcs.func_t) -> Optional[int]:
    if func.flags & ida_funcs.FUNC_THUNK:
        tgt = ida_funcs.calc_thunk_func_target(func)
        if isinstance(tgt, int) and tgt != idc.BADADDR:
            return tgt
    return None


def ea_category(ea: int) -> str:
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
    tgt_ea = get_thunk_target_ea(f)
    if tgt_ea:
        seg2 = idaapi.getseg(tgt_ea)
        if seg2 and seg2.type == idaapi.SEG_XTRN:
            return "IMPORT_API"
    if f.flags & ida_funcs.FUNC_LIB:
        return "IMPORT_API"
    return "USER_DEF"


def normalize_api_name(ea: int, raw_name: str) -> str:
    for prefix in (".", "_imp_", "__imp_"):
        if raw_name.startswith(prefix):
            raw_name = raw_name[len(prefix):]
    f = ida_funcs.get_func(ea)
    if f and (f.flags & ida_funcs.FUNC_THUNK):
        tgt_ea = get_thunk_target_ea(f)
        if tgt_ea and tgt_ea != idc.BADADDR:
            tmp = idaapi.get_name(tgt_ea) or ""
            if tmp and tmp != raw_name:
                return normalize_api_name(tgt_ea, tmp)
    return raw_name

# --------------------------------------------------------------------------
#   汇编层获取 callee
# --------------------------------------------------------------------------

def is_tail_jump(insn_ea: int, target_ea: int) -> bool:
    if idaapi.is_call_insn(insn_ea):
        return False
    if ida_bytes.is_flow(idaapi.get_full_flags(insn_ea)):
        return False
    tgt_func = ida_funcs.get_func(target_ea)
    return tgt_func is not None and tgt_func.start_ea == target_ea


def collect_callees_from_asm(func_ea: int) -> List[Tuple[int, int]]:
    results: List[Tuple[int, int]] = []
    f = ida_funcs.get_func(func_ea)
    if not f:
        return results

    for insn_ea in idautils.FuncItems(func_ea):
        if idaapi.is_call_insn(insn_ea):
            for xr in idautils.XrefsFrom(insn_ea, ida_xref.XREF_FAR):
                if xr.iscode:
                    results.append((xr.to, insn_ea))
        else:
            xr = next(idautils.XrefsFrom(insn_ea, ida_xref.XREF_FAR), None)
            if xr and is_tail_jump(insn_ea, xr.to):
                results.append((xr.to, insn_ea))

    if f.flags & ida_funcs.FUNC_THUNK:
        tgt = ida_funcs.calc_thunk_func_target(f)
        if isinstance(tgt, int):
            results.append((tgt, func_ea))
    return results

# --------------------------------------------------------------------------
#   反编译层获取 callee
# --------------------------------------------------------------------------

def collect_func_objs(expr) -> Set[int]:
    found: Set[int] = set()
    class V(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_obj:
                found.add(e.obj_ea)
            return 0
    V().apply_to(expr, None)
    return found


def expr_uses_lvar(expr, lvar_idx_set: Set[int]) -> bool:
    class C(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
            self.hit = False
        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_var and e.v.idx in lvar_idx_set:
                self.hit = True
                return 1
            return 0
    chk = C()
    chk.apply_to(expr, None)
    return chk.hit


def resolve_callee_via_defs(cfunc, callee_expr) -> List[int]:
    results: Set[int] = set()
    lvar_idx_set: Set[int] = set()

    class Grab(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_var:
                lvar_idx_set.add(e.v.idx)
            return 0

    Grab().apply_to(callee_expr, None)
    if not lvar_idx_set:
        return []

    MAX_DEF = 1000
    visited = 0

    class Def(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
        def visit_expr(self, e):
            nonlocal visited
            if visited > MAX_DEF:
                return 1
            if e.op == ida_hexrays.cot_asg:
                lhs, rhs = e.x, e.y
                if expr_uses_lvar(lhs, lvar_idx_set):
                    objs = collect_func_objs(rhs)
                    results.update(objs)
            visited += 1
            return 0

    Def().apply_to(cfunc.body, None)
    return list(results)


def try_resolve_callee(expr) -> Optional[int]:
    if expr.op == ida_hexrays.cot_obj:
        return expr.obj_ea
    elif expr.op in (
        ida_hexrays.cot_cast, ida_hexrays.cot_ref, ida_hexrays.cot_ptr,
        ida_hexrays.cot_memptr, ida_hexrays.cot_memref
    ):
        return try_resolve_callee(expr.x)
    return None


def collect_callees_from_hexrays(func_ea: int) -> List[Tuple[int, int]]:
    if not ida_hexrays.init_hexrays_plugin():
        return []
    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        return []

    found: List[Tuple[int, int]] = []

    class CallVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
        def visit_expr(self, e):
            if e.op != ida_hexrays.cot_call:
                return 0

            callee_expr = e.x
            direct = try_resolve_callee(callee_expr)

            # 使用表达式自身的 ea；在 9.x 中多数情况下有效
            call_ea = e.ea

            if direct and direct != idc.BADADDR:
                found.append((direct, call_ea))
            else:
                inline_objs = collect_func_objs(callee_expr)
                if len(inline_objs) == 1:
                    found.append((next(iter(inline_objs)), call_ea))
                else:
                    for tgt in resolve_callee_via_defs(cfunc, callee_expr):
                        found.append((tgt, call_ea))
            return 0

    CallVisitor().apply_to(cfunc.body, None)
    return found

# --------------------------------------------------------------------------
#   汇总
# --------------------------------------------------------------------------

def get_function_calls(func_ea: int) -> List[Tuple[str, str, int]]:
    if func_ea == idc.BADADDR:
        return []

    asm_calls = collect_callees_from_asm(func_ea)
    hr_calls  = collect_callees_from_hexrays(func_ea)
    combined  = asm_calls + hr_calls

    cfunc   = ida_hexrays.decompile(func_ea)
    ea2line = choose_ea2line_map_builder(cfunc)

    calls_dict: Dict[Tuple[int, int], int] = {}
    for callee_ea, callsite_ea in combined:
        line_no   = ea2line.get(callsite_ea, 0)
        prev_line = calls_dict.get((callee_ea, callsite_ea), 0)
        if prev_line == 0 or (line_no and line_no < prev_line):
            calls_dict[(callee_ea, callsite_ea)] = line_no

    results: List[Tuple[str, str, int]] = []
    for (callee_ea, _callsite), ln in calls_dict.items():
        cat       = ea_category(callee_ea)
        raw_name  = idaapi.get_name(callee_ea) or f"{callee_ea:#x}"
        callee_nm = normalize_api_name(callee_ea, raw_name) if cat == "IMPORT_API" else strip_dot_prefix(raw_name)
        results.append((callee_nm, cat, ln))
    return results


def main():
    ida_auto.auto_wait()
    if ida_hexrays.init_hexrays_plugin():
        idc.msg(f"[+] Hex‑Rays {ida_hexrays.get_hexrays_version()} loaded\n")

    funcs_list = parse_args()
    idc.msg(f"[+] funcs_list = {funcs_list}\n")
    idc.msg(f"[+] output    = {OUT_FILE}\n")

    result = {}
    for fn in funcs_list:
        ea = get_ea_by_name(fn)
        if ea == idc.BADADDR:
            continue
        calls = get_function_calls(ea)
        calls.sort(key=lambda x: (x[2], x[0]))          # 行号 + 名字
        result[fn] = calls

    with open(OUT_FILE, "w", encoding="utf-8") as fp:
        json.dump(result, fp, ensure_ascii=False, indent=2)

    idc.msg(f"[+] Done! Wrote results to {os.path.abspath(OUT_FILE)}\n")
    idaapi.qexit(0)


if __name__ == "__main__":
    main()
