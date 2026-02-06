# -*- coding: utf-8 -*-
"""
call_find_fixed.py  –  适用于 IDA 9.1
收集函数内所有调用点（汇编 + 反编译）并标注伪代码行号
"""

import idaapi, ida_auto, ida_hexrays, ida_funcs, ida_xref
import idautils, idc, ida_bytes, json, os
from typing import List, Dict, Set, Optional, Tuple

OUT_FILE = "cc_path.json"

# ----------------------------------------------------------------------
# 0. 统一工具
# ----------------------------------------------------------------------
def strip_dot_prefix(name: str) -> str:
    return name[1:] if name.startswith('.') else name

def is_plt_segment(seg) -> bool:
    return seg is not None and (idaapi.get_segm_name(seg) or "").startswith(".plt")

def get_thunk_target_ea(func: ida_funcs.func_t) -> Optional[int]:
    if func and (func.flags & ida_funcs.FUNC_THUNK):
        tgt = ida_funcs.calc_thunk_func_target(func)
        if isinstance(tgt, int) and tgt != idc.BADADDR:
            return tgt
    return None

def resolve_final_target(ea: int) -> int:
    """递归解析多层 thunk/stub"""
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
    if get_thunk_target_ea(f):
        tgt = get_thunk_target_ea(f)
        seg2 = idaapi.getseg(tgt) if tgt else None
        if seg2 and seg2.type == idaapi.SEG_XTRN:
            return "IMPORT_API"
    if f.flags & ida_funcs.FUNC_LIB:
        return "IMPORT_API"
    return "USER_DEF"

def normalize_api_name(ea: int, raw: str) -> str:
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

# ----------------------------------------------------------------------
# 1. 行号映射（汇编层使用）
# ----------------------------------------------------------------------
def build_ea2line_map_via_eamap(cfunc) -> Dict[int, int]:
    ea2line: Dict[int, int] = {}
    if not cfunc:
        return ea2line
    _ = cfunc.get_pseudocode()
    eamap = cfunc.get_eamap()
    if not eamap:
        return ea2line
    for ea in list(eamap.keys()):
        best = None
        for item in eamap[ea]:
            try:
                col, row = cfunc.find_item_coords(item)
                if row >= 0 and (best is None or row < best):
                    best = row
            except Exception:
                pass
        if best is not None:
            ea2line[ea] = best + 1
    return ea2line

def build_ea2line_map_via_ctree(cfunc) -> Dict[int, int]:
    ea2line = {}
    if not cfunc:
        return ea2line
    ln = 1
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

def choose_ea2line_map_builder(cfunc) -> Dict[int, int]:
    try:
        m = build_ea2line_map_via_eamap(cfunc)
        if m:
            return m
    except Exception:
        pass
    return build_ea2line_map_via_ctree(cfunc)

# ----------------------------------------------------------------------
# 2. 汇编层收集 (callee_ea, line_no)
# ----------------------------------------------------------------------
def collect_callees_from_asm(func_ea: int,
                             ea2line: Dict[int, int]) -> List[Tuple[int, int]]:
    out: List[Tuple[int, int]] = []
    f = ida_funcs.get_func(func_ea)
    if not f:
        return out
    for insn_ea in idautils.FuncItems(func_ea):
        if not idaapi.is_call_insn(insn_ea):
            continue
        ln = ea2line.get(insn_ea, 0)          # 行号可能为 0
        for xr in idautils.XrefsFrom(insn_ea, ida_xref.XREF_FAR):
            if xr.iscode:
                out.append((resolve_final_target(xr.to), ln))
    return out

# ----------------------------------------------------------------------
# 3. 反编译层辅助
# ----------------------------------------------------------------------
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

def expr_uses_lvar(expr, idxs: Set[int]) -> bool:
    class C(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST); self.hit=False
        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_var and e.v.idx in idxs:
                self.hit=True; return 1
            return 0
    c=C(); c.apply_to(expr,None); return c.hit

def resolve_callee_via_defs(cfunc, callee_expr) -> List[int]:
    lvar_idxs: Set[int] = set()
    class Grab(ida_hexrays.ctree_visitor_t):
        def __init__(self): super().__init__(ida_hexrays.CV_FAST)
        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_var: lvar_idxs.add(e.v.idx)
            return 0
    Grab().apply_to(callee_expr, None)
    if not lvar_idxs: return []
    results: Set[int] = set(); visited=0; MAX_DEF=2000
    class DF(ida_hexrays.ctree_visitor_t):
        def __init__(self): super().__init__(ida_hexrays.CV_FAST)
        def visit_expr(self, e):
            nonlocal visited
            if visited>MAX_DEF: return 1
            if e.op==ida_hexrays.cot_asg:
                if expr_uses_lvar(e.x,lvar_idxs):
                    results.update(collect_func_objs(e.y))
            visited+=1; return 0
    DF().apply_to(cfunc.body,None)
    return list(results)

def try_direct(expr) -> Optional[int]:
    if expr.op == ida_hexrays.cot_obj:
        return expr.obj_ea
    if expr.op in (ida_hexrays.cot_cast, ida_hexrays.cot_ref,
                   ida_hexrays.cot_ptr, ida_hexrays.cot_memptr,
                   ida_hexrays.cot_memref):
        return try_direct(expr.x)
    return None

def get_row_of_call(cfunc, call_expr) -> int:
    try:
        _c, r = cfunc.find_item_coords(call_expr)
        if r >= 0: return r+1
    except Exception:
        pass
    return 0

# ----------------------------------------------------------------------
# 4. 反编译层收集 (callee_ea, line_no)
# ----------------------------------------------------------------------
def collect_callees_from_hexrays(func_ea: int,
                                 cfunc) -> List[Tuple[int, int]]:
    if not cfunc: return []
    out: List[Tuple[int, int]] = []
    class CV(ida_hexrays.ctree_visitor_t):
        def __init__(self): super().__init__(ida_hexrays.CV_FAST)
        def visit_expr(self, e):
            if e.op != ida_hexrays.cot_call: return 0
            ln = get_row_of_call(cfunc, e)
            callees: Set[int] = set()
            d = try_direct(e.x)
            if d: callees.add(resolve_final_target(d))
            callees.update(resolve_final_target(x) for x in collect_func_objs(e.x))
            callees.update(resolve_final_target(x) for x in resolve_callee_via_defs(cfunc, e.x))
            for ea in callees:
                if ea != idc.BADADDR:
                    out.append((ea, ln))
            return 0
    CV().apply_to(cfunc.body, None)
    return out

# ----------------------------------------------------------------------
# 5. 汇总
# ----------------------------------------------------------------------
def get_function_calls(func_ea: int) -> List[Tuple[str, str, int]]:
    if func_ea == idc.BADADDR: return []
    cfunc   = ida_hexrays.decompile(func_ea)
    ea2line = choose_ea2line_map_builder(cfunc)
    asm = collect_callees_from_asm(func_ea, ea2line)
    hr  = collect_callees_from_hexrays(func_ea, cfunc)

    uniq: Dict[Tuple[int, int], None] = {}
    for ea, ln in asm + hr:
        uniq[(ea, ln)] = None   # 行号可为 0

    res: List[Tuple[str, str, int]] = []
    for (ea, ln) in uniq:
        cat  = ea_category(ea)
        raw  = idaapi.get_name(ea) or f"{ea:#x}"
        name = normalize_api_name(ea, raw) if cat=="IMPORT_API" else strip_dot_prefix(raw)
        res.append((name, cat, ln))
    res.sort(key=lambda x: (x[2], x[0]))
    return res

# ----------------------------------------------------------------------
# 6. CLI & main
# ----------------------------------------------------------------------
def parse_args() -> List[str]:
    lst=[]
    for a in idc.ARGV:
        if a.startswith("funcs_list="):
            raw=a.split("=",1)[1].strip()
            if raw.startswith("["):
                try: lst=json.loads(raw)
                except: pass
            else:
                lst=[x.strip() for x in raw.split(",") if x.strip()]
    if not lst:
        idc.msg('Usage: -S"call_find_fixed.py funcs_list=funA,funB"\n')
        idaapi.qexit(1)
    return lst

def get_ea_by_name(name: str) -> int:
    ea=idc.get_name_ea_simple(name)
    if ea==idc.BADADDR: return idc.BADADDR
    f=ida_funcs.get_func(ea)
    return f.start_ea if f else idc.BADADDR

def main():
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    funcs=parse_args()
    result={}
    for fn in funcs:
        ea=get_ea_by_name(fn)
        if ea==idc.BADADDR: continue
        result[fn]=get_function_calls(ea)
    with open(OUT_FILE,"w",encoding="utf-8") as fp:
        json.dump(result,fp,ensure_ascii=False,indent=2)
    idc.msg(f"[+] Done -> {os.path.abspath(OUT_FILE)}\n")
    idaapi.qexit(0)

if __name__=="__main__":
    main()
