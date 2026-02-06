# -*- coding: utf-8 -*-
"""
call_find_final.py  –  IDA 9.1
按伪代码行号收集函数调用，过滤回溯时的运行时调用
"""
#PS E:\IDA_PRO_9_1> ./ida.exe -A -L"output.log" -S"G:\ida_util\analysis_init\call_find_v6.py funcs_list=A1" G:\vuln_test\test_cc\test_ccc.elf

import idaapi, ida_auto, ida_hexrays, ida_funcs, ida_xref
import idautils, idc, ida_bytes, json, os
from typing import List, Dict, Set, Optional, Tuple

OUT_FILE = "func_call.json"

# ---------- 通用辅助 ----------
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
    seen=set()
    while True:
        if ea in seen: return ea
        seen.add(ea)
        f=ida_funcs.get_func(ea)
        if not f or not (f.flags & ida_funcs.FUNC_THUNK):
            return ea
        tgt=ida_funcs.calc_thunk_func_target(f)
        if not isinstance(tgt,int) or tgt==idc.BADADDR:
            return ea
        ea=tgt

def ea_category(ea: int) -> str:
    if ea==idc.BADADDR: return "OTHER"
    f=ida_funcs.get_func(ea)
    if not f:
        seg=idaapi.getseg(ea)
        return "IMPORT_API" if seg and seg.type==idaapi.SEG_XTRN else "OTHER"
    seg=idaapi.getseg(ea)
    if seg and seg.type==idaapi.SEG_XTRN: return "IMPORT_API"
    if is_plt_segment(seg):               return "IMPORT_API"
    if get_thunk_target_ea(f):
        tgt=get_thunk_target_ea(f)
        seg2=idaapi.getseg(tgt) if tgt else None
        if seg2 and seg2.type==idaapi.SEG_XTRN: return "IMPORT_API"
    if f.flags & ida_funcs.FUNC_LIB:      return "IMPORT_API"
    return "USER_DEF"

def normalize_api_name(ea: int, raw: str) -> str:
    for p in (".","_imp_","__imp_"):
        if raw.startswith(p): raw=raw[len(p):]
    f=ida_funcs.get_func(ea)
    if f and (f.flags & ida_funcs.FUNC_THUNK):
        tgt=get_thunk_target_ea(f)
        if tgt and tgt!=idc.BADADDR:
            raw2=idaapi.get_name(tgt) or raw
            return normalize_api_name(tgt, raw2)
    return raw

# ---------- 行号映射 ----------
def build_ea2line_map_via_eamap(cfunc):
    ea2line={}
    if not cfunc: return ea2line
    _=cfunc.get_pseudocode()
    em=cfunc.get_eamap()
    if not em: return ea2line
    for ea in list(em.keys()):
        best=None
        for it in em[ea]:
            try:
                c,r=cfunc.find_item_coords(it)
                if r>=0 and (best is None or r<best):
                    best=r
            except: pass
        if best is not None: ea2line[ea]=best+1
    return ea2line

def build_ea2line_map_via_ctree(cfunc):
    ea2line={}; ln=1
    if not cfunc: return ea2line
    class W(ida_hexrays.ctree_visitor_t):
        def __init__(self): super().__init__(ida_hexrays.CV_FAST)
        def visit_stmt(self,s):
            nonlocal ln
            if s.ea!=idc.BADADDR and s.ea not in ea2line: ea2line[s.ea]=ln
            ln+=1; return 0
    W().apply_to(cfunc.body,None)
    return ea2line

def choose_ea2line_map_builder(cfunc):
    try:
        m=build_ea2line_map_via_eamap(cfunc)
        if m: return m
    except: pass
    return build_ea2line_map_via_ctree(cfunc)

# ---------- 汇编层 ----------
def collect_callees_from_asm(func_ea, ea2line):
    out=[]
    f=ida_funcs.get_func(func_ea)
    if not f: return out
    for insn_ea in idautils.FuncItems(func_ea):
        if not idaapi.is_call_insn(insn_ea): continue
        ln=ea2line.get(insn_ea,0)
        for xr in idautils.XrefsFrom(insn_ea, ida_xref.XREF_FAR):
            if xr.iscode: out.append((resolve_final_target(xr.to), ln))
    return out

# ---------- 反编译层辅助 ----------
def collect_func_objs(expr)->Set[int]:
    s=set()
    class V(ida_hexrays.ctree_visitor_t):
        def __init__(self): super().__init__(ida_hexrays.CV_FAST)
        def visit_expr(self,e):
            if e.op==ida_hexrays.cot_obj: s.add(e.obj_ea)
            return 0
    V().apply_to(expr,None); return s

def expr_contains_call(expr)->bool:
    hit=False
    class V(ida_hexrays.ctree_visitor_t):
        def __init__(self): super().__init__(ida_hexrays.CV_FAST)
        def visit_expr(self,e):
            nonlocal hit
            if e.op==ida_hexrays.cot_call: hit=True; return 1
            return 0
    V().apply_to(expr,None); return hit

def expr_uses_lvar(expr,idxs:Set[int])->bool:
    h=False
    class C(ida_hexrays.ctree_visitor_t):
        def __init__(self): super().__init__(ida_hexrays.CV_FAST)
        def visit_expr(self,e):
            nonlocal h
            if e.op==ida_hexrays.cot_var and e.v.idx in idxs: h=True; return 1
            return 0
    C().apply_to(expr,None); return h

# ---------- 核心修正：回溯时过滤含 call 的 rhs ----------
def resolve_callee_via_defs(cfunc, callee_expr)->List[int]:
    lidx=set()
    class Grab(ida_hexrays.ctree_visitor_t):
        def __init__(self): super().__init__(ida_hexrays.CV_FAST)
        def visit_expr(self,e):
            if e.op==ida_hexrays.cot_var: lidx.add(e.v.idx)
            return 0
    Grab().apply_to(callee_expr,None)
    if not lidx: return []

    res=set(); visited=0; MAX=2000
    class DF(ida_hexrays.ctree_visitor_t):
        def __init__(self): super().__init__(ida_hexrays.CV_FAST)
        def visit_expr(self,e):
            nonlocal visited
            if visited>MAX: return 1
            if e.op==ida_hexrays.cot_asg:
                if expr_uses_lvar(e.x,lidx):
                    rhs=e.y
                    # ------ 过滤包含运行时调用的赋值 ------
                    if expr_contains_call(rhs):
                        return 0
                    res.update(collect_func_objs(rhs))
            visited+=1; return 0
    DF().apply_to(cfunc.body,None)
    return list(res)

def try_direct(expr)->Optional[int]:
    if expr.op==ida_hexrays.cot_obj: return expr.obj_ea
    if expr.op in (ida_hexrays.cot_cast, ida_hexrays.cot_ref,
                   ida_hexrays.cot_ptr, ida_hexrays.cot_memptr,
                   ida_hexrays.cot_memref):
        return try_direct(expr.x)
    return None

def get_row_of_call(cfunc,call_expr)->int:
    try:
        _c,r=cfunc.find_item_coords(call_expr)
        if r>=0: return r+1
    except: pass
    return 0

# ---------- 反编译层 ----------
def collect_callees_from_hexrays(func_ea,cfunc):
    if not cfunc: return []
    out=[]
    class CV(ida_hexrays.ctree_visitor_t):
        def __init__(self): super().__init__(ida_hexrays.CV_FAST)
        def visit_expr(self,e):
            if e.op!=ida_hexrays.cot_call: return 0
            ln=get_row_of_call(cfunc,e)
            callees=set()
            d=try_direct(e.x)
            if d: callees.add(resolve_final_target(d))
            callees.update(resolve_final_target(x) for x in collect_func_objs(e.x))
            callees.update(resolve_final_target(x) for x in resolve_callee_via_defs(cfunc,e.x))
            for ea in callees:
                if ea!=idc.BADADDR: out.append((ea,ln))
            return 0
    CV().apply_to(cfunc.body,None); return out

# ---------- 汇总 ----------
def get_function_calls(func_ea):
    if func_ea==idc.BADADDR: return []
    cfunc=ida_hexrays.decompile(func_ea)
    ea2line=choose_ea2line_map_builder(cfunc)
    asm=collect_callees_from_asm(func_ea,ea2line)
    hr =collect_callees_from_hexrays(func_ea,cfunc)
    uniq={}
    for ea,ln in asm+hr: uniq[(ea,ln)]=None
    res=[]
    for (ea,ln) in uniq:
        cat=ea_category(ea)
        raw=idaapi.get_name(ea) or f"{ea:#x}"
        name=normalize_api_name(ea,raw) if cat=="IMPORT_API" else strip_dot_prefix(raw)
        res.append({"name": name, "cat": cat, "ln": ln})
    res.sort(key=lambda x: (x["ln"], x["name"]))
    return res

# ---------- CLI & main ----------
def parse_args():
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
        idc.msg('Usage: -S"call_find_final.py funcs_list=funA,funB"\n')
        idaapi.qexit(1)
    return lst

def get_ea_by_name(name):
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

#./ida -A -L"output.log" -S"/home/workspace/ida_util/analysis_init/call_find_v7.py funcs_list=sub_155F" /home/workspace/Testcase/test3/vuln_n
#./ida -A -L"output.log" -S"/home/workspace/ida_util/analysis_init/call_find_v6.py funcs_list=route_command" /home/workspace/Testcase/test2/vuln
#./ida -A -L"output.log" -S"/home/workspace/ida_util/analysis_init/call_find_v6.py funcs_list=technique2" /home/workspace/Testcase/call/test_ccx.elf
#./ida -A -L"output.log" -S"/home/workspace/ida_util/analysis_init/call_find_v6.py funcs_list=A1" /home/workspace/Testcase/call/test_ccc.elf
#./ida -A -L"output.log" -S"/home/workspace/ida_util/analysis_init/call_find_v7.py funcs_list=CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_memcpy_11_bad" /home/workspace/jc/t1/CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_memcpy_11-bad