# --------------------------------------------------------------------------
#  IDA 9.1  ‑  Call‑Map  v2
#  功能 : 给定函数列表，输出每个函数的直接调用图（含重复调用点、外部 API）
#  作者 : 2025‑04‑13  @ChatGPT‑o3
# --------------------------------------------------------------------------

import idaapi, ida_auto, ida_hexrays, ida_funcs, ida_xref, idautils, idc, ida_bytes # type: ignore
import json, os
from typing import List, Dict, Tuple, Set, Optional

OUT_FILE       = "callmap.json"
MAX_DEF_SEARCH = 1000          # 轻量切片阈

# --------------------------------------------------------------------------
# ---------------------------- 参数解析 ------------------------------------

def parse_args() -> List[str]:
    funcs: List[str] = []
    for a in idc.ARGV:
        if a.startswith("funcs_list="):
            funcs = [s.strip() for s in a.split("=", 1)[1].split(",") if s.strip()]
            break
    if not funcs:
        idc.msg('Usage: -S"callmap_v2.py funcs_list=f1,f2,..."\n')
        idaapi.qexit(1)
    return funcs

# --------------------------------------------------------------------------
# ---------------------------- 分类 / 名称 ----------------------------------

def is_plt(ea: int) -> bool:
    """
    判断地址 ea 是否落在 .plt / .plt.got 段
    兼容 IDA 9.x Python‑SDK
    """
    seg = idaapi.getseg(ea)
    if not seg:
        return False
    name = idaapi.get_segm_name(seg)   # ← 传 segment_t*
    return bool(name and name.startswith(".plt"))

def normalize_api_name(name: str) -> str:
    if name.startswith("."):
        return name[1:]
    for p in ("_imp_", "__imp_"):
        if name.startswith(p):
            return name[len(p):]
    return name

def ea_category(ea: int) -> str:
    if ea == idaapi.BADADDR:
        return "OTHER"

    seg = idaapi.getseg(ea)
    if seg and seg.type == idaapi.SEG_XTRN:
        return "IMPORT_API"

    f = ida_funcs.get_func(ea)
    if not f:
        return "OTHER"

    # thunk -> import
    if f.flags & ida_funcs.FUNC_THUNK:
        tgt = ida_funcs.calc_thunk_func_target(f)
        if isinstance(tgt, int):
            seg2 = idaapi.getseg(tgt)
            if seg2 and seg2.type == idaapi.SEG_XTRN:
                return "IMPORT_API"

    if is_plt(ea):
        return "IMPORT_API"

    if f.flags & ida_funcs.FUNC_LIB:
        return "IMPORT_API"

    return "USER_DEF"

# --------------------------------------------------------------------------
# ---------------------------- Hex‑Rays 辅助 -------------------------------

def try_resolve_callee(expr) -> Optional[int]:
    if expr.op == ida_hexrays.cot_obj:
        return expr.obj_ea
    elif expr.op in (ida_hexrays.cot_cast, ida_hexrays.cot_ref, ida_hexrays.cot_ptr,
                     ida_hexrays.cot_memptr, ida_hexrays.cot_memref):
        return try_resolve_callee(expr.x)
    return None

def collect_func_objs(expr) -> Set[int]:
    found: Set[int] = set()
    class _V(ida_hexrays.ctree_visitor_t):
        def __init__(self): super().__init__(ida_hexrays.CV_FAST)
        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_obj:
                found.add(e.obj_ea)
            return 0
    _V().apply_to(expr, None)
    return found

def expr_uses_lvar(expr, idx_set: Set[int]) -> bool:
    class _C(ida_hexrays.ctree_visitor_t):
        def __init__(self): super().__init__(ida_hexrays.CV_FAST); self.hit=False
        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_var and e.v.idx in idx_set:
                self.hit=True; return 1
            return 0
    c=_C(); c.apply_to(expr,None); return c.hit

def resolve_callee_via_defs(cfunc, callee_expr) -> List[int]:
    results: Set[int] = set()
    lvar_idx: Set[int] = set()
    class _G(ida_hexrays.ctree_visitor_t):
        def __init__(self): super().__init__(ida_hexrays.CV_FAST)
        def visit_expr(self,e):
            if e.op==ida_hexrays.cot_var: lvar_idx.add(e.v.idx)
            return 0
    _G().apply_to(callee_expr,None)
    if not lvar_idx: return []

    visited=0
    class _F(ida_hexrays.ctree_visitor_t):
        def __init__(self): super().__init__(ida_hexrays.CV_FAST)
        def visit_expr(self,e):
            nonlocal visited
            if visited>MAX_DEF_SEARCH: return 1
            if e.op==ida_hexrays.cot_asg:
                lhs,rhs=e.x,e.y
                if expr_uses_lvar(lhs,lvar_idx):
                    results.update(collect_func_objs(rhs))
            visited+=1
            return 0
    _F().apply_to(cfunc.body,None)
    return list(results)

# --------------------------------------------------------------------------
# ---------------------------- 调用收集核心 --------------------------------

def collect_calls(func_ea: int) -> List[Tuple[str,str,int]]:
    """
    返回 [(callee_name, category, line_no), ...]
    line_no: 1‑based, -1 表示无法定位
    """
    # key = 调用点EA
    callsite_map: Dict[int, Tuple[str,str,int]] = {}

    # ---------- Hex‑Rays ----------
    if ida_hexrays.init_hexrays_plugin():
        cfunc = ida_hexrays.decompile(func_ea)
        if cfunc:
            def line_of(item)->int:
                loc = cfunc.find_item_coords(item)  # (x,y) or None
                return loc[1]+1 if loc else -1

            class _CallVis(ida_hexrays.ctree_visitor_t):
                def __init__(self): super().__init__(ida_hexrays.CV_FAST)
                def visit_expr(self,e):
                    if e.op!=ida_hexrays.cot_call: return 0
                    call_ea=e.ea
                    if call_ea in callsite_map: return 0  # 已记录
                    line=line_of(e)
                    callee_ea=try_resolve_callee(e.x)
                    targets=[]
                    if callee_ea:
                        targets=[callee_ea]
                    else:
                        objs=collect_func_objs(e.x)
                        targets=list(objs) if len(objs)==1 else resolve_callee_via_defs(cfunc,e.x)
                    if not targets: targets=[idaapi.BADADDR]

                    tgt=targets[0]   # 这里只取首个解析结果，避免同一调用点出现多目标的稀有场景
                    cat=ea_category(tgt)
                    raw_name=idc.get_func_name(tgt) or idc.get_name(tgt) or f"{tgt:#x}"
                    name=normalize_api_name(raw_name)
                    callsite_map[call_ea]=(name,cat,line)
                    return 0
            _CallVis().apply_to(cfunc.body,None)

    # ---------- 汇编补漏 ----------
    for insn in idautils.FuncItems(func_ea):
        if idaapi.is_call_insn(insn):
            if insn in callsite_map: continue
            xref = next((xr for xr in idautils.XrefsFrom(insn, ida_xref.XREF_FAR) if xr.iscode), None)
            if not xref: continue
            tgt=xref.to
            cat=ea_category(tgt)
            raw_name=idc.get_func_name(tgt) or idc.get_name(tgt) or f"{tgt:#x}"
            name=normalize_api_name(raw_name)
            callsite_map[insn]=(name,cat,-1)
        else:
            # 尾调用
            first = next(idautils.XrefsFrom(insn, ida_xref.XREF_FAR), None)
            if first and insn not in callsite_map:
                tgt=first.to
                if ida_funcs.get_func(tgt) and ida_funcs.get_func(tgt).start_ea==tgt:
                    cat=ea_category(tgt)
                    raw_name=idc.get_func_name(tgt) or f"{tgt:#x}"
                    name=normalize_api_name(raw_name)
                    callsite_map[insn]=(name,cat,-1)

    # ---------- thunk ----------
    f=ida_funcs.get_func(func_ea)
    if f and (f.flags & ida_funcs.FUNC_THUNK):
        tgt=ida_funcs.calc_thunk_func_target(f)
        if isinstance(tgt,int):
            if f.start_ea not in callsite_map:
                cat=ea_category(tgt)
                raw_name=idc.get_func_name(tgt) or f"{tgt:#x}"
                name=normalize_api_name(raw_name)
                callsite_map[f.start_ea]=(name,cat,-1)

    # ---------- 输出排序 ----------
    return sorted(callsite_map.values(), key=lambda t:(t[2], t[0]))

# --------------------------------------------------------------------------
# ---------------------------- 主入口 --------------------------------------

def main():
    ida_auto.auto_wait()
    funcs=parse_args()
    idc.msg(f"[+] funcs_list = {funcs}\n[+] output     = {OUT_FILE}\n")
    if ida_hexrays.init_hexrays_plugin():
        idc.msg(f"Hex‑Rays {ida_hexrays.get_hexrays_version()} loaded\n")

    callmap: Dict[str,List[List]]={}
    for name in funcs:
        ea=idc.get_name_ea_simple(name)
        f=ida_funcs.get_func(ea) if ea!=idaapi.BADADDR else None
        if not f:
            idc.msg(f"[!] Function '{name}' not found, skip\n"); continue
        lst=collect_calls(f.start_ea)
        callmap[name]=[list(t) for t in lst]
        idc.msg(f"    ├─ {name}: {len(lst)} call‑sites\n")

    with open(OUT_FILE,"w",encoding="utf-8") as fp:
        json.dump(callmap,fp,ensure_ascii=False,indent=2)
    idc.msg(f"[+] Call‑map written to {os.path.abspath(OUT_FILE)}\n")
    idaapi.qexit(0)

# --------------------------------------------------------------------------
main()
