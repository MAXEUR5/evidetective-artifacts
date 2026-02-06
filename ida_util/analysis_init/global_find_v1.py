# global_var_analysis.py
# -*- coding: utf-8 -*-

import idaapi
import idc
import idautils
import ida_bytes
import ida_funcs
import ida_ua
import ida_hexrays
import ida_lines
import json

def build_ea2line_map_via_eamap(cfunc):
    ea2line = {}
    if not cfunc:
        return ea2line
    _ = cfunc.get_pseudocode()
    em = cfunc.get_eamap()
    if not em:
        return ea2line
    for ea, items in em.items():
        best_row = None
        for it in items:
            try:
                col, row = cfunc.find_item_coords(it)
                if row >= 0 and (best_row is None or row < best_row):
                    best_row = row
            except Exception:
                pass
        if best_row is not None:
            ea2line[ea] = best_row + 1
    return ea2line

def build_ea2line_map_via_ctree(cfunc):
    ea2line = {}
    ln = 1
    if not cfunc:
        return ea2line

    class MyVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_stmt(self, s):
            nonlocal ln
            if s.ea != idc.BADADDR and s.ea not in ea2line:
                ea2line[s.ea] = ln
            ln += 1
            return 0

    mv = MyVisitor()
    mv.apply_to(cfunc.body, None)
    return ea2line

def choose_ea2line_map_builder(cfunc):
    try:
        mapping = build_ea2line_map_via_eamap(cfunc)
        if mapping:
            return mapping
    except:
        pass
    return build_ea2line_map_via_ctree(cfunc)

def is_data_candidate(ea):
    flags = ida_bytes.get_full_flags(ea)
    if not ida_bytes.is_data(flags):
        return False
    seg = idaapi.getseg(ea)
    if not seg:
        return False
    # 仅演示：排除可执行段
    if seg.perm & idaapi.SEGPERM_EXEC:
        return False
    for xref in idautils.XrefsTo(ea, flags=0):
        if ida_funcs.get_func(xref.frm):
            return True
    return False

def get_segment_rwx(seg):
    perms = []
    if seg.perm & idaapi.SEGPERM_READ:
        perms.append('R')
    if seg.perm & idaapi.SEGPERM_WRITE:
        perms.append('W')
    if seg.perm & idaapi.SEGPERM_EXEC:
        perms.append('X')
    return "".join(perms)

def collect_global_variables():
    gvars = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg:
            continue
        for head_ea in idautils.Heads(seg.start_ea, seg.end_ea):
            if is_data_candidate(head_ea):
                gvars.append(head_ea)
    return gvars

def main():
    # 判断是否可用 Hex-Rays
    has_decompiler = ida_hexrays.init_hexrays_plugin()

    gvars = collect_global_variables()
    result_dict = {}

    for var_ea in gvars:
        var_name = idc.get_name(var_ea) or "unnamed_global"
        seg = idaapi.getseg(var_ea)
        if not seg:
            continue
        var_rwx = get_segment_rwx(seg)

        references = []
        for xref in idautils.XrefsTo(var_ea, flags=0):
            ref_ea = xref.frm
            func = ida_funcs.get_func(ref_ea)
            if not func:
                continue
            func_ea = func.start_ea
            func_name = idc.get_func_name(func_ea)

            line_num = None
            if has_decompiler:
                cfunc = ida_hexrays.decompile(func_ea)
                if cfunc:
                    ea2line = choose_ea2line_map_builder(cfunc)
                    line_num = ea2line.get(ref_ea, None)

            references.append({
                "function_name": func_name,
                "ref_ea": "0x{:X}".format(ref_ea),
                "decompiled_line": line_num
            })

        if references:
            var_key = "0x{:X}".format(var_ea)
            result_dict[var_key] = {
                "name": var_name,
                "segment_rwx": var_rwx,
                "references": references
            }
    OUT_FILE="global_var.json"
    #json_output = json.dumps(result_dict, ensure_ascii=False, indent=4)
    with open(OUT_FILE, "w", encoding="utf-8") as fp:
        json.dump(result_dict, fp, ensure_ascii=False, indent=2)

# -------------------------------
# 关键：静默模式、自动退出处理
# -------------------------------
if __name__ == '__main__':
    # 1) 等待自动分析完成
    idc.auto_wait()

    # 2) 执行主流程
    main()

    # 3) 执行完毕后自动退出(返回码=0)
    idc.qexit(0)
    # 或者 idaapi.qexit(0)
