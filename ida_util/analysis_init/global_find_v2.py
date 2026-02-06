# global_find_v2_fixed.py
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

###############################################
# 修正的辅助函数：保证返回值一定是 int 或 BADADDR
###############################################
def get_thunk_target_ea(f: ida_funcs.func_t) -> int:
    """
    若函数 f 是 Thunk，则尝试调用 ida_funcs.calc_thunk_func_target(f)
    返回真正指向的目标EA，否则返回 BADADDR。
    """
    if not f or not (f.flags & ida_funcs.FUNC_THUNK):
        return idaapi.BADADDR

    tgt = ida_funcs.calc_thunk_func_target(f)
    if tgt is None:
        return idaapi.BADADDR
    # 强制转换为 int 类型
    try:
        tgt = int(tgt)
    except (ValueError, TypeError):
        return idaapi.BADADDR

    return tgt

def is_plt_segment(seg: idaapi.segment_t) -> bool:
    """示例：简单判断段名是否含 '.plt'。可根据需要调整。"""
    if not seg:
        return False
    name = idaapi.get_segm_name(seg)
    return (name and '.plt' in name.lower())

###############################################
# normalize_api_name 与 ea_category 修正
###############################################
def normalize_api_name(ea: int, raw: str) -> str:
    """
    将函数名或符号名中开头的 "."、"_imp_"、"__imp_" 等前缀去除；
    若是 Thunk 函数则递归跟进目标地址取真正名称。
    """
    # 去掉常见前缀
    for p in (".", "_imp_", "__imp_"):
        if raw.startswith(p):
            raw = raw[len(p):]

    f = ida_funcs.get_func(ea)
    if f and (f.flags & ida_funcs.FUNC_THUNK):
        tgt = get_thunk_target_ea(f)
        if tgt != idaapi.BADADDR:
            # 若拿到合法地址，则获取其名称再递归
            raw2 = idaapi.get_name(tgt) or raw
            return normalize_api_name(tgt, raw2)

    return raw

def ea_category(ea: int) -> str:
    """
    判断给定 ea 对应的函数类别 (IMPORT_API / USER_DEF / OTHER)。
    包括：段是否是 XTRN (.idata)、是否位于 PLT 段、或 Thunk 指向外部等。
    """
    if ea == idaapi.BADADDR:
        return "OTHER"

    f = ida_funcs.get_func(ea)
    if not f:
        seg = idaapi.getseg(ea)
        if seg and seg.type == idaapi.SEG_XTRN:
            return "IMPORT_API"
        return "OTHER"

    # 已经是函数
    seg = idaapi.getseg(ea)
    if seg and seg.type == idaapi.SEG_XTRN:
        return "IMPORT_API"
    if is_plt_segment(seg):
        return "IMPORT_API"

    # 若函数是 Thunk，且指向外部 SEG_XTRN，也视为 IMPORT_API
    tgt = get_thunk_target_ea(f)
    if tgt != idaapi.BADADDR:
        seg2 = idaapi.getseg(tgt)
        if seg2 and seg2.type == idaapi.SEG_XTRN:
            return "IMPORT_API"

    if f.flags & ida_funcs.FUNC_LIB:
        return "IMPORT_API"

    return "USER_DEF"

###############################################
# 以下原先已有的代码
###############################################
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
            # 原始名称
            raw_name = idaapi.get_name(func_ea) or ""
            # 去前缀 + 处理Thunk
            norm_name = normalize_api_name(func_ea, raw_name)
            # 分类
            func_cat  = ea_category(func_ea)

            line_num = None
            if has_decompiler:
                cfunc = ida_hexrays.decompile(func_ea)
                if cfunc:
                    ea2line = choose_ea2line_map_builder(cfunc)
                    line_num = ea2line.get(ref_ea, None)

            references.append({
                "function_name": norm_name,
                "function_category": func_cat,
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

    OUT_FILE = "global_var.json"
    with open(OUT_FILE, "w", encoding="utf-8") as fp:
        json.dump(result_dict, fp, ensure_ascii=False, indent=2)
    idc.msg("Save to "+OUT_FILE+"\n")

# ------------------------------------------------
# 静默模式启动：等待分析完毕后执行脚本并退出
# ------------------------------------------------
if __name__ == '__main__':
    idc.auto_wait()
    main()
    idaapi.qexit(0)
