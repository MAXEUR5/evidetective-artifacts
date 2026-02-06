# global_find_v3_ctree_only.py
# -*- coding: utf-8 -*-

import idaapi
import idc
import idautils
import ida_bytes
import ida_funcs
import ida_hexrays
import json

BADADDR = idaapi.BADADDR


def get_segment_rwx(seg):
    perms = []
    if seg.perm & idaapi.SEGPERM_READ:
        perms.append('R')
    if seg.perm & idaapi.SEGPERM_WRITE:
        perms.append('W')
    if seg.perm & idaapi.SEGPERM_EXEC:
        perms.append('X')
    return "".join(perms)

def is_data_candidate(ea):
    """仅演示：识别出可做全局变量候选的地址"""
    flags = ida_bytes.get_full_flags(ea)
    if not ida_bytes.is_data(flags):
        return False
    seg = idaapi.getseg(ea)
    if not seg:
        return False
    # 仅演示：排除可执行段
    if seg.perm & idaapi.SEGPERM_EXEC:
        return False
    return True

def collect_global_variables():
    """收集全部可能的全局变量地址(粗略)。"""
    gvars = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg:
            continue
        for head_ea in idautils.Heads(seg.start_ea, seg.end_ea):
            if is_data_candidate(head_ea):
                gvars.append(head_ea)
    return gvars


def visit_cfunc_for_var(cfunc, var_ea):
    """
    在给定 cfunc 的 ctree 中查找对 var_ea 的所有引用。
    返回形如 [ (ref_ea1, line_num1), (ref_ea2, line_num2), ... ]
    """

    references = []
    if not cfunc:
        return references

    # 准备伪代码文本行信息
    _ = cfunc.get_pseudocode()

    class VarRefVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            # e.op == cot_obj => 该表达式引用了某个全局/局部对象
            # e.obj_ea 就是它指向的地址
            if e.op == ida_hexrays.cot_obj and e.obj_ea == var_ea:
                # 记录下它的 e.ea（一般是指令地址）以及伪代码行号
                # 注意：有些情况下 e.ea 也可能是 BADADDR，这时只能拿行号
                line_num = None
                ea_int = e.ea
                try:
                    col, row = cfunc.find_item_coords(e)
                    if row >= 0:
                        line_num = row + 1
                except:
                    pass

                references.append((ea_int, line_num))
            return 0

    mv = VarRefVisitor()
    mv.apply_to(cfunc.body, None)
    return references


def main():
    # 初始化反编译器
    if not ida_hexrays.init_hexrays_plugin():
        print("No decompiler available!")
        return

    # 收集所有候选的全局变量地址
    gvars = collect_global_variables()

    # 收集程序中所有函数地址
    all_func_starts = [f for f in idautils.Functions()]

    result_dict = {}

    for var_ea in gvars:
        var_name = idc.get_name(var_ea) or "unnamed_global"
        seg = idaapi.getseg(var_ea)
        if not seg:
            continue
        var_rwx = get_segment_rwx(seg)

        # references 用于收集 (函数名, ref_ea, decompiled_line)
        references = []

        # 遍历每个函数，对其反编译，并遍历 ctree
        for f_ea in all_func_starts:
            cfunc = ida_hexrays.decompile(f_ea)
            if not cfunc:
                continue

            # 在该函数里找对 var_ea 的所有引用
            refs_in_func = visit_cfunc_for_var(cfunc, var_ea)
            if not refs_in_func:
                continue

            # 该函数名
            func_name = idaapi.get_name(f_ea) or ""
            # 收集所有引用
            for (ref_ea, line_num) in refs_in_func:
                # 如果 ref_ea == BADADDR，表示表达式没有准确的指令地址
                ref_ea_str = "0x{:X}".format(ref_ea) if ref_ea != BADADDR else None
                references.append({
                    "function_name": func_name,
                    "function_ea": "0x{:X}".format(f_ea),
                    "ref_ea": ref_ea_str,
                    "decompiled_line": line_num
                })

        # 如果该全局变量确有引用，则记录到 result_dict
        if references:
            var_key = "0x{:X}".format(var_ea)
            result_dict[var_key] = {
                "name": var_name,
                "segment_rwx": var_rwx,
                "references": references
            }

    # 导出到 JSON
    out_file = "global_var_ctree_refs.json"
    with open(out_file, "w", encoding="utf-8") as fp:
        json.dump(result_dict, fp, ensure_ascii=False, indent=2)

    idc.msg("Analysis done. Results saved to: {}\n".format(out_file))


# ------------------------------------------------
# 静默模式启动：等待分析完毕后执行脚本并退出
# ------------------------------------------------
if __name__ == '__main__':
    idc.auto_wait()
    main()
    idaapi.qexit(0)
