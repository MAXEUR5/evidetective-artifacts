# stack_var_legacy.py
# -*- coding: utf-8 -*-
import idaapi
import idc
import ida_funcs
import ida_hexrays
import ida_lines
import json

"""
在 IDA 9.0 下使用旧式的 cinsn_t + cexpr_t 遍历，
识别栈变量读写/取地址(指针写)，并输出行级信息到 JSON.

使用:
  idat64.exe -A -S"E:/ida_util/stack_var_legacy.py" "E:/binary.exe" MyTargetFunc
"""


OUTPUT_JSON = "stackvar_analysis.json"


# -----------------------------------------------------------------------
# 1) 从命令行参数获取函数名
# -----------------------------------------------------------------------
def get_target_func_name():
    # 假设 ARGV[1] 是目标函数名
    if len(idc.ARGV) < 2:
        return None
    return idc.ARGV[1].strip()


# -----------------------------------------------------------------------
# 2) 初始化Hex-Rays
# -----------------------------------------------------------------------
def ensure_hexrays():
    if not ida_hexrays.init_hexrays_plugin():
        idc.msg("Hex-Rays decompiler plugin not available!\n")
        idaapi.qexit(1)
    ver = ida_hexrays.get_hexrays_version()
    idc.msg(f"Hex-Rays version {ver} loaded.\n")


# -----------------------------------------------------------------------
# 3) 判断lvar是否是栈变量
#    IDA9.0 下用 is_stk_var() + stkoff()，不再使用 froff
# -----------------------------------------------------------------------
def is_stack_lvar(lvar):
    return lvar.is_stk_var()

def get_stack_offset(lvar):
    return lvar.stkoff()  # 通常正数，代表在栈帧中的距离


# -----------------------------------------------------------------------
# 4) 维护对每个栈变量的读/写/ptr写索引
# -----------------------------------------------------------------------
#   var_usage = { lvar_idx: {
#       'reads': set_of_citem_index,
#       'writes': set_of_citem_index,
#       'ptr_writes': set_of_citem_index
#   }}
#
#   pointer_map = { citem_idx_of_ref_expr : lvar_idx }
#       # 当遇到 &var
# -----------------------------------------------------------------------
def analyze_cfunc_vars(cfunc):
    var_usage = {}
    for i, lv in enumerate(cfunc.lvars):
        if is_stack_lvar(lv):
            var_usage[i] = {
                'reads': set(),
                'writes': set(),
                'ptr_writes': set()
            }
    pointer_map = {}

    # 分别写2个函数: traverse_cinsn(语句) & traverse_cexpr(表达式)

    def mark_var_use(lvar_idx, citem_idx, is_write=False):
        if lvar_idx not in var_usage:
            return
        if is_write:
            var_usage[lvar_idx]['writes'].add(citem_idx)
        else:
            var_usage[lvar_idx]['reads'].add(citem_idx)

    def traverse_cexpr(e, parent_op=None, child_role=None):
        """ 递归处理表达式节点 cexpr_t """
        if not e:
            return
        op = e.op
        idx = e.index  # citem index

        # 1) 如果是局部变量
        if op == ida_hexrays.cot_var:
            lvar_idx = e.l.getv()
            # 写: 当 parent是cot_asg且自己在左值
            if parent_op == ida_hexrays.cot_asg and child_role == "left":
                mark_var_use(lvar_idx, idx, is_write=True)
            else:
                mark_var_use(lvar_idx, idx, is_write=False)

        # 2) 如果是取地址 &var
        if op == ida_hexrays.cot_ref:
            sub = e.x
            if sub and sub.op == ida_hexrays.cot_var:
                lvar_idx = sub.l.getv()
                if lvar_idx in var_usage:
                    pointer_map[idx] = lvar_idx

        # 3) 根据表达式类型，递归子表达式
        #    不可用 cexpr_dependencies()，需要手动区分
        if op == ida_hexrays.cot_asg:
            # e.x => 左值, e.y => 右值
            traverse_cexpr(e.x, parent_op=op, child_role="left")
            traverse_cexpr(e.y, parent_op=op, child_role="right")
        elif op == ida_hexrays.cot_call:
            # e.x => 函数名or指针; e.a[] => 参数数组
            traverse_cexpr(e.x, parent_op=op, child_role="func_ptr")
            for a in e.a:
                traverse_cexpr(a, parent_op=op, child_role="call_arg")
        elif op in (
            ida_hexrays.cot_mul, ida_hexrays.cot_divu, ida_hexrays.cot_add,
            ida_hexrays.cot_sub, ida_hexrays.cot_lor, ida_hexrays.cot_land,
            ida_hexrays.cot_eq, ida_hexrays.cot_ne, ida_hexrays.cot_lt, ida_hexrays.cot_gt,
            ida_hexrays.cot_uge, ida_hexrays.cot_le, ida_hexrays.cot_ge, ida_hexrays.cot_ult,
            ida_hexrays.cot_mod, ida_hexrays.cot_xor, ida_hexrays.cot_and, ida_hexrays.cot_or,
            ida_hexrays.cot_lsl, ida_hexrays.cot_lsr, ida_hexrays.cot_asr,
            ida_hexrays.cot_udiv, ida_hexrays.cot_umod, ida_hexrays.cot_fadd, ida_hexrays.cot_fsub,
            ida_hexrays.cot_fmul, ida_hexrays.cot_fdiv, ida_hexrays.cot_fneg,
            ida_hexrays.cot_conv, ida_hexrays.cot_nots, ida_hexrays.cot_neg, ida_hexrays.cot_lnot,
            ida_hexrays.cot_preinc, ida_hexrays.cot_predec, ida_hexrays.cot_postinc, ida_hexrays.cot_postdec,
            ida_hexrays.cot_ptr, ida_hexrays.cot_ref,
            ida_hexrays.cot_memptr, ida_hexrays.cot_memref,
        ):
            # 大多数二元或一元运算 => 递归 x,y
            if e.x:
                traverse_cexpr(e.x, parent_op=op, child_role="x")
            if e.y:
                traverse_cexpr(e.y, parent_op=op, child_role="y")
        elif op == ida_hexrays.cot_tern:
            # 三元运算 cond ? x : y
            if e.x:
                traverse_cexpr(e.x, parent_op=op, child_role="cond")
            if e.y:
                traverse_cexpr(e.y, parent_op=op, child_role="true_expr")
            if e.z:
                traverse_cexpr(e.z, parent_op=op, child_role="false_expr")
        # 其它 op 视情况而定, 可能还有 cot_num, cot_str, etc.

    def traverse_cinsn(insn):
        """ 递归处理语句节点 cinsn_t """
        if not insn:
            return
        itype = insn.op
        # CIT_BLOCK => cblock_t
        if itype == ida_hexrays.cit_block:
            blk = insn.cblock
            for i2 in range(len(blk)):
                traverse_cinsn(blk.at(i2))
        elif itype == ida_hexrays.cit_expr:
            # 表达式语句
            expr_stmt = insn.cexpr
            traverse_cexpr(expr_stmt)
        elif itype == ida_hexrays.cit_if:
            # if ( cexpr ) { cinsn } else { cinsn }
            cif = insn.cif
            traverse_cexpr(cif.expr)        # 条件
            traverse_cinsn(cif.ithen)       # then体
            if cif.ielse:
                traverse_cinsn(cif.ielse)   # else体
        elif itype == ida_hexrays.cit_return:
            # return cexpr
            cret = insn.creturn
            if cret and cret.expr:
                traverse_cexpr(cret.expr)
        elif itype == ida_hexrays.cit_for:
            cfor = insn.cfor
            traverse_cinsn(cfor.init)  # init语句
            traverse_cexpr(cfor.expr)  # for条件
            traverse_cinsn(cfor.step)  # step语句
            traverse_cinsn(cfor.body)  # 循环体
        elif itype == ida_hexrays.cit_while:
            cwhl = insn.cwhile
            traverse_cexpr(cwhl.expr)
            traverse_cinsn(cwhl.body)
        elif itype == ida_hexrays.cit_do:
            cdo = insn.cdo
            traverse_cinsn(cdo.body)
            traverse_cexpr(cdo.expr)
        elif itype == ida_hexrays.cit_switch:
            csw = insn.cswitch
            traverse_cexpr(csw.expr)
            traverse_cinsn(csw.body)
        else:
            # 其它诸如 cit_break, cit_continue, cit_goto, cit_label, cit_asm
            # 都没有子表达式需要递归
            pass

    # 从 cfunc.body (cinsn_t) 开始
    traverse_cinsn(cfunc.body)

    return var_usage, pointer_map


# -----------------------------------------------------------------------
# 5) 第二遍：分析指针用法（ptr_writes）
# -----------------------------------------------------------------------
def analyze_pointer_usage(cfunc, var_usage, pointer_map):
    """
    若 &var 出现的表达式(取地址)被用在 '*(ptr)=...' (左值) 或 函数参数
    则视为对 var 的写
    同样需要语句/表达式分开遍历
    """

    def mark_ptr_write(idx):
        lvar_idx = pointer_map.get(idx, None)
        if lvar_idx is not None:
            var_usage[lvar_idx]['ptr_writes'].add(idx)

    def traverse_cexpr(e, parent_op=None, child_role=None):
        if not e:
            return
        idx = e.index
        op = e.op

        # 若此 cexpr 本身是个指针(&var)
        if idx in pointer_map:
            # 如果父节点是赋值且自己在左值 => 写
            if parent_op == ida_hexrays.cot_asg and child_role == "left":
                mark_ptr_write(idx)
            # 如果父节点是函数调用参数 => 可能写
            elif parent_op == ida_hexrays.cot_call and child_role == "call_arg":
                mark_ptr_write(idx)

        # 再递归处理子表达式
        if op == ida_hexrays.cot_asg:
            traverse_cexpr(e.x, parent_op=op, child_role="left")
            traverse_cexpr(e.y, parent_op=op, child_role="right")
        elif op == ida_hexrays.cot_call:
            traverse_cexpr(e.x, parent_op=op, child_role="func_ptr")
            for a in e.a:
                traverse_cexpr(a, parent_op=op, child_role="call_arg")
        elif op == ida_hexrays.cot_tern:
            if e.x: traverse_cexpr(e.x, parent_op=op, child_role="cond")
            if e.y: traverse_cexpr(e.y, parent_op=op, child_role="true_expr")
            if e.z: traverse_cexpr(e.z, parent_op=op, child_role="false_expr")
        else:
            # 二元/一元运算
            if e.x:
                traverse_cexpr(e.x, parent_op=op, child_role="x")
            if e.y:
                traverse_cexpr(e.y, parent_op=op, child_role="y")

    def traverse_cinsn(insn):
        if not insn:
            return
        itype = insn.op
        if itype == ida_hexrays.cit_block:
            blk = insn.cblock
            for i2 in range(len(blk)):
                traverse_cinsn(blk.at(i2))
        elif itype == ida_hexrays.cit_expr:
            traverse_cexpr(insn.cexpr)
        elif itype == ida_hexrays.cit_if:
            cif = insn.cif
            traverse_cexpr(cif.expr)
            traverse_cinsn(cif.ithen)
            if cif.ielse:
                traverse_cinsn(cif.ielse)
        elif itype == ida_hexrays.cit_return:
            cret = insn.creturn
            if cret and cret.expr:
                traverse_cexpr(cret.expr)
        elif itype == ida_hexrays.cit_for:
            cfor = insn.cfor
            traverse_cinsn(cfor.init)
            traverse_cexpr(cfor.expr)
            traverse_cinsn(cfor.step)
            traverse_cinsn(cfor.body)
        elif itype == ida_hexrays.cit_while:
            cwhl = insn.cwhile
            traverse_cexpr(cwhl.expr)
            traverse_cinsn(cwhl.body)
        elif itype == ida_hexrays.cit_do:
            cdo = insn.cdo
            traverse_cinsn(cdo.body)
            traverse_cexpr(cdo.expr)
        elif itype == ida_hexrays.cit_switch:
            csw = insn.cswitch
            traverse_cexpr(csw.expr)
            traverse_cinsn(csw.body)
        else:
            # break, goto, label, etc...
            pass

    traverse_cinsn(cfunc.body)


# -----------------------------------------------------------------------
# 6) 将 citem 索引 -> 反编译行
# -----------------------------------------------------------------------
def map_citem_to_lines(cfunc, var_usage):
    pseudocode_lines = cfunc.get_pseudocode()
    line_citem_map = []
    for line_obj in pseudocode_lines:
        raw_line = line_obj.line
        tokens = ida_lines.parse_json_colored_line(raw_line)
        cset = set()
        for tk in tokens:
            if "links" in tk and "citem" in tk["links"]:
                cset.add(tk["links"]["citem"])
        line_citem_map.append(cset)

    for lvidx, usage_dict in var_usage.items():
        rset = usage_dict['reads']
        wset = usage_dict['writes']
        pset = usage_dict['ptr_writes']
        usage_dict['reads']      = []
        usage_dict['writes']     = []
        usage_dict['ptr_writes'] = []
        for idx, cset in enumerate(line_citem_map):
            intersect_r = rset & cset
            intersect_w = wset & cset
            intersect_p = pset & cset
            if intersect_r or intersect_w or intersect_p:
                pure_line = idaapi.tag_remove(pseudocode_lines[idx].line)
                if intersect_r:
                    usage_dict['reads'].append({
                        'line_index': idx,
                        'line_text':  pure_line
                    })
                if intersect_w:
                    usage_dict['writes'].append({
                        'line_index': idx,
                        'line_text':  pure_line
                    })
                if intersect_p:
                    usage_dict['ptr_writes'].append({
                        'line_index': idx,
                        'line_text':  pure_line
                    })


# -----------------------------------------------------------------------
# 7) 分析指定函数
# -----------------------------------------------------------------------
def analyze_function(func_ea):
    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        idc.msg(f"[-] Decompile failed for 0x{func_ea:X}\n")
        return None

    name = idaapi.get_func_name(func_ea) or ""
    idc.msg(f"Analyzing: {name}(EA=0x{func_ea:X})\n")

    # 收集栈上变量
    stack_lvar_indices = []
    for i, lv in enumerate(cfunc.lvars):
        if is_stack_lvar(lv):
            stack_lvar_indices.append(i)

    if not stack_lvar_indices:
        return {
            'function_ea':  func_ea,
            'function_name': name,
            'stack_vars':    []
        }

    # 第1遍：遍历语句/表达式, 收集 read/write & pointer_map
    var_usage, pointer_map = analyze_cfunc_vars(cfunc)

    # 第2遍：再次遍历, 检查指针 usage => ptr_writes
    analyze_pointer_usage(cfunc, var_usage, pointer_map)

    # 第3步：映射到行
    map_citem_to_lines(cfunc, var_usage)

    # 整理输出
    out_vars = []
    for i in stack_lvar_indices:
        lv = cfunc.lvars[i]
        offset = get_stack_offset(lv)
        usage = var_usage[i]
        out_vars.append({
            'name': lv.name,
            'offset': offset,
            'reads': usage['reads'],
            'writes': usage['writes'],
            'ptr_writes': usage['ptr_writes']
        })

    return {
        'function_ea':  func_ea,
        'function_name': name,
        'stack_vars':    out_vars
    }

# -----------------------------------------------------------------------
# 8) main: 参数->函数->分析->JSON->退出
# -----------------------------------------------------------------------
def main():
    ensure_hexrays()
    func_name = get_target_func_name()
    if not func_name:
        idc.msg("Usage: script.py <function_name>\n")
        idaapi.qexit(1)
        return

    func_ea = idc.get_name_ea_simple(func_name)
    if func_ea == idc.BADADDR:
        idc.msg(f"Cannot find function: {func_name}\n")
        idaapi.qexit(1)
        return

    f = ida_funcs.get_func(func_ea)
    if not f:
        idc.msg(f"Invalid function object for: {func_name}\n")
        idaapi.qexit(1)
        return

    result = analyze_function(func_ea)
    if not result:
        idc.msg("[!] analyze_function returned None\n")
        idaapi.qexit(1)
        return

    with open(OUTPUT_JSON, "w", encoding="utf-8") as jf:
        json.dump(result, jf, indent=2, ensure_ascii=False)

    idc.msg(f"[+] Done. Output => {OUTPUT_JSON}\n")
    idaapi.qexit(0)


if __name__ == "__main__":
    main()
