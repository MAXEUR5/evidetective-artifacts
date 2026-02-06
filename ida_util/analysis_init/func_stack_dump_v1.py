import idc # type: ignore
import idaapi # type: ignore
import ida_funcs # type: ignore
import ida_lines # type: ignore
import ida_hexrays # type: ignore
import ida_typeinf # type: ignore
import ida_frame # type: ignore
import idautils # type: ignore
import ida_auto # type: ignore
import json # type: ignore

#PS D:\IDA91\IDA_PRO> ./ida.exe -A -L"output.log" -S"E:\ida_util\analysis_init\func_stack_dump.py checkPass" E:\vuln_test\test1_junk\main_junk.exe
# ---------- 行号映射 ----------
def build_ea2line_map_via_eamap(cfunc):
    """
    尝试通过 cfunc.get_eamap() 获取 ea->伪代码行号的映射。
    """
    ea2line = {}
    if not cfunc:
        return ea2line
    _ = cfunc.get_pseudocode()  # 触发 pseudocode 构建
    em = cfunc.get_eamap()
    if not em:
        return ea2line
    for ea, items in em.items():
        best_line = None
        for it in items:
            try:
                c, r = cfunc.find_item_coords(it)
                if r >= 0 and (best_line is None or r < best_line):
                    best_line = r
            except:
                pass
        if best_line is not None:
            # 行号从 1 开始计更直观
            ea2line[ea] = best_line + 1
    return ea2line

def build_ea2line_map_via_ctree(cfunc):
    """
    通过遍历 ctree 的方式构建 ea->行号的映射。
    每遇到一个语句，就将其 .ea 与行号关联。
    """
    ea2line = {}
    ln = 1
    if not cfunc:
        return ea2line

    class MyCtreeVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_stmt(self, s):
            nonlocal ln
            if s.ea != idc.BADADDR and s.ea not in ea2line:
                ea2line[s.ea] = ln
            ln += 1
            return 0

    visitor = MyCtreeVisitor()
    visitor.apply_to(cfunc.body, None)
    return ea2line

def choose_ea2line_map_builder(cfunc):
    """
    优先尝试 eamap 的行号生成方式。
    若结果为空，则回退到 ctree 遍历方式。
    """
    try:
        m = build_ea2line_map_via_eamap(cfunc)
        if m:
            return m
    except:
        pass
    return build_ea2line_map_via_ctree(cfunc)

# -----------------------------------------------------
# 识别每个局部变量在伪代码中使用的行号
# -----------------------------------------------------
def find_var_usage_lines(cfunc):
    """
    为每个局部变量记录其在伪代码中出现的行号集合。
    返回一个 { lvar_idx: set([行号, ...]) } 的映射。
    """
    usage_map = {}
    ea2line = choose_ea2line_map_builder(cfunc)
    lvars = cfunc.get_lvars()
    for idx in range(len(lvars)):
        usage_map[idx] = set()

    class VarRefVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            """
            当访问到某个表达式时，如果它是局部变量 (cot_var)，
            则将对应的行号记录到 usage_map。
            """
            if e.op == ida_hexrays.cot_var:
                var_idx = e.v.idx
                if e.ea in ea2line:
                    usage_map[var_idx].add(ea2line[e.ea])
            return 0

    visitor = VarRefVisitor()
    visitor.apply_to(cfunc.body, None)
    return usage_map


def main():
    """
    1) 在命令行用 -S"func_dump_sp.py <function_name>" 运行，<function_name> 是要分析的函数
    2) 分析并读取该函数的反编译结果与栈帧 (UDT) 成员
    3) 通过对比 lvar 的 offset 与 UDT 成员 offset 判断匹配关系
    4) 额外：为每个局部变量收集其在反编译伪代码中出现的行号，并将结果以 JSON 格式输出
    """
    ida_auto.auto_wait()
    # 初始化 Hex-Rays
    if not ida_hexrays.init_hexrays_plugin():
        idc.msg("Hex-Rays decompiler plugin not available!\n")
        idaapi.qexit(1)
    idc.msg(f"Hex-rays version {ida_hexrays.get_hexrays_version()} has been detected\n")

    # 获取命令行参数
    if len(idc.ARGV) < 2:
        idc.msg("Usage: func_dump_sp.py <function_name>\n")
        idaapi.qexit(1)
    func_name = idc.ARGV[1]
    idc.msg(f"Analyzing function: {func_name}\n")

    # 获取函数地址
    func_ea = idc.get_name_ea_simple(func_name)
    if func_ea == idc.BADADDR:
        idc.msg(f"Function '{func_name}' not found!\n")
        idaapi.qexit(1)
    f = ida_funcs.get_func(func_ea)
    if not f:
        idc.msg(f"Failed to get function object for '{func_name}'!\n")
        idaapi.qexit(1)

    # 反编译
    cfunc = ida_hexrays.decompile(f)
    if not cfunc:
        idc.msg(f"Decompilation of '{func_name}' failed!\n")
        idaapi.qexit(1)

    # （可选）若需要读取并应用用户自定义的局部变量设置，可在此添加相关逻辑
    # 例如：
    # lvinf = ida_hexrays.lvar_uservec_t()
    # success = ida_hexrays.restore_user_lvar_settings(lvinf, f.start_ea)
    # if success:
    #     ida_hexrays.apply_user_lvar_settings(cfunc, lvinf)
    # cfunc.build_c_tree()

    # 获取栈帧并查找 __return_address
    tinfo = ida_typeinf.tinfo_t()
    if not ida_frame.get_func_frame(tinfo, f):
        idc.msg(f"No function frame recognized for '{func_name}'!\n")
        idaapi.qexit(1)

    udt = ida_typeinf.udt_type_data_t()
    if not tinfo.get_udt_details(udt):
        idc.msg(f"Unable to get UDT details for the frame of '{func_name}'!\n")
        idaapi.qexit(1)

    ret_addr_offset = None
    for m in udt:
        if m.name == "__return_address":
            ret_addr_offset = m.offset // 8
            break

    # 如果找不到，就做简单猜测
    if ret_addr_offset is None:
        inf = idaapi.get_inf_structure()
        ret_addr_offset = 8 if inf.is_64bit() else 4
        idc.msg("Warning: __return_address not found; using default offset = %d\n" % ret_addr_offset)
    idc.msg(f"__return_address offset = {ret_addr_offset} (from the stack frame base)\n")

    # 将 UDT 成员放入字典 (offset -> {name, type_str, size})
    udt_map = {}
    for m in udt:
        mem_off_in_frame = m.offset // 8
        mem_tinfo = m.type
        mem_size = mem_tinfo.get_size()
        mem_type_str = mem_tinfo.dstr()
        udt_map[mem_off_in_frame] = {
            "name": m.name,
            "type_str": mem_type_str,
            "size": mem_size,
        }

    # 先收集每个局部变量在伪代码中的行号使用情况
    var_usage_map = find_var_usage_lines(cfunc)

    # 遍历反编译出来的 lvars，匹配 UDT 并计算与 __return_address 的距离
    results = []
    lvars = cfunc.get_lvars()
    for idx, lvar in enumerate(lvars):
        if not lvar.is_stk_var():
            continue

        lvar_off_in_frame = lvar.location.stkoff() + cfunc.get_stkoff_delta()
        lvar_tinfo = lvar.type()
        lvar_type_str = lvar_tinfo.dstr()
        lvar_size = lvar.width

        rec = {
            "lvar_idx": idx,
            "lvar_name": lvar.name,
            "lvar_offset": lvar_off_in_frame,
            "lvar_type": lvar_type_str,
            "lvar_size": lvar_size,
            "usage_lines": sorted(list(var_usage_map[idx])),  # 行号使用情况
            "udt_name": None,
            "udt_type": None,
            "udt_size": None,
            "dist_from_ret_addr": None,
        }

        udt_member = udt_map.get(lvar_off_in_frame, None)
        if udt_member:
            rec["udt_name"] = udt_member["name"]
            rec["udt_type"] = udt_member["type_str"]
            rec["udt_size"] = udt_member["size"]
            # 相对于返回地址的距离
            dist = lvar_off_in_frame - ret_addr_offset
            rec["dist_from_ret_addr"] = dist

        results.append(rec)

    # 以 JSON 格式写入输出文件
    json_filename = f"func_{func_name}_varmatch.json"
    output_data = {
        "function_name": func_name,
        "__return_address_offset": ret_addr_offset,
        "variables": results
    }
    with open(json_filename, "w", encoding="utf-8", errors="replace") as outf:
        json.dump(output_data, outf, indent=2, ensure_ascii=False)

    idc.msg(f"JSON result saved to: {json_filename}\n")
    idaapi.qexit(0)


if __name__ == "__main__":
    main()