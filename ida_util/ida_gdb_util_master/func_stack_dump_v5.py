import idc  # type: ignore
import idaapi  # type: ignore
import ida_funcs  # type: ignore
import ida_lines  # type: ignore
import ida_hexrays  # type: ignore
import ida_typeinf  # type: ignore
import ida_frame  # type: ignore
import ida_auto  # type: ignore
import idautils  # type: ignore
import json  # type: ignore


# -------------------------------------------------------------------------------------
# 1) 判断当前二进制是否64位，不使用图形接口
# -------------------------------------------------------------------------------------
def is_64bit():
    """
    优先使用 ida_ida.idainfo_is_64bit()，
    若不存在则尝试 idaapi.cvar.inf.is_64bit()，
    若都失败则抛错。
    """
    try:
        from ida_ida import idainfo_is_64bit
        return idainfo_is_64bit()
    except ImportError:
        pass

    inf = idaapi.cvar.inf
    if inf is not None and hasattr(inf, "is_64bit"):
        return inf.is_64bit()

    raise RuntimeError("无法判断当前二进制是32位还是64位："
                       "idainfo_is_64bit() 和 cvar.inf.is_64bit() 均不可用。")


# -------------------------------------------------------------------------------------
# 2) EA -> 行号映射的构建方式（eamap 优先，失败则 ctree）
# -------------------------------------------------------------------------------------
def build_ea2line_map_via_eamap(cfunc):
    """
    利用 cfunc.get_eamap() 构建从 EA 到伪代码行号的映射
    """
    ea2line = {}
    if not cfunc:
        return ea2line

    # 先触发生成伪代码
    _ = cfunc.get_pseudocode()
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
            # +1 让行号更贴近伪代码显示
            ea2line[ea] = best_line + 1
    return ea2line


def build_ea2line_map_via_ctree(cfunc):
    """
    通过遍历 ctree 构建 EA -> 行号映射
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
    优先尝试 eamap，若为空或失败则回退到 ctree
    """
    try:
        m = build_ea2line_map_via_eamap(cfunc)
        if m:
            return m
    except:
        pass
    return build_ea2line_map_via_ctree(cfunc)


# -------------------------------------------------------------------------------------
# 3) 收集局部变量使用行号，包含对赋值表达式(cot_asg)和函数调用(cot_call)等的处理
# -------------------------------------------------------------------------------------
def find_var_usage_lines(cfunc):
    """
    返回 usage_map: dict( var_idx -> set( 行号 ) )
    其中行号基于 eamap 或 ctree 计算得来。
    """
    lvars = cfunc.get_lvars()
    usage_map = {i: set() for i in range(len(lvars))}
    ea2line = choose_ea2line_map_builder(cfunc)

    # 在表达式级获取“行号”时，如果 e.ea == BADADDR，就用 find_item_coords 兜底
    def add_usage(var_idx, e):
        ea = e.ea
        if ea != idc.BADADDR and ea in ea2line:
            usage_map[var_idx].add(ea2line[ea])
        else:
            # fallback: 直接用 find_item_coords 来获取行坐标
            try:
                c, r = cfunc.find_item_coords(e)
                if r >= 0:
                    usage_map[var_idx].add(r + 1)
            except:
                pass

    def collect_var_indexes(e, out_set):
        """递归：收集当前表达式 e 中出现的所有局部变量 var_idx"""
        if not e:
            return

        # 遇到变量节点
        if e.op == ida_hexrays.cot_var:
            out_set.add(e.v.idx)

        # 继续下探 x, y, z
        if e.x and isinstance(e.x, ida_hexrays.cexpr_t):
            collect_var_indexes(e.x, out_set)
        if e.y and isinstance(e.y, ida_hexrays.cexpr_t):
            collect_var_indexes(e.y, out_set)
        if e.z and isinstance(e.z, ida_hexrays.cexpr_t):
            collect_var_indexes(e.z, out_set)

        # 如果是函数调用，需要遍历参数列表 e.a
        if e.op == ida_hexrays.cot_call and e.a:
            for arg_expr in e.a:
                if arg_expr and isinstance(arg_expr, ida_hexrays.cexpr_t):
                    collect_var_indexes(arg_expr, out_set)

    class VarUsageVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            """
            - 若是一般变量引用 (cot_var)，单独记录其所在表达式的行号
            - 若是赋值表达式 (cot_asg)，把左右子表达式里的所有 var 均视作在同一行出现
            - 若是其他表达式 (含函数调用 cot_call)，也会在递归中搜集 var；下面可视需求做行号标记
            """
            if e.op == ida_hexrays.cot_var:
                # 记录单个变量引用
                add_usage(e.v.idx, e)

            elif e.op == ida_hexrays.cot_asg:
                # 对赋值左右两侧收集
                var_idxs = set()
                collect_var_indexes(e.x, var_idxs)
                collect_var_indexes(e.y, var_idxs)
                # 在这条“赋值表达式”本身的行号上，登记所有参与的变量
                for vid in var_idxs:
                    add_usage(vid, e)

            else:
                # 其他表达式可能包含函数调用、数组引用等
                # 默认逻辑：它的子表达式会在 deeper visit_expr 中处理“cot_var”引用
                # 如果想让函数调用的所有变量也登记到同一行，可以类似 cot_asg 的做法。
                pass

            return 0

    visitor = VarUsageVisitor()
    visitor.apply_to(cfunc.body, None)
    return usage_map


# -------------------------------------------------------------------------------------
# 4) 主体逻辑
# -------------------------------------------------------------------------------------
def main():
    ida_auto.auto_wait()

    if not ida_hexrays.init_hexrays_plugin():
        idc.msg("[!] Hex-Rays decompiler plugin not available.\n")
        idaapi.qexit(1)
    idc.msg(f"[+] Hex-Rays version: {ida_hexrays.get_hexrays_version()}\n")

    if len(idc.ARGV) < 2:
        idc.msg("[!] Usage: this_script.py <function_name>\n")
        idaapi.qexit(1)

    func_name = idc.ARGV[1]
    idc.msg(f"[+] Analyzing function: {func_name}\n")

    func_ea = idc.get_name_ea_simple(func_name)
    if func_ea == idc.BADADDR:
        idc.msg(f"[!] Function '{func_name}' not found!\n")
        idaapi.qexit(1)

    try:
        arch64 = is_64bit()
    except RuntimeError as e:
        idc.msg(f"[!] {e}\n")
        idaapi.qexit(1)
    idc.msg(f"[+] is_64bit = {arch64}\n")

    f = ida_funcs.get_func(func_ea)
    if not f:
        idc.msg(f"[!] Failed to get function object for '{func_name}'!\n")
        idaapi.qexit(1)

    cfunc = ida_hexrays.decompile(f)
    if not cfunc:
        idc.msg(f"[!] Decompilation of '{func_name}' failed!\n")
        idaapi.qexit(1)

    # ====== 修复点 #1：获取帧类型 + 返回地址偏移（用 ida_frame API）======
    tinfo = ida_typeinf.tinfo_t()
    if not tinfo.get_func_frame(f):  # 推荐写法：面向对象
        idc.msg(f"[!] No function frame recognized for '{func_name}'!\n")
        idaapi.qexit(1)

    # 直接拿帧坐标中的返回地址起始偏移（locals<0, args>0）
    ret_addr_offset = ida_frame.frame_off_retaddr(f)
    idc.msg(f"[+] __return_address offset (frame coord) = {ret_addr_offset:#x}\n")

    # ====== 修复点 #2：构造 UDT 映射到“帧坐标” ======
    udt = ida_typeinf.udt_type_data_t()
    if not tinfo.get_udt_details(udt):
        idc.msg(f"[!] Unable to get UDT details for '{func_name}'!\n")
        idaapi.qexit(1)

    udt_map = {}
    for m in udt:
        # m.offset 是 bit，先转字节的“结构偏移”
        soff = m.offset // 8
        # 把结构偏移换成“帧指针相对偏移”（fp-relative, 即 Stack 窗口用的坐标）
        fpoff = ida_frame.soff_to_fpoff(f, soff)
        mem_tinfo = m.type
        udt_map[fpoff] = {
            "name": m.name,
            "type_str": mem_tinfo.dstr(),
            "size": mem_tinfo.get_size()
        }

    # ====== 变量使用行号（你的原逻辑）======
    var_usage_map = find_var_usage_lines(cfunc)
    lvars = cfunc.get_lvars()
    results = []

    for idx, lvar in enumerate(lvars):
        if not lvar.name:
            continue

        lvar_tinfo = lvar.type()
        lvar_type_str = lvar_tinfo.dstr()
        lvar_size = lvar.width

        if lvar.is_reg_var():
            loc_obj = lvar.location
            if loc_obj.is_reg1():
                reg_id = loc_obj.reg1()
            elif loc_obj.is_reg2():
                raise ValueError("[X] Two-register location not handled.")
            else:
                raise ValueError("[X] Unsupported register location type.")
            results.append({
                "lvar_idx": idx,
                "lvar_name": lvar.name,
                "lvar_type": lvar_type_str,
                "lvar_size": lvar_size,
                "usage_lines": sorted(list(var_usage_map[idx])),
                "reg_id": reg_id
            })
            continue

        if lvar.is_stk_var():
            # ====== 修复点 #3：帧偏移换算要“减去” delta ======
            lvar_off_in_frame = lvar.location.stkoff() - cfunc.get_stkoff_delta()

            rec = {
                "lvar_idx": idx,
                "lvar_name": lvar.name,
                "lvar_offset": lvar_off_in_frame,  # 现在是 Stack 窗口同一坐标：locals<0，ret/args>=0
                "lvar_type": lvar_type_str,
                "lvar_size": lvar_size,
                "usage_lines": sorted(list(var_usage_map[idx])),
                "udt_name": None,
                "udt_type": None,
                "udt_size": None,
                "dist_from_ret_addr": lvar_off_in_frame - ret_addr_offset  # 负数=在返回地址之下（更深的栈）
            }

            udt_member = udt_map.get(lvar_off_in_frame, None)
            if udt_member:
                rec["udt_name"] = udt_member["name"]
                rec["udt_type"] = udt_member["type_str"]
                rec["udt_size"] = udt_member["size"]

            results.append(rec)
            continue

        idc.msg(f"[~] lvar idx={idx} is neither reg_var nor stk_var, skip.\n")

    out_data = {
        "function_name": func_name,
        "__return_address_offset": ret_addr_offset,
        "variables": results
    }
    json_filename = "func_stack_varmatch.json"
    with open(json_filename, "w", encoding="utf-8", errors="replace") as outf:
        json.dump(out_data, outf, indent=2, ensure_ascii=False)

    idaapi.msg(f"[+] JSON result saved to: {json_filename}\n")
    idaapi.qexit(0)


if __name__ == "__main__":
    main()
#./ida.exe -A -L"output.log" -S"E:\ida_util\analysis_init\func_stack_dump_v3.py process_data" E:\vuln_test\test_n2\vuln
#./ida -A -L"output.log" -S"/home/workspace/ida_util/analysis_init/func_stack_dump_v4.py sub_138D" /home/workspace/Testcase/test3/vuln_n
#./ida -A -L"output.log" -S"/home/workspace/ida_util/analysis_init/func_stack_dump_v5.py CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_memmove_12_bad" /home/workspace/Testcase/exp1/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_memmove_12-bad
#./ida -A -L"output.log" -S"/home/workspace/ida_util/analysis_init/func_stack_dump_v5.py log_save" /home/workspace/Testcase/Benchmark_01_2vul/vuln_b01
