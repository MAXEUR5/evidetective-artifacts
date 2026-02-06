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

    _ = cfunc.get_pseudocode()  # 触发生成伪代码行信息
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
    尝试 eamap，若为空或失败则回退到 ctree 遍历
    """
    try:
        m = build_ea2line_map_via_eamap(cfunc)
        if m:
            return m
    except:
        pass
    return build_ea2line_map_via_ctree(cfunc)


# -------------------------------------------------------------------------------------
# 3) 收集局部变量使用行号，包含对赋值表达式(cot_asg)的特殊处理
# -------------------------------------------------------------------------------------
def find_var_usage_lines(cfunc):
    """
    返回 usage_map: dict( var_idx -> set( 行号 ) )
    其中行号基于 eamap 或 ctree 计算得来。
    """
    lvars = cfunc.get_lvars()
    usage_map = {i: set() for i in range(len(lvars))}
    ea2line = choose_ea2line_map_builder(cfunc)

    def add_usage(var_idx, ea):
        """辅助函数：将 var_idx 在 ea 对应的行号处出现的记录加到 usage_map。"""
        if ea in ea2line:
            usage_map[var_idx].add(ea2line[ea])

    def collect_var_indexes(e, out_set):
        """
        递归函数：采集表达式 e 中所有 'cot_var' 的 var_idx。
        cexpr_t 不可迭代，需要手动访问 x,y,z。
        """
        if e.op == ida_hexrays.cot_var:
            out_set.add(e.v.idx)

        # cexpr_t 可能有 0~3 个子节点(x, y, z)
        if e.x and isinstance(e.x, ida_hexrays.cexpr_t):
            collect_var_indexes(e.x, out_set)
        if e.y and isinstance(e.y, ida_hexrays.cexpr_t):
            collect_var_indexes(e.y, out_set)
        if e.z and isinstance(e.z, ida_hexrays.cexpr_t):
            collect_var_indexes(e.z, out_set)

    class VarUsageVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            """
            - 若是一般变量引用(cot_var)，记录其 e.ea 对应行号
            - 若是赋值表达式(cot_asg)，则把左、右子表达式中所有 var 均视作在 e.ea 对应行号出现
            """
            if e.op == ida_hexrays.cot_var:
                add_usage(e.v.idx, e.ea)
            elif e.op == ida_hexrays.cot_asg:
                var_idxs = set()
                collect_var_indexes(e.x, var_idxs)
                collect_var_indexes(e.y, var_idxs)
                for vid in var_idxs:
                    add_usage(vid, e.ea)
            return 0

    visitor = VarUsageVisitor()
    visitor.apply_to(cfunc.body, None)
    return usage_map


# -------------------------------------------------------------------------------------
# 4) 主体逻辑
# -------------------------------------------------------------------------------------
def main():
    """
    用法：
      ida64.exe -A -S"func_stack_dump_v3.py <function_name>" <target_binary>
    解析指定函数，对局部变量:
      - 若是寄存器变量(只输出 reg_id)
      - 若是栈变量(输出偏移等信息)
      - 在伪代码中的行号(包括初始化赋值)
    结果写入 JSON。
    """
    ida_auto.auto_wait()

    # 确保 Hex-Rays Decompiler 可用
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

    # 判断 32/64 位
    try:
        arch64 = is_64bit()
    except RuntimeError as e:
        idc.msg(f"[!] {e}\n")
        idaapi.qexit(1)
    idc.msg(f"[+] is_64bit = {arch64}\n")

    # 获取函数对象
    f = ida_funcs.get_func(func_ea)
    if not f:
        idc.msg(f"[!] Failed to get function object for '{func_name}'!\n")
        idaapi.qexit(1)

    # 调用 Hex-Rays 反编译
    cfunc = ida_hexrays.decompile(f)
    if not cfunc:
        idc.msg(f"[!] Decompilation of '{func_name}' failed!\n")
        idaapi.qexit(1)

    # 获取函数frame (stack frame)
    tinfo = ida_typeinf.tinfo_t()
    if not ida_frame.get_func_frame(tinfo, f):
        idc.msg(f"[!] No function frame recognized for '{func_name}'!\n")
        idaapi.qexit(1)

    # 解析 UDT
    udt = ida_typeinf.udt_type_data_t()
    if not tinfo.get_udt_details(udt):
        idc.msg(f"[!] Unable to get UDT details for '{func_name}'!\n")
        idaapi.qexit(1)

    # 查找 __return_address 偏移
    ret_addr_offset = None
    for m in udt:
        if m.name == "__return_address":
            ret_addr_offset = m.offset // 8
            break
    if ret_addr_offset is None:
        # 若没找到，则给个默认
        ret_addr_offset = 8 if arch64 else 4
        idc.msg(f"[!] __return_address not found; default={ret_addr_offset}\n")
    idc.msg(f"[+] __return_address offset = {ret_addr_offset}\n")

    # 构造 UDT 映射
    udt_map = {}
    for m in udt:
        mem_off_in_frame = m.offset // 8
        mem_tinfo = m.type
        mem_size = mem_tinfo.get_size()
        mem_type_str = mem_tinfo.dstr()
        udt_map[mem_off_in_frame] = {
            "name": m.name,
            "type_str": mem_type_str,
            "size": mem_size
        }

    # 获取局部变量在伪代码中的使用行号
    var_usage_map = find_var_usage_lines(cfunc)
    lvars = cfunc.get_lvars()
    results = []

    for idx, lvar in enumerate(lvars):
        if not lvar.name:
            continue  # 无名局部变量可根据需要处理

        lvar_tinfo = lvar.type()
        lvar_type_str = lvar_tinfo.dstr()
        lvar_size = lvar.width

        if lvar.is_reg_var():
            # 只输出 reg_id，不尝试寄存器名称
            loc_obj = lvar.location
            if loc_obj.is_reg1():
                reg_id = loc_obj.reg1()
            elif loc_obj.is_reg2():
                raise ValueError("[X] Two-register location not handled.")
            else:
                raise ValueError("[X] Unsupported register location type.")

            idc.msg(f"[+] lvar idx={idx}, name={lvar.name}, reg_id={reg_id}\n")
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
            # 栈变量
            lvar_off_in_frame = lvar.location.stkoff() + cfunc.get_stkoff_delta()
            rec = {
                "lvar_idx": idx,
                "lvar_name": lvar.name,
                "lvar_offset": lvar_off_in_frame,
                "lvar_type": lvar_type_str,
                "lvar_size": lvar_size,
                "usage_lines": sorted(list(var_usage_map[idx])),
                "udt_name": None,
                "udt_type": None,
                "udt_size": None,
                "dist_from_ret_addr": None
            }
            udt_member = udt_map.get(lvar_off_in_frame, None)
            if udt_member:
                rec["udt_name"] = udt_member["name"]
                rec["udt_type"] = udt_member["type_str"]
                rec["udt_size"] = udt_member["size"]
                rec["dist_from_ret_addr"] = lvar_off_in_frame - ret_addr_offset

            results.append(rec)
            continue

        idc.msg(f"[~] lvar idx={idx} is neither reg_var nor stk_var, skip.\n")

    # 输出 JSON
    json_filename = f"func_{func_name}_varmatch.json"
    out_data = {
        "function_name": func_name,
        "__return_address_offset": ret_addr_offset,
        "variables": results
    }
    with open(json_filename, "w", encoding="utf-8", errors="replace") as outf:
        json.dump(out_data, outf, indent=2, ensure_ascii=False)

    idc.msg(f"[+] JSON result saved to: {json_filename}\n")
    idaapi.qexit(0)

if __name__ == "__main__":
    main()
