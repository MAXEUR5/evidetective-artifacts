import idc
import idaapi
import ida_funcs
import ida_lines
import ida_hexrays
import ida_typeinf
import ida_frame
import idautils
import os

def main():
    """
    1) 在命令行用 -S"func_dump_sp.py <function_name>" 运行，<function_name> 是要分析的函数
    2) 读取该函数反编译后的局部变量 (lvars) 与栈帧(UDT)成员
    3) 通过比较它们在 Frame(相对于函数入口RSP)中的“绝对偏移”是否相等，直接判断哪一个lvar对应哪个UDT成员
    4) 最后计算到 __return_address 的距离
    """

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

    # ------------------------------
    # 导出反汇编 (可选)
    # ------------------------------
    asm_filename = f"func_{func_name}_asm.txt"
    with open(asm_filename, "w", encoding="utf-8", errors="replace") as outf_asm:
        for ea in idautils.Heads(f.start_ea, f.end_ea):
            line = idc.GetDisasm(ea)
            outf_asm.write(f"0x{ea:08X}: {line}\n")
    idc.msg(f"Disassembly saved to: {asm_filename}\n")

    # ------------------------------
    # 导出伪代码 (可选)
    # ------------------------------
    pcode_filename = f"func_{func_name}_pcode.txt"
    with open(pcode_filename, "w", encoding="utf-8", errors="replace") as outf_pc:
        for sline in cfunc.get_pseudocode():
            outf_pc.write(ida_lines.tag_remove(sline.line) + "\n")
    idc.msg(f"Pseudocode saved to: {pcode_filename}\n")

    # ------------------------------
    # 获取栈帧 (UDT) 并查找 __return_address
    # ------------------------------
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
        # m.offset 是 bit 单位
        if m.name == "__return_address":
            ret_addr_offset = m.offset // 8
            break

    # 如果找不到，就做简单猜测
    if ret_addr_offset is None:
        inf = idaapi.get_inf_structure()
        ret_addr_offset = 8 if inf.is_64bit() else 4
        idc.msg("Warning: __return_address not found; using default offset = %d\n" % ret_addr_offset)
    idc.msg(f"__return_address offset = {ret_addr_offset} (from the stack frame base)\n")

    # ------------------------------
    # 把 UDT 中各成员以 (offset_in_frame -> 结构) 存到字典里
    # 用于 O(1) 地匹配 cfunc lvar
    # ------------------------------
    udt_map = {}
    for m in udt:
        mem_off_in_frame = m.offset // 8  # IDA 里以字节为单位
        mem_tinfo = m.type     # udt_member_t 的类型属性
        mem_size = mem_tinfo.get_size()
        mem_type_str = mem_tinfo.dstr()

        udt_map[mem_off_in_frame] = {
            "name": m.name,
            "type_str": mem_type_str,
            "size": mem_size,
        }

    # ------------------------------
    # 遍历反编译出来的 lvars
    # 计算其 "offset_in_frame = stkoff + get_stkoff_delta()"
    # ------------------------------
    results = []
    for lvar in cfunc.get_lvars():
        if not lvar.is_stk_var():
            continue
        
        lvar_off_in_frame = lvar.location.stkoff() + cfunc.get_stkoff_delta()
        # lvar.type() 是方法调用
        lvar_tinfo = lvar.type()
        lvar_type_str = lvar_tinfo.dstr()
        lvar_size = lvar.width

        # 查表匹配：如果 offset_in_frame 一致，则表示同一个地址
        udt_member = udt_map.get(lvar_off_in_frame, None)

        # 准备记录的项
        rec = {
            "lvar_name": lvar.name,
            "lvar_offset": lvar_off_in_frame,
            "lvar_type": lvar_type_str,
            "lvar_size": lvar_size,
            "udt_member": udt_member
        }

        # 如果匹配上 UDT 成员，计算该成员到 __return_address 的距离
        if udt_member:
            rec["udt_name"] = udt_member["name"]
            rec["udt_type"] = udt_member["type_str"]
            rec["udt_size"] = udt_member["size"]
            # 相对于返回地址的距离
            dist = lvar_off_in_frame - ret_addr_offset
            rec["dist_from_ret_addr"] = dist
        else:
            rec["udt_name"] = None
            rec["udt_type"] = None
            rec["udt_size"] = None
            rec["dist_from_ret_addr"] = None

        results.append(rec)

    # ------------------------------
    # 写入输出文件
    # ------------------------------
    match_filename = f"func_{func_name}_varmatch.txt"
    with open(match_filename, "w", encoding="utf-8", errors="replace") as outf:
        outf.write(f"Function: {func_name}\n")
        outf.write(f"__return_address offset (frame base) = {ret_addr_offset}\n\n")

        for r in results:
            outf.write("------------------------------------------------------\n")
            outf.write(f"HexRays Var Name : {r['lvar_name']}\n")
            outf.write(f"  offset_in_frame: {r['lvar_offset']}\n")
            outf.write(f"  Type           : {r['lvar_type']}\n")
            outf.write(f"  Size           : {r['lvar_size']}\n")

            if r["udt_name"]:
                outf.write(f"Matched UDT Member: {r['udt_name']}\n")
                outf.write(f"  UDT Type         : {r['udt_type']}\n")
                outf.write(f"  UDT Size         : {r['udt_size']}\n")
                outf.write(f"  Dist from ret    : {r['dist_from_ret_addr']}\n")
            else:
                outf.write("Matched UDT Member: None\n")

            outf.write("\n")

    idc.msg(f"Variable matching info saved to: {match_filename}\n")
    idaapi.qexit(0)


if __name__ == "__main__":
    main()
