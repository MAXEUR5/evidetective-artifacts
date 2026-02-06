import idc          # type: ignore
import idaapi       # type: ignore
import ida_funcs    # type: ignore
import ida_lines    # type: ignore
import ida_hexrays  # type: ignore
import ida_typeinf
import ida_frame
import os

def main():
    # Initialize Hex-Rays decompiler plugin
    if not ida_hexrays.init_hexrays_plugin():
        idc.msg("Hex-Rays decompiler plugin not available!\n")
        idaapi.qexit(1)
    
    idc.msg("Hex-rays version %s has been detected\n" % ida_hexrays.get_hexrays_version())
    idc.msg("Working directory: " + os.getcwd() + "\n")
    
    # Parse command-line arguments (first entry is the script, second is the target function name)
    if len(idc.ARGV) < 2:
        idc.msg("Usage: script.py <function_name>\n")
        idaapi.qexit(1)
    
    target_function_name = idc.ARGV[1]
    idc.msg("Target function name: " + target_function_name + "\n")
    
    # Locate the function address and function object by name
    func_ea = idc.get_name_ea_simple(target_function_name)
    if func_ea == idc.BADADDR:
        idc.msg("Function not found: " + target_function_name + "\n")
        idaapi.qexit(1)
    
    f = ida_funcs.get_func(func_ea)
    if f is None:
        idc.msg("Failed to get function for: " + target_function_name + "\n")
        idaapi.qexit(1)
    
    # Call the Hex-Rays decompiler to obtain pseudocode and save it to a file
    cfunc = ida_hexrays.decompile(f)
    if cfunc is None:
        idc.msg("Failed to decompile function: " + target_function_name + "\n")
        idaapi.qexit(1)
    
    pcode_filename = "func_%s_pcode.txt" % target_function_name
    with open(pcode_filename, "w", encoding="utf-8", errors="replace") as f_out:
        for sline in cfunc.get_pseudocode():
            f_out.write(ida_lines.tag_remove(sline.line) + "\n")
    idc.msg("Pseudocode saved to: " + pcode_filename + "\n")
    
    # Build a mapping from fp offset to the variable name shown in the decompiler output
    lvar_map = {}
    for lvar in cfunc.get_lvars():
        idc.msg(str(lvar))
        loc = lvar.get_storage()  # Retrieve the var_locator_t object
        if loc.is_stk_var():
            # Use the offset field as the local variable's stack offset (bytes)
            lvar_map[loc.off] = lvar.name

    # Use ida_frame.get_func_frame() to obtain the frame tinfo object
    tinfo = ida_typeinf.tinfo_t()
    if not ida_frame.get_func_frame(tinfo, f):
        idc.msg("No frame found for function %s\n" % target_function_name)
        idaapi.qexit(1)
    
    # Convert tinfo into UDT structure details (udt_type_data_t)
    udt = ida_typeinf.udt_type_data_t()
    if not tinfo.get_udt_details(udt):
        idc.msg("Unable to get the frame details.\n")
        idaapi.qexit(1)
    
    # Inspect UDT members to find the __return_address offset (bits, divide by 8 to get bytes)
    ret_addr_offset = None
    for member in udt:
        if member.name == "__return_address":
            ret_addr_offset = member.offset // 8
            break
    if ret_addr_offset is None:
        idc.msg("Return address (__return_address) not found in frame\n")
        idaapi.qexit(1)
    
    # Analyze stack locals and save them to func_<function>_stackvar.txt
    stackvar_filename = "func_%s_stackvar.txt" % target_function_name
    with open(stackvar_filename, "w", encoding="utf-8", errors="replace") as f_out:
        f_out.write("[Stack Local Variable Analysis]\n")
        for member in udt:
            # Skip __saved_registers and __return_address
            if member.name in ("__saved_registers", "__return_address"):
                continue
            offset_bytes = member.offset // 8
            offset_diff = ret_addr_offset - offset_bytes
            # Find the variable name in the decompiled output (empty string if missing)
            decompiled_name = lvar_map.get(offset_bytes, "")
            f_out.write("Variable: %-20s (decompiled as: %-20s)  Offset: 0x%08x  Diff to return address: 0x%x (%d bytes)\n" %
                        (member.name, decompiled_name, offset_bytes, offset_diff, offset_diff))
    
    idc.msg("Stack variable analysis saved to: " + stackvar_filename + "\n")
    idaapi.qexit(0)

if __name__ == '__main__':
    main()
