import idc          # type: ignore
import idaapi       # type: ignore
import ida_funcs    # type: ignore
import ida_lines    # type: ignore
import ida_hexrays  # type: ignore
import os

def main():
    # 初始化Hex-Rays插件（IDA 9.0中通常需要调用）
    if not ida_hexrays.init_hexrays_plugin():
        idc.msg("Hex-Rays decompiler plugin not available!\n")
        idaapi.qexit(1)
    
    idc.msg("Hex-rays version %s has been detected\n" % ida_hexrays.get_hexrays_version())
    idc.msg("Working directory: " + os.getcwd() + "\n")
    
    # 从 idc.ARGV 获取参数（第一个元素为脚本名）
    if len(idc.ARGV) < 2:
        idc.msg("Usage: script.py <function_name>\n")
        idaapi.qexit(1)
    
    target_function_name = idc.ARGV[1]
    idc.msg("Target function name: " + target_function_name + "\n")
    
    # 根据函数名获取函数地址
    func_ea = idc.get_name_ea_simple(target_function_name)
    if func_ea == idc.BADADDR:
        idc.msg("Function not found: " + target_function_name + "\n")
        idaapi.qexit(1)
    
    f = ida_funcs.get_func(func_ea)
    if f is None:
        idc.msg("Failed to get function for: " + target_function_name + "\n")
        idaapi.qexit(1)
    
    # 调用Hex-Rays反编译
    cfunc = ida_hexrays.decompile(f)
    if cfunc is None:
        idc.msg("Failed to decompile function: " + target_function_name + "\n")
        idaapi.qexit(1)
    
    # 获取伪代码行并利用 ida_lines.tag_remove() 清除内部格式标记
    pseudocode_lines = []
    for sline in cfunc.get_pseudocode():
        pseudocode_lines.append(ida_lines.tag_remove(sline.line))
    
    # 保存伪代码到文件
    pcode_filename = "func_%s_pcode.txt" % target_function_name
    with open(pcode_filename, "w", encoding="utf-8", errors="replace") as f_out:
        for line in pseudocode_lines:
            f_out.write(line + "\n")
    idc.msg("Pseudocode saved to: " + pcode_filename + "\n")
    
    # 同时打印到控制台
    for line in pseudocode_lines:
        print(line)
    
    idaapi.qexit(0)

if __name__ == '__main__':
    main()
