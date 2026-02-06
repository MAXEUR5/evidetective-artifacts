# lvar_name_init.py (调试加强版)

import json
import idaapi
import idc
import ida_hexrays
import ida_loader
import traceback

def parse_args():
    """解析命令行参数并输出调试信息。"""
    idc.msg(f"[DEBUG] ARGV = {idc.ARGV}\n")  # 打印脚本实际收到的参数

    funcs = []
    for arg in idc.ARGV:
        if arg.startswith("funcs_list="):
            raw = arg.split("=", 1)[1].strip()
            if raw.startswith("["):
                try:
                    funcs = json.loads(raw)
                except Exception as e:
                    idc.msg(f"[!] JSON parse error: {e}\n")
            else:
                # 逗号分隔
                funcs = [x.strip() for x in raw.split(",") if x.strip()]

    idc.msg(f"[DEBUG] parse_args() => funcs = {funcs}\n")
    if not funcs:
        idc.msg("[!] Usage: -S\"lvar_name_init.py funcs_list=funA,funB\"\n")
        idaapi.qexit(1)
    return funcs

def get_varloc_id(varloc):
    """返回相对稳定的 varloc 标识 (栈偏移 或 寄存器号)"""
    if varloc.is_stkoff():
        return f"stack_0x{varloc.stkoff():X}"
    elif varloc.is_reg1():
        return f"reg_{varloc.reg1()}"
    return f"other_{varloc.atype()}"

def rename_all_empty_lvars(func_ea):
    """主逻辑：循环反编译，找出空名 lvar 并改为 arg_x。"""
    if not ida_hexrays.init_hexrays_plugin():
        idc.msg("[!] Hex-Rays decompiler not available.\n")
        return

    processed_locs = set()
    new_name_index = 0
    loop_count = 0

    while True:
        loop_count += 1
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc:
            idc.msg(f"[!] decompile() failed at 0x{func_ea:X} (loop={loop_count}).\n")
            break

        all_lvars = cfunc.get_lvars()
        if not all_lvars:
            idc.msg(f"[-] No lvars found at 0x{func_ea:X} (loop={loop_count}).\n")
            break

        idc.msg(f"[DEBUG] loop={loop_count}, func_ea=0x{func_ea:X}, total_lvars={len(all_lvars)}.\n")

        found_empty = False
        # 打印当前的 lvar name 和 location
        for lvar in all_lvars:
            idc.msg(f"[VAR] name='{lvar.name}' ; location='{get_varloc_id(lvar.location)}'\n")

        # 开始处理空名
        for lvar in all_lvars:
            if not lvar.name:  # 真正空名
                loc_str = get_varloc_id(lvar.location)
                if loc_str in processed_locs:
                    idc.msg(f"[DEBUG] Already processed loc={loc_str}, skip.\n")
                    continue
                tmp_name = f"arg_{new_name_index}"
                new_name_index += 1

                ok = ida_hexrays.rename_lvar(func_ea, "", tmp_name)
                idc.msg(f"[-] Rename1 0x{func_ea:X} - {tmp_name}, loc={loc_str}, ok={ok}, loop={loop_count}.\n")
                processed_locs.add(loc_str)

                if ok:
                    found_empty = True
                break

        if not found_empty:
            idc.msg(f"[DEBUG] No more empty lvars left at 0x{func_ea:X}, loop={loop_count}.\n")
            break

def process_function(func_name):
    """根据函数名获取入口地址，若存在则调用 rename_all_empty_lvars。"""
    func_ea = idc.get_name_ea_simple(func_name)
    idc.msg(f"[DEBUG] process_function('{func_name}') => 0x{func_ea:X}\n")
    if func_ea == idc.BADADDR:
        idc.msg(f"[!] Function '{func_name}' not found or invalid.\n")
        return

    rename_all_empty_lvars(func_ea)

def main():
    try:
        funcs_to_process = parse_args()
        idc.msg(f"[DEBUG] main() got funcs_to_process = {funcs_to_process}\n")

        for fn in funcs_to_process:
            idc.msg(f"[*] Start processing function '{fn}'\n")
            process_function(fn)

        idc.msg("[+] All Done\n")

        # 若想自动保存并退出，加上以下：
        # cur_idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        # if not cur_idb_path:
        #     cur_idb_path = idc.get_idb_path()
        # if not cur_idb_path:
        #     cur_idb_path = "temp_auto_save.i64"
        # try:
        #     ida_loader.save_database(cur_idb_path, 0)
        #     idc.msg(f"[*] Database saved to '{cur_idb_path}'.\n")
        # except Exception as e:
        #     idc.msg(f"[!] Failed to save DB: {e}\n")

        idaapi.qexit(0)

    except Exception as exc:
        # 捕获异常并打印堆栈
        tb = traceback.format_exc()
        idc.msg(f"[EXCEPTION] {exc}\nTraceback:\n{tb}\n")
        idaapi.qexit(1)

if __name__ == "__main__":
    main()
