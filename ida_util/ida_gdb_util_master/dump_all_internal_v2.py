import json
import os
import idc
import ida_funcs
import idautils
import ida_segment
import ida_nalt
import ida_auto
import idaapi

# ------------------------------------------------------------
# 收集所有导入函数的 EA
# ------------------------------------------------------------
def collect_import_eas() -> set[int]:
    eas: set[int] = set()
    for mod_idx in range(ida_nalt.get_import_module_qty()):
        ida_nalt.enum_import_names(mod_idx,
                                   lambda ea, _n, _o: eas.add(ea) or True)
    return eas


# ------------------------------------------------------------
# PLT-Stub 启发式：体积小 + 只有跳转 + 没有返回
# ------------------------------------------------------------
_RET_MNEMS = {
    "ret", "retn", "retf", "retfq", "iret", "iretd", "iretq"
}

def looks_like_plt_stub(ea: int, max_size: int = 0x20) -> bool:
    func = ida_funcs.get_func(ea)
    if not func:
        return False

    if (func.end_ea - func.start_ea) > max_size:
        return False

    has_jmp = False
    for insn_ea in idautils.FuncItems(ea):
        mnem = (idc.print_insn_mnem(insn_ea) or "").lower()

        # ① 任何带 “jmp” 字样的助记符都记为跳转
        if "jmp" in mnem:
            has_jmp = True

        # ② 出现任意返回指令，则不是 PLT-stub
        if mnem in _RET_MNEMS:
            return False

    return has_jmp  # 必须至少含一条 jmp


# ------------------------------------------------------------
# 计算函数大小（字节）：累计所有函数块（含 tails）
# ------------------------------------------------------------
def get_function_size(ea: int) -> int:
    """
    更稳妥的计算方式：遍历 idautils.Chunks(ea)，
    将所有函数块 (start, end) 的长度相加，得到真实覆盖字节数。
    """
    total = 0
    # idautils.Chunks(ea) 会遍历该函数的所有块（主块 + 尾块）
    for start, end in idautils.Chunks(ea):
        total += (end - start)
    return total


# ------------------------------------------------------------
# 核心判定：是否为**用户自定义函数**
# ------------------------------------------------------------
def is_user_func(ea: int, import_eas: set[int]) -> bool:
    # 1. 导入地址
    if ea in import_eas:
        return False

    # 2. 段类型
    seg = ida_segment.getseg(ea)
    if seg and seg.type in (ida_segment.SEG_XTRN, ida_segment.SEG_IMP):
        return False

    # 3. 库 / 跳板标志
    func = ida_funcs.get_func(ea)
    if not func:
        return False
    if func.flags & (ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK):
        return False

    # 4. PLT-Stub 启发式
    if looks_like_plt_stub(ea):
        return False

    return True


# ------------------------------------------------------------
def main():
    ida_auto.auto_wait()
    import_eas = collect_import_eas()
    user_funcs = []

    for ea in idautils.Functions():
        print("ea:", hex(ea))
        if is_user_func(ea, import_eas):
            size_bytes = get_function_size(ea)
            user_funcs.append({
                "name": idc.get_func_name(ea),
                "start_ea": f"0x{ea:X}",
                "size": f"0x{size_bytes:X}"   # 新增：函数大小（字节，十六进制）
            })

    out_path = os.path.join(os.getcwd(), "func_internal_list.json")
    with open(out_path, "w", encoding="utf-8") as fp:
        json.dump(user_funcs, fp, indent=4, ensure_ascii=False, sort_keys=True)

    print(f"[+] 已输出 {len(user_funcs)} 个用户函数 → {out_path}")
    idc.qexit(0)


if __name__ == "__main__":
    main()
#./ida -A -L"output.log" -S"/home/workspace/ida_util/analysis_init/dump_all_internal_v2.py" /home/workspace/Testcase/test3/vuln_n
#./ida -A -L"output.log" -S"/home/workspace/ida_util/analysis_init/dump_all_internal_v2.py" /home/workspace/jc/t1/CWE121_Stack_Based_Buffer_Overflow__src_char_declare_cpy_84-bad
