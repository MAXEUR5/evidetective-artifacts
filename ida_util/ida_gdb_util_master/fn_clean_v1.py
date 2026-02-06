# coding: utf-8
# 清洗 USER_DEF 函数名：检测到包含 '.' 等不合法字符时，改用 visible_name 替换并写回 IDB。
# 运行方式（GUI或批处理皆可）：
#   - GUI:  File -> Script file... 选中本脚本
#   - 批处理: ida -A -L"clean.log" -S"/path/clean_userdef_names.py" <your_binary>
#
# 可选参数（通过 -S 传参，空格分隔）：
#   --no-save     只改名不保存 IDB（默认会保存）
#   --no-exit     运行完不 qexit（默认会退出）

import os
import re
import sys
import idc
import idaapi
import ida_funcs
import idautils
import ida_segment
import ida_nalt
import ida_auto
import ida_name

# ------------------------------ 复用：收集导入地址 ------------------------------
def collect_import_eas() -> set[int]:
    eas: set[int] = set()
    for mod_idx in range(ida_nalt.get_import_module_qty()):
        ida_nalt.enum_import_names(mod_idx,
                                   lambda ea, _n, _o: eas.add(ea) or True)
    return eas

# ------------------------------ 复用：启发式 PLT stub ---------------------------
_RET_MNEMS = {"ret", "retn", "retf", "retfq", "iret", "iretd", "iretq"}
def looks_like_plt_stub(ea: int, max_size: int = 0x20) -> bool:
    func = ida_funcs.get_func(ea)
    if not func:
        return False
    if (func.end_ea - func.start_ea) > max_size:
        return False
    has_jmp = False
    for insn_ea in idautils.FuncItems(ea):
        mnem = (idc.print_insn_mnem(insn_ea) or "").lower()
        if "jmp" in mnem:
            has_jmp = True
        if mnem in _RET_MNEMS:
            return False
    return has_jmp

# ------------------------------ 复用：判定 USER_DEF -----------------------------
def is_user_func(ea: int, import_eas: set[int]) -> bool:
    if ea in import_eas:
        return False
    seg = ida_segment.getseg(ea)
    if seg and seg.type in (ida_segment.SEG_XTRN, ida_segment.SEG_IMP):
        return False
    func = ida_funcs.get_func(ea)
    if not func:
        return False
    if func.flags & (ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK):
        return False
    if looks_like_plt_stub(ea):
        return False
    return True

# ------------------------------ 名称合法性/清洗 ---------------------------------
# “不合法”的判定：含 '.' 或含非 [A-Za-z0-9_]；或以 '.' 开头；或以数字开头
_ILLEGAL_RE = re.compile(r"[^A-Za-z0-9_]")
def is_bad_symbol(s: str) -> bool:
    if not s:
        return True
    if s.startswith(".") or "." in s:
        return True
    if _ILLEGAL_RE.search(s):
        return True
    if s[0].isdigit():
        return True
    return False

def basic_sanitize(s: str) -> str:
    # 兜底清洗：空白->"_", 非法字符->"_", 处理开头 '.' 或数字
    if not s:
        s = "noname"
    s = s.replace(" ", "_")
    s = _ILLEGAL_RE.sub("_", s)
    if s.startswith("."):
        s = "_" + s[1:]
    if s[0].isdigit():
        s = "f_" + s
    return s

def ensure_unique_name(base: str, ea: int) -> str:
    """
    保证名字在当前数据库唯一。若冲突，自动加后缀 _2/_3...
    """
    name = base
    idx = 2
    while True:
        other_ea = ida_name.get_name_ea(idaapi.BADADDR, name)
        if other_ea == idaapi.BADADDR or other_ea == ea:
            return name
        name = f"{base}_{idx}"
        idx += 1

# ------------------------------ 主逻辑 -----------------------------------------
def main():
    # 解析脚本参数
    SAVE_DB = True
    DO_EXIT = True
    for a in sys.argv[1:]:
        if a == "--no-save":
            SAVE_DB = False
        elif a == "--no-exit":
            DO_EXIT = False

    ida_auto.auto_wait()

    import_eas = collect_import_eas()
    renamed_cnt = 0
    skipped_cnt = 0

    for ea in idautils.Functions():
        if not is_user_func(ea, import_eas):
            continue

        cur_name = ida_funcs.get_func_name(ea) or idc.get_name(ea) or ""
        if not is_bad_symbol(cur_name):
            skipped_cnt += 1
            continue

        # 1) 优先尝试 GUI 可见名（通常已把 '.' -> '_'）
        vis = ida_name.get_visible_name(ea) or ""
        candidate = vis if vis else cur_name
        # 2) 再做一次兜底清洗，确保能作为“标识符”
        candidate = basic_sanitize(candidate)
        # 3) 确保唯一
        candidate = ensure_unique_name(candidate, ea)

        # 4) 改名（使用 set_name 更通用；也可用 ida_funcs.set_func_name）
        ok = idc.set_name(ea, candidate, idc.SN_NOWARN | idc.SN_CHECK)
        if not ok:
            # 如果 set_name 因为某些限制失败，退回到函数专用接口再试一次
            ok = ida_funcs.set_func_name(ea, candidate)
        if ok:
            print(f"[RENAMED] {hex(ea)}: {cur_name}  ->  {candidate}")
            renamed_cnt += 1
        else:
            print(f"[WARN]    {hex(ea)}: rename failed: {cur_name} -> {candidate}")

    print(f"[SUMMARY] renamed={renamed_cnt}, unchanged={skipped_cnt}")

    # 可选：保存数据库（建议在批处理模式下开启；GUI模式你也可以手动 File->Save）
    if SAVE_DB:
        try:
            # IDA 9.x 通常支持这个形式：传入当前 IDB 路径 & flags=0
            idb_path = idc.get_idb_path()
            if not idb_path:
                # 保险：若拿不到路径，仍尝试直接保存当前会话
                idaapi.save_database()
            else:
                idaapi.save_database(idb_path, 0)
            print(f"[+] Database saved: {idb_path}")
        except Exception as e:
            try:
                # 旧式接口兜底
                idc.save_database(idc.get_idb_path(), 0)
                print(f"[+] Database saved (idc.save_database)")
            except Exception as e2:
                print(f"[!] Auto-save failed: {e} / {e2}. Please save manually.")

    # 最后退出（按你的要求）
    if DO_EXIT:
        idc.qexit(0)

if __name__ == "__main__":
    main()

# ./ida -A -L"output.log" -S"/home/workspace/ida_util/analysis_init/fn_clean_v1.py" /home/workspace/Testcase/test3/vuln_n
