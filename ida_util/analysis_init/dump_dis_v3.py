# -*- coding: utf-8 -*-
"""
dump_dis_v3.py -- IDA 9.1 + Hex-Rays
按函数名列表导出：
  - 原始反汇编（仅指令）
  - 伪代码
  - 增强汇编（插 label + 就近插入伪代码行）
并在导出前，若目标函数存在 PR_BADSTACK（栈分析失败），
先执行一次“alloca 临近赋值 RHS 修正”，以提高反编译与 eamap 的准确性。

用法示例（Linux）：
./ida -A -L"output.log" -S"/path/dump_dis_v3.py funcs_list=[goodG2B,bad]" /path/to/binary
"""
from __future__ import annotations

import json
import os

import idaapi
import idc
import idautils

import ida_auto
import ida_bytes
import ida_funcs
import ida_lines
import ida_name

# ===== 0) 等待自动分析完成 =====
if callable(getattr(idaapi, "auto_wait", None)):
    idaapi.auto_wait()
ida_auto.auto_wait()

# ===== 1) 解析 funcs_list 参数 =====
def parse_funcs_from_argv() -> list[str]:
    """
    从 idc.ARGV 中提取 'funcs_list=' 参数，并返回函数名列表。
    仅做简单字符串处理，不依赖正则。
    """
    for arg in idc.ARGV[1:]:  # ARGV[0] 是脚本路径
        if arg.startswith("funcs_list="):
            value = arg.partition("=")[2].strip()
            if value.startswith("[") and value.endswith("]"):
                raw_items = value[1:-1].split(",")
                return [item.strip() for item in raw_items if item.strip()]
            return [value]
    idc.warning("未检测到参数 funcs_list=...，脚本退出")
    idaapi.qexit(1)

FUNC_NAMES: list[str] = parse_funcs_from_argv()
idc.msg(f"[*] 解析到函数列表: {FUNC_NAMES}\n")

# ===== 2) 确保 Hex-Rays 可用 =====
try:
    import ida_hexrays
    if not ida_hexrays.init_hexrays_plugin():
        idc.warning("Hex-Rays 反编译器未激活，无法导出伪代码/增强汇编")
        idaapi.qexit(1)
except Exception as e:
    idc.warning(f"加载 Hex-Rays 失败: {e}")
    idaapi.qexit(1)

# ===== 3) 通用工具 =====
def is_code(ea: int) -> bool:
    return ida_bytes.is_code(ida_bytes.get_full_flags(ea))

def get_disasm_text(ea: int) -> str:
    try:
        s = ida_lines.generate_disasm_line(ea, 0)
        if s:
            return ida_lines.tag_remove(s)
    except Exception:
        pass
    return idc.GetDisasm(ea) or ""

def get_label_at(ea: int, func_start_ea: int) -> str | None:
    try:
        name = ida_name.get_name(ea)
    except Exception:
        name = None
    if not name:
        return None
    # 如不希望在函数首地址打印函数名标签，可以下两行解注：
    # if ea == func_start_ea:
    #     return None
    return f"{name}:"

def is_meaningful_pseudoline(text: str) -> bool:
    s = text.strip()
    if not s:
        return False
    if s in ("{", "}"):
        return False
    if s == "else" or s == "do":
        return False
    return True

def build_ea_to_pseudorows(cfunc) -> dict[int, list[int]]:
    """
    使用 eamap 建立 EA -> 伪代码行号(y) 的映射。
    """
    ea2rows: dict[int, list[int]] = {}
    eamap = cfunc.get_eamap()
    for ea in idautils.FuncItems(cfunc.entry_ea):
        if not is_code(ea):
            continue
        rows = set()
        try:
            cvec = eamap.at(ea)
        except Exception:
            cvec = None
        if cvec:
            for i in range(len(cvec)):
                ci = cvec[i]
                try:
                    xy = cfunc.find_item_coords(ci)  # (x, y)
                    if isinstance(xy, tuple) and len(xy) == 2:
                        rows.add(int(xy[1]))
                except Exception:
                    pass
        if rows:
            ea2rows[ea] = sorted(rows)
    return ea2rows

def make_enhanced_disasm_for_func(f: ida_funcs.func_t, cfunc) -> str:
    """
    生成增强汇编文本：
      - 插入 label 行（GUI 里的 'xxx:'）
      - 在首个对应指令前插入伪代码注释行（模拟 GUI 的 Copy to assembly 语义）
      - 输出指令行
    """
    sv = cfunc.get_pseudocode()  # strvec_t
    ea2rows = build_ea_to_pseudorows(cfunc)
    printed_rows = set()

    lines: list[str] = []
    for ea in idautils.FuncItems(f.start_ea):
        if not is_code(ea):
            continue

        lbl = get_label_at(ea, f.start_ea)
        if lbl:
            lines.append(lbl)

        rows = ea2rows.get(ea, [])
        for y in rows:
            if y in printed_rows:
                continue
            try:
                raw = sv[y].line
                text = ida_lines.tag_remove(raw)
            except Exception:
                continue
            if is_meaningful_pseudoline(text):
                lines.append(f"; {text}")
            printed_rows.add(y)

        lines.append(get_disasm_text(ea))

    return "\n".join(lines)

# ===== 4) alloca 修正（仅提取必要部分；require_badstack=True） =====
import ida_ida, ida_idaapi, ida_problems

ALLOC_NAMES = {
    "alloca", "__alloca", "_alloca",
    "__chkstk", "__chkstk_ms", "_chkstk", "___chkstk_ms",
    "alloca_probe"
}

def function_has_badstack(f: ida_funcs.func_t) -> bool:
    ea = ida_ida.inf_get_min_ea()
    while True:
        ea = ida_problems.get_problem(ida_problems.PR_BADSTACK, ea + 1)
        if ea == ida_idaapi.BADADDR:
            break
        if f.start_ea <= ea < f.end_ea:
            return True
    return False

def _get_call_name(call_e: ida_hexrays.cexpr_t) -> str | None:
    callee = call_e.x
    try:
        if callee.op == ida_hexrays.cot_obj:
            return ida_name.get_name(callee.obj_ea)
        if callee.op == ida_hexrays.cot_helper:
            return callee.helper
    except Exception:
        pass
    return None

def _is_alloca_call(rhs: ida_hexrays.cexpr_t) -> bool:
    if rhs.op != ida_hexrays.cot_call:
        return False
    name = _get_call_name(rhs)
    if not name:
        return False
    base = name.lower().split("@", 1)[0]
    return base in ALLOC_NAMES or ("alloca" in base)

def _replace_rhs_with_lvar(rhs_expr: ida_hexrays.cexpr_t, lvar: ida_hexrays.lvar_t) -> None:
    repl = ida_hexrays.cexpr_t()
    repl.op = ida_hexrays.cot_var
    repl.v = lvar
    rhs_expr.replace_by(repl)

def _process_any(cfunc: ida_hexrays.cfunc_t, node, debug: bool=False) -> int:
    """
    在 cblock / cinsn_t 中做“alloca -> 紧邻下一条赋值”的就近配对替换。
    """
    if isinstance(node, ida_hexrays.cblock_t):
        return _process_block_seq(cfunc, node, debug)
    if isinstance(node, ida_hexrays.cinsn_t):
        if node.op == ida_hexrays.cit_block and node.cblock:
            return _process_block_seq(cfunc, node.cblock, debug)
        tmp = ida_hexrays.cblock_t()
        tmp.push_back(node)
        return _process_block_seq(cfunc, tmp, debug)
    return 0

def _process_block_seq(cfunc: ida_hexrays.cfunc_t, blk: ida_hexrays.cblock_t, debug: bool=False) -> int:
    changed = 0
    i = 0
    n = blk.size()
    while i < n:
        insn = blk[i]
        op = insn.op

        # 递归进入子语句
        if op == ida_hexrays.cit_block and insn.cblock:
            changed += _process_any(cfunc, insn.cblock, debug)
        elif op == ida_hexrays.cit_if:
            if insn.cif.ithen: changed += _process_any(cfunc, insn.cif.ithen, debug)
            if insn.cif.ielse: changed += _process_any(cfunc, insn.cif.ielse, debug)
        elif op == ida_hexrays.cit_for:
            if insn.cfor.body: changed += _process_any(cfunc, insn.cfor.body, debug)
        elif op == ida_hexrays.cit_while:
            if insn.cwhile.body: changed += _process_any(cfunc, insn.cwhile.body, debug)
        elif op == ida_hexrays.cit_do:
            if insn.cdo.body: changed += _process_any(cfunc, insn.cdo.body, debug)
        elif op == ida_hexrays.cit_switch:
            if insn.cswitch.body: changed += _process_any(cfunc, insn.cswitch.body, debug)

        # 查找 “x = alloca(...)”，并尝试与下一条赋值配对
        if op == ida_hexrays.cit_expr:
            e = insn.cexpr
            if e.op == ida_hexrays.cot_asg and e.x.op == ida_hexrays.cot_var and _is_alloca_call(e.y):
                alloca_lvar = e.x.v
                if debug:
                    idc.msg("[alloca] at 0x%X -> %s\n" % (e.ea, getattr(alloca_lvar, "name", "lvar")))
                j = i + 1
                if j < n:
                    nxt = blk[j]
                    if nxt.op == ida_hexrays.cit_expr and nxt.cexpr.op == ida_hexrays.cot_asg:
                        try:
                            _replace_rhs_with_lvar(nxt.cexpr.y, alloca_lvar)
                            changed += 1
                            if debug:
                                idc.msg("  -> replace RHS at 0x%X\n" % (nxt.cexpr.ea,))
                            i = j  # 跳过已配对的下一条
                        except Exception as ex:
                            idc.msg("[alloca-fix] replace failed at 0x%X: %s\n" % (nxt.cexpr.ea, ex))

        i += 1
    return changed

def fix_cfunc(cfunc: ida_hexrays.cfunc_t, debug: bool=False) -> int:
    changed = _process_any(cfunc, cfunc.body, debug=debug)
    if changed:
        cfunc.refresh_func_ctext()
        try:
            ida_hexrays.mark_cfunc_dirty(cfunc.func_ea)
        except Exception:
            pass
    return changed

def fix_function(ea: int, require_badstack: bool=True, debug: bool=False) -> int:
    f = ida_funcs.get_func(ea)
    if not f:
        idc.msg("[alloca-fix] 0x%X: not in a function\n" % ea)
        return 0
    if require_badstack and not function_has_badstack(f):
        idc.msg("[alloca-fix] skip %s: no PR_BADSTACK\n" % ida_funcs.get_func_name(f.start_ea))
        return 0
    try:
        cfunc = ida_hexrays.decompile(f.start_ea)
    except ida_hexrays.DecompilationFailure:
        idc.msg("[alloca-fix] decompile failed at 0x%X\n" % f.start_ea)
        return 0
    n = fix_cfunc(cfunc, debug=debug)
    idc.msg("[alloca-fix] %s: sequence replacements = %d\n" %
            (ida_funcs.get_func_name(f.start_ea), n))
    return n

# ===== 5) 主流程：逐函数修正（若 PR_BADSTACK）并导出 =====
result: dict[str, dict[str, str]] = {}

for func_name in FUNC_NAMES:
    func_ea = idc.get_name_ea_simple(func_name)
    if func_ea == idc.BADADDR:
        idc.msg(f"[!] 未找到函数 '{func_name}'，跳过\n")
        continue

    f = ida_funcs.get_func(func_ea)
    if not f:
        idc.msg(f"[!] 获取函数对象 '{func_name}' 失败，跳过\n")
        continue

    # 5-0) 若存在 PR_BADSTACK，先尝试修正（require_badstack=True）
    try:
        if function_has_badstack(f):
            idc.msg(f"[*] 检测到 PR_BADSTACK: {func_name}，执行 alloca 修正...\n")
            fix_function(func_ea, require_badstack=True, debug=False)
        else:
            idc.msg(f"[*] 无 PR_BADSTACK: {func_name}，直接导出\n")
    except Exception as _ex:
        idc.msg(f"[!] 检测/修正 PR_BADSTACK 时异常: {func_name} -> {_ex}\n")

    # 5-1) 导出“原始反汇编”（仅指令，不含 label）
    dis_lines: list[str] = [
        idc.GetDisasm(ea) for ea in idautils.Heads(f.start_ea, f.end_ea) if is_code(ea)
    ]
    disasm_text = "\n".join(dis_lines)

    # 5-2) 导出伪代码（修正后再反编译）
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        pcode_lines = [ida_lines.tag_remove(sline.line) for sline in cfunc.get_pseudocode()]
        pcode_text = "\n".join(pcode_lines)
    except ida_hexrays.DecompilationFailure as e:
        idc.msg(f"[!] 反编译 '{func_name}' 失败: {e}\n")
        cfunc = None
        pcode_text = ""

    # 5-3) 生成“增强汇编”（需要成功拿到 cfunc）
    if cfunc:
        try:
            disasm_enhanced = make_enhanced_disasm_for_func(f, cfunc)
        except Exception as ee:
            idc.msg(f"[!] 生成增强汇编 '{func_name}' 失败: {ee}\n")
            disasm_enhanced = ""
    else:
        disasm_enhanced = ""

    # 5-4) 收集结果
    result[func_name] = {
        "pcode": pcode_text,
        "disasm": disasm_text,
        "disasm_enhanced": disasm_enhanced,
    }

# ===== 6) 写出 JSON 并退出 =====
out_path = "func_dis.json"
try:
    with open(out_path, "w", encoding="utf-8") as fp:
        json.dump(result, fp, ensure_ascii=False, indent=2)
    idc.msg(f"[*] 结果已保存至 {out_path}\n")
except Exception as err:
    fallback = os.path.join(os.getcwd(), "func_dis.json")
    with open(fallback, "w", encoding="utf-8") as fp:
        json.dump(result, fp, ensure_ascii=False, indent=2)
    idc.msg(f"[!] 写入 {out_path} 失败({err})，已改存 {fallback}\n")

idaapi.qexit(0)

#./ida -A -L"output.log" -S"/home/workspace/ida_util/analysis_init/dump_dis_v3.py funcs_list=CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_loop_01_bad" /home/workspace/jc/t1/CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_loop_01-bad
#./ida -A -L"output.log" -S"/home/workspace/ida_util/analysis_init/dump_dis_v3.py funcs_list=CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_memcpy_11_bad" /home/workspace/jc/t1/CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_memcpy_11-bad