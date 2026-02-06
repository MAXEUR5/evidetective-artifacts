# -*- coding: utf-8 -*-
"""
适用版本 : IDA Pro / IDA Home 9.1 及以后

脚本参数:
    funcs_list=[main,func1]       # 列表形式, 多个函数
    或
    funcs_list=main               # 单个函数
    }
"""

import json
import os
import idaapi
import idc
import idautils
import ida_funcs
import ida_lines
import ida_auto

# ---------- 0. 等待自动分析完成 ----------
if callable(getattr(idaapi, "auto_wait", None)):
    idaapi.auto_wait()
ida_auto.auto_wait()
# ---------- 1. 解析 funcs_list ----------
def parse_funcs_from_argv() -> list[str]:
    """
    从 idc.ARGV 中提取 'funcs_list=' 参数，并返回函数名列表。
    完全不依赖正则表达式，仅做简单字符串处理。
    """
    for arg in idc.ARGV[1:]:                 # ARGV[0] 是脚本路径
        if arg.startswith("funcs_list="):
            value = arg.partition("=")[2].strip()
            # 列表形式: [main,func1] 或 [  main , func1 ]
            if value.startswith("[") and value.endswith("]"):
                raw_items = value[1:-1].split(",")
                return [item.strip() for item in raw_items if item.strip()]
            # 单个函数
            return [value]
    # 未找到参数, 直接退出
    idc.warning("未检测到参数 funcs_list=...，脚本退出")
    idaapi.qexit(1)

FUNC_NAMES: list[str] = parse_funcs_from_argv()
idc.msg(f"[*] 解析到函数列表: {FUNC_NAMES}\n")

# ---------- 2. 确保 Hex-Rays 反编译器可用 ----------
try:
    import ida_hexrays
    if not ida_hexrays.init_hexrays_plugin():
        idc.warning("Hex-Rays 反编译器未激活，无法导出 pcode")
        idaapi.qexit(1)
except Exception as e:
    idc.warning(f"加载 Hex-Rays 失败: {e}")
    idaapi.qexit(1)

# ---------- 3. 主流程 ----------
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

    # 3-1. 导出反汇编
    dis_lines: list[str] = [
        idc.GetDisasm(ea) for ea in idautils.Heads(f.start_ea, f.end_ea)
    ]
    disasm_text = "\n".join(dis_lines)

    # 3-2. 导出伪代码
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        pcode_lines = [
            ida_lines.tag_remove(sline.line) for sline in cfunc.get_pseudocode()
        ]
        pcode_text = "\n".join(pcode_lines)
    except ida_hexrays.DecompilationFailure as e:
        idc.msg(f"[!] 反编译 '{func_name}' 失败: {e}\n")
        pcode_text = ""

    # 3-3. 收集结果
    result[func_name] = {"pcode": pcode_text, "disasm": disasm_text}

# ---------- 4. 写入 JSON ----------
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

# ---------- 5. 结束 ----------
idaapi.qexit(0)

# ./ida -A -L"output.log" -S"/home/workspace/ida_util/analysis_init/dump_dis.py funcs_list=main" /home/workspace/Testcase/test3/vuln_n