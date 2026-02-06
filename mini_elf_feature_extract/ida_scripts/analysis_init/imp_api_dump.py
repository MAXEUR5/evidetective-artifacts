# -*- coding: utf-8 -*-
"""
export_imports_with_prototype.py
适用：IDA 9.1 及向下兼容若干版本 (Python 3.x)

功能：
  - 枚举所有导入函数
  - 采集 (库名, 函数名, 函数原型) 三元组
  - 智能处理 '.dynsym' 拆分
  - 导出 JSON：import_api_with_proto.json
"""
import idaapi # type: ignore
import ida_nalt # type: ignore
import idc # type: ignore
import ida_typeinf # type: ignore

import json

imports_data = []          # [(lib, func, proto), ...]

def _get_func_proto(ea: int, func_name: str) -> str:
    """
    获取 EA 对应的函数原型字符串，跨版本兼容：
      1. 先用 idc.get_type()
      2. 再尝试 ida_typeinf / idaapi.get_tinfo()
    """
    # ——方案 1：最快——
    proto = idc.get_type(ea)
    if proto:
        return proto

    # ——方案 2：跨版本探测——
    tif = ida_typeinf.tinfo_t()
    get_tinfo_fn = getattr(ida_typeinf, 'get_tinfo', None) \
                   or getattr(idaapi, 'get_tinfo', None)

    if get_tinfo_fn and get_tinfo_fn(tif, ea):
        # 打印选项：PRTYPE_DEF(0x01) | PRTYPE_1LINE(0x02)
        pr_def   = getattr(ida_typeinf, 'PRTYPE_DEF',   0x01)
        pr_1line = getattr(ida_typeinf, 'PRTYPE_1LINE', 0x02)
        proto = ida_typeinf.print_tinfo(
            '', 0, 0, pr_def | pr_1line, tif, func_name, ''
        )
        return proto or ''

    # ——兜底：返回空串——
    return ''


def imp_cb(ea: int, func_name: str, ordinal: int) -> bool:
    """enum_import_names() 的回调：采集导入信息"""
    if func_name:
        proto = _get_func_proto(ea, func_name)
        imports_data.append((current_module, func_name, proto))
    return True   # 继续枚举


def main():
    global current_module

    mod_qty = ida_nalt.get_import_module_qty()
    if mod_qty == 0:
        print("[-] 未检测到任何导入模块，脚本结束。")
        idaapi.qexit(0)
        return

    print(f"[+] 检测到 {mod_qty} 个导入模块，开始遍历……")

    for i in range(mod_qty):
        current_module = ida_nalt.get_import_module_name(i) or f"unknown_module_{i}"
        ida_nalt.enum_import_names(i, imp_cb)

    # ——后处理 '.dynsym'——
    processed = []
    for lib, func, proto in imports_data:
        if lib == '.dynsym':
            if "@@" in func:
                name_part, lib_part = func.split("@@", 1)
                processed.append((lib_part, name_part, proto))
            else:
                processed.append(('dynsym', func.split("@@")[0], proto))
        else:
            processed.append((lib, func, proto))

    # ——序列化——
    json_data = [
        {"lib": lib, "func": func, "proto": proto}
        for lib, func, proto in processed
    ]
    out_file = "import_api_with_proto.json"
    with open(out_file, "w", encoding="utf-8") as fp:
        json.dump(json_data, fp, indent=2, ensure_ascii=False)

    print(f"[+] 共导出 {len(json_data)} 条记录 → {out_file}")
    idaapi.qexit(0)


if __name__ == "__main__":
    main()
#./ida.exe -A -L"output.log" -S"E:\ida_util\analysis_init\imp_api_dump.py" E:\vuln_test\test_n1\vuln