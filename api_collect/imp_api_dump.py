# -*- coding: utf-8 -*-

import idaapi # type: ignore
import ida_nalt # type: ignore
import idc # type: ignore
import ida_typeinf # type: ignore

import json

imports_data = []          # [(lib, func, proto), ...]

def _get_func_proto(ea: int, func_name: str) -> str:

    proto = idc.get_type(ea)
    if proto:
        return proto

    tif = ida_typeinf.tinfo_t()
    get_tinfo_fn = getattr(ida_typeinf, 'get_tinfo', None) \
                   or getattr(idaapi, 'get_tinfo', None)

    if get_tinfo_fn and get_tinfo_fn(tif, ea):
        pr_def   = getattr(ida_typeinf, 'PRTYPE_DEF',   0x01)
        pr_1line = getattr(ida_typeinf, 'PRTYPE_1LINE', 0x02)
        proto = ida_typeinf.print_tinfo(
            '', 0, 0, pr_def | pr_1line, tif, func_name, ''
        )
        return proto or ''

    return ''


def imp_cb(ea: int, func_name: str, ordinal: int) -> bool:

    if func_name:
        proto = _get_func_proto(ea, func_name)
        imports_data.append((current_module, func_name, proto))
    return True


def main():
    global current_module

    mod_qty = ida_nalt.get_import_module_qty()
    if mod_qty == 0:
        print("[-] No import modules detected, exiting script.")
        idaapi.qexit(0)
        return

    print(f"[+] Detected {mod_qty} import modules, starting enumeration...")

    for i in range(mod_qty):
        current_module = ida_nalt.get_import_module_name(i) or f"unknown_module_{i}"
        ida_nalt.enum_import_names(i, imp_cb)

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

    json_data = [
        {"lib": lib, "func": func, "proto": proto}
        for lib, func, proto in processed
    ]
    out_file = "import_api_with_proto.json"
    with open(out_file, "w", encoding="utf-8") as fp:
        json.dump(json_data, fp, indent=2, ensure_ascii=False)

    print(f"[+] Exported {len(json_data)} records → {out_file}")
    idaapi.qexit(0)


if __name__ == "__main__":
    main()
#./ida.exe -A -L"output.log" -S"E:\ida_util\analysis_init\imp_api_dump.py" E:\vuln_test\test_n1\vuln