# global_find_v5_fast.py
# -*- coding: utf-8 -*-
"""
IDA 9.1 / IDAPython

优化版：先判定“是否存在引用”，再对被引用的全局变量进行耗时推断（type/size/init_value）。
核心优化：每个函数只反编译一次，在 ctree 中收集所有 cot_obj 的 obj_ea。

输出文件：global_var_ctree_refs.json
"""

import json
import struct

import idaapi
import idc
import idautils
import ida_bytes
import ida_hexrays
import ida_typeinf
import ida_nalt
import ida_ida

BADADDR = idaapi.BADADDR


# ------------------------------------------------------------
# 基础工具
# ------------------------------------------------------------
def get_segment_rwx(seg):
    perms = []
    if seg.perm & idaapi.SEGPERM_READ:
        perms.append('R')
    if seg.perm & idaapi.SEGPERM_WRITE:
        perms.append('W')
    if seg.perm & idaapi.SEGPERM_EXEC:
        perms.append('X')
    return "".join(perms)


def is_data_candidate(ea):
    """
    识别可作为全局变量候选的地址：
    - 必须是数据项
    - 排除可执行段
    """
    flags = ida_bytes.get_full_flags(ea)
    if not ida_bytes.is_data(flags):
        return False
    seg = idaapi.getseg(ea)
    if not seg:
        return False
    if seg.perm & idaapi.SEGPERM_EXEC:
        return False
    return True


# ------------------------------------------------------------
# 尺寸与类型推导（沿用你的实现）
# ------------------------------------------------------------
def _get_string_size_bytes(ea):
    # 1) item_size
    try:
        sz = ida_bytes.get_item_size(ea)
        if isinstance(sz, int) and sz > 0:
            return sz
    except Exception:
        pass

    # 2) string API
    try:
        st = ida_nalt.get_str_type(ea)
        if st is not None and st != -1:
            try:
                mlen = ida_bytes.get_max_strlit_length(ea, st)
                if isinstance(mlen, int) and mlen > 0:
                    return mlen
            except Exception:
                pass
            data = ida_bytes.get_strlit_contents(ea, 0, st)
            if data:
                if isinstance(data, (bytes, bytearray)):
                    return len(data)
                else:
                    bpu = ida_nalt.get_strtype_bpu(st) or 1
                    return len(str(data)) * bpu
    except Exception:
        pass

    # 3) scan in segment for terminator
    seg = idaapi.getseg(ea)
    if not seg:
        return None
    try:
        st = ida_nalt.get_str_type(ea)
        bpu = ida_nalt.get_strtype_bpu(st) if st is not None and st != -1 else 1
    except Exception:
        bpu = 1

    max_scan = min(0x10000, seg.end_ea - ea)
    blob = ida_bytes.get_bytes(ea, max_scan) or b""
    term = b"\x00" * max(1, bpu)
    pos = blob.find(term)
    if pos != -1:
        return pos + len(term)
    return None


def _get_array_size_from_tinfo_or_bounds(ea, tif):
    try:
        if tif and tif.is_array():
            atd = ida_typeinf.array_type_data_t()
            if tif.get_array_details(atd):
                esz = atd.elem_tinfo.get_size()
                if (isinstance(esz, int) and esz > 0) and atd.nelems > 0:
                    return esz * atd.nelems
    except Exception:
        pass

    try:
        head = ida_bytes.get_item_head(ea)
        end = ida_bytes.get_item_end(ea)
        if end > head:
            return end - head
    except Exception:
        pass

    return None


def _type_from_flags(flags):
    if ida_bytes.is_byte(flags):
        return "uint8_t"
    if ida_bytes.is_word(flags):
        return "uint16_t"
    if ida_bytes.is_dword(flags):
        return "uint32_t"
    if ida_bytes.is_qword(flags):
        return "uint64_t"
    try:
        if ida_bytes.is_oword(flags):
            return "__int128"
    except Exception:
        pass
    if ida_bytes.is_float(flags):
        return "float"
    if ida_bytes.is_double(flags):
        return "double"
    if ida_bytes.is_struct(flags):
        return "struct /*unnamed*/"
    return "data"


def deduce_type_and_size(var_ea):
    tif = ida_typeinf.tinfo_t()
    has_ti = False
    try:
        has_ti = ida_nalt.get_tinfo(tif, var_ea)
    except Exception:
        has_ti = False

    # type string
    type_str = None
    if has_ti:
        try:
            type_str = tif.dstr() or idc.get_type(var_ea)
        except Exception:
            type_str = idc.get_type(var_ea)

    if not type_str:
        flags = ida_bytes.get_full_flags(var_ea)
        if ida_bytes.is_strlit(flags):
            try:
                st = ida_nalt.get_str_type(var_ea)
                bpu = ida_nalt.get_strtype_bpu(st) if st not in (None, -1) else 1
            except Exception:
                bpu = 1
            if bpu == 1:
                base = "char"
            elif bpu == 2:
                base = "char16_t"
            elif bpu == 4:
                base = "char32_t"
            else:
                base = "char"
            seg = idaapi.getseg(var_ea)
            is_const = bool(seg and not (seg.perm & idaapi.SEGPERM_WRITE))
            type_str = ("const " if is_const else "") + f"{base}[]"
        else:
            type_str = _type_from_flags(flags)

    # size
    flags = ida_bytes.get_full_flags(var_ea)

    # A) string
    if ida_bytes.is_strlit(flags):
        sz = _get_string_size_bytes(var_ea)
        return (type_str or "const char[]",
                sz if isinstance(sz, int) and sz > 0 else "unknown")

    # B) tinfo size
    if has_ti:
        try:
            sz = tif.get_size()
            if isinstance(sz, int) and sz > 0:
                return (type_str or "undefined", sz)
        except Exception:
            pass

        sz = _get_array_size_from_tinfo_or_bounds(var_ea, tif)
        if isinstance(sz, int) and sz > 0:
            return (type_str or "undefined", sz)

    # C) item bounds
    try:
        head = ida_bytes.get_item_head(var_ea)
        end = ida_bytes.get_item_end(var_ea)
        sz = end - head
        if isinstance(sz, int) and sz > 0:
            return (type_str or "undefined", sz)
    except Exception:
        pass

    return (type_str or "undefined", "unknown")


# ------------------------------------------------------------
# init_value（沿用你的实现）
# ------------------------------------------------------------
def _safe_get_db_bytes(ea, size):
    try:
        data = idc.get_bytes(ea, size, False)
    except TypeError:
        try:
            data = idc.get_bytes(ea, size)
        except Exception:
            data = None
    except Exception:
        data = None

    if data is None:
        return None

    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    if isinstance(data, str):
        try:
            return data.encode("latin-1", errors="ignore")
        except Exception:
            return None

    try:
        return bytes(data)
    except Exception:
        return None


def deduce_init_value(var_ea, type_str, size_bytes):
    flags = ida_bytes.get_full_flags(var_ea)

    # 1) string
    if ida_bytes.is_strlit(flags):
        try:
            st = ida_nalt.get_str_type(var_ea)
            if st not in (None, -1):
                raw = ida_bytes.get_strlit_contents(var_ea, 0, st)
                if raw:
                    if isinstance(raw, str):
                        raw = raw.encode("utf-8", errors="replace")
                    else:
                        raw = bytes(raw)
                    raw = raw.rstrip(b"\x00")
                    try:
                        return raw.decode("utf-8", errors="replace")
                    except Exception:
                        return raw.decode("latin-1", errors="replace")
        except Exception:
            pass

        try:
            sz = _get_string_size_bytes(var_ea)
            if isinstance(sz, int) and sz > 0:
                b = _safe_get_db_bytes(var_ea, sz)
                if b:
                    b = b.rstrip(b"\x00")
                    try:
                        return b.decode("utf-8", errors="replace")
                    except Exception:
                        return b.decode("latin-1", errors="replace")
        except Exception:
            pass

        return ""

    # 2) ensure size
    if not isinstance(size_bytes, int) or size_bytes <= 0:
        try:
            head = ida_bytes.get_item_head(var_ea)
            end = ida_bytes.get_item_end(var_ea)
            if end > head:
                size_bytes = end - head
        except Exception:
            size_bytes = None

    if not isinstance(size_bytes, int) or size_bytes <= 0:
        return "unknown"

    # 3) uninitialized
    try:
        if not ida_bytes.is_loaded(var_ea):
            return "uninitialized"
    except Exception:
        pass
    try:
        if not ida_bytes.has_value(ida_bytes.get_full_flags(var_ea)):
            return "uninitialized"
    except Exception:
        pass

    be = False
    try:
        be = bool(ida_ida.inf_is_be())
    except Exception:
        be = False
    endian_prefix = ">" if be else "<"
    endian_name = "big" if be else "little"

    # 4) float/double
    if ida_bytes.is_float(flags) and size_bytes == 4:
        b = _safe_get_db_bytes(var_ea, 4)
        if b and len(b) == 4:
            try:
                return struct.unpack(endian_prefix + "f", b)[0]
            except Exception:
                pass

    if ida_bytes.is_double(flags) and size_bytes == 8:
        b = _safe_get_db_bytes(var_ea, 8)
        if b and len(b) == 8:
            try:
                return struct.unpack(endian_prefix + "d", b)[0]
            except Exception:
                pass

    # 5) scalar int
    if size_bytes <= 8:
        b = _safe_get_db_bytes(var_ea, size_bytes)
        if b and len(b) == size_bytes:
            try:
                v = int.from_bytes(b, endian_name, signed=False)
                ts = type_str or ""
                if (("*" in ts) or ("ptr" in ts.lower())) and size_bytes in (4, 8):
                    return "0x{:X}".format(v)
                return v
            except Exception:
                pass

    # 6) hex dump
    MAX_DUMP = 0x1000
    read_sz = size_bytes if size_bytes <= MAX_DUMP else MAX_DUMP
    b = _safe_get_db_bytes(var_ea, read_sz)
    if not b:
        return "uninitialized"

    hex_body = b.hex()
    if size_bytes > MAX_DUMP:
        return "0x" + hex_body + "...(truncated, total={} bytes)".format(size_bytes)
    return "0x" + hex_body


# ------------------------------------------------------------
# 关键优化：一次反编译一个函数，收集该函数内所有全局引用
# ------------------------------------------------------------
def collect_global_refs_from_cfunc(cfunc):
    """
    返回：list of (obj_ea, ref_ea, line_num)
    - obj_ea: 被引用的全局对象地址（ctree cot_obj 的 obj_ea）
    - ref_ea: 表达式对应的 ea（可能为 BADADDR）
    - line_num: 伪代码行号（从 1 开始），可能为 None
    """
    out = []
    if not cfunc:
        return out

    # 预热伪代码（否则 find_item_coords 不稳定）
    try:
        _ = cfunc.get_pseudocode()
    except Exception:
        pass

    class AllObjVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self, cf):
            super().__init__(ida_hexrays.CV_FAST)
            self.cf = cf

        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_obj:
                obj_ea = e.obj_ea
                ref_ea = e.ea
                line_num = None
                try:
                    col, row = self.cf.find_item_coords(e)
                    if row >= 0:
                        line_num = row + 1
                except Exception:
                    pass
                out.append((obj_ea, ref_ea, line_num))
            return 0

    v = AllObjVisitor(cfunc)
    try:
        v.apply_to(cfunc.body, None)
    except Exception:
        pass
    return out


# ------------------------------------------------------------
# 主逻辑（优化版）

def main():
    if not ida_hexrays.init_hexrays_plugin():
        print("No decompiler available!")
        return

    all_func_starts = list(idautils.Functions())

    # var_ea -> {"references":[...], "name":..., "segment_rwx":...}
    # 先不推断类型/值
    var_map = {}

    # 1) 先跑一遍所有函数（每个函数只反编译一次），收集所有全局引用
    for f_ea in all_func_starts:
        try:
            cfunc = ida_hexrays.decompile(f_ea)
        except Exception:
            cfunc = None
        if not cfunc:
            continue

        func_name = idaapi.get_name(f_ea) or ""

        refs = collect_global_refs_from_cfunc(cfunc)
        if not refs:
            continue

        # （可选但推荐）避免同一函数里同一处反复记录：用集合去重
        # key: (obj_ea, ref_ea, line_num)
        seen = set()

        for (obj_ea, ref_ea, line_num) in refs:
            k = (obj_ea, ref_ea, line_num)
            if k in seen:
                continue
            seen.add(k)

            # 过滤：只保留数据段的全局候选（排除 .text、无效地址、非 data item）
            if obj_ea in (None, BADADDR):
                continue
            if not is_data_candidate(obj_ea):
                continue

            seg = idaapi.getseg(obj_ea)
            if not seg:
                continue

            entry = var_map.get(obj_ea)
            if entry is None:
                var_name = idc.get_name(obj_ea) or "unnamed_global"
                entry = {
                    "name": var_name,
                    "segment_rwx": get_segment_rwx(seg),
                    "references": []
                }
                var_map[obj_ea] = entry

            ref_ea_str = "0x{:X}".format(ref_ea) if ref_ea not in (None, BADADDR) else None
            entry["references"].append({
                "function_name": func_name,
                "function_ea": "0x{:X}".format(f_ea),
                "ref_ea": ref_ea_str,
                "decompiled_line": line_num
            })

    # 2) 只对“确实被引用”的全局变量做耗时推断
    result_dict = {}
    for var_ea, info in var_map.items():
        deduced_type, size_bytes = deduce_type_and_size(var_ea)
        init_value = deduce_init_value(var_ea, deduced_type, size_bytes)

        var_key = "0x{:X}".format(var_ea)
        result_dict[var_key] = {
            "name": info["name"],
            "segment_rwx": info["segment_rwx"],
            "type": deduced_type,
            "size_bytes": size_bytes,
            "init_value": init_value,
            "references": info["references"]
        }

    # 3) 导出 JSON
    out_file = "global_var_ctree_refs.json"
    with open(out_file, "w", encoding="utf-8") as fp:
        json.dump(result_dict, fp, ensure_ascii=False, indent=2)

    idc.msg("Analysis done. Results saved to: {}\n".format(out_file))


if __name__ == '__main__':
    idc.auto_wait()
    main()
    idaapi.qexit(0)
