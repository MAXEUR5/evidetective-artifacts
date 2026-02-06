# global_find_v5.py
# -*- coding: utf-8 -*-
"""
IDA 9.1 / IDAPython
在原有“全局变量引用分析”的基础上，新增：
- 为每个全局变量推导类型（type）
- 为每个全局变量估计尺寸（size_bytes）
  * 优先使用 tinfo
  * 字符串使用字符串专用 API（max_strlit_length / get_strlit_contents）
  * 数组尝试 array_type_data_t 细节
  * 最后退回 item 边界估算
- 新增：提取全局变量的初始值（init_value）
  * 字符串：get_strlit_contents 解码
  * 标量（<=8 bytes）：按端序解析为 int；float/double 解析为浮点
  * 未初始化（如 .bss）："uninitialized"
  * 其他/大对象：输出 hex（过大时截断）

若无法确定，类型为 'undefined'，尺寸为 'unknown'。
输出文件：global_var_ctree_refs.json
"""

import json
import struct

import idaapi
import idc
import idautils
import ida_bytes
import ida_funcs
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


def collect_global_variables():
    """粗略收集所有可能的全局变量地址。"""
    gvars = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg:
            continue
        for head_ea in idautils.Heads(seg.start_ea, seg.end_ea):
            if is_data_candidate(head_ea):
                gvars.append(head_ea)
    return gvars


# ------------------------------------------------------------
# 尺寸与类型推导（稳健版）
# ------------------------------------------------------------
def _get_string_size_bytes(ea):
    """
    针对字符串的专用尺寸估算：
    1) 若已实体化为 STRLIT，item_size 通常可用
    2) 用 get_max_strlit_length / get_strlit_contents 估算
    3) 仍失败则在段内扫描到第一个 0x00...0 终止
    返回 int 或 None
    """
    # 1) 已有 item 尺寸
    try:
        sz = ida_bytes.get_item_size(ea)
        if isinstance(sz, int) and sz > 0:
            return sz
    except Exception:
        pass

    # 2) 字符串 API
    try:
        st = ida_nalt.get_str_type(ea)
        if st is not None and st != -1:
            # 2a) 直接取最大长度（通常包含结尾 0）
            try:
                mlen = ida_bytes.get_max_strlit_length(ea, st)
                if isinstance(mlen, int) and mlen > 0:
                    return mlen
            except Exception:
                pass
            # 2b) 取内容长度（len=0 -> 自动使用最大长度）
            data = ida_bytes.get_strlit_contents(ea, 0, st)
            if data:
                if isinstance(data, (bytes, bytearray)):
                    return len(data)
                else:
                    # 极端情况下 data 是 str；尽量给出保守字节估计
                    bpu = ida_nalt.get_strtype_bpu(st) or 1
                    return len(str(data)) * bpu
    except Exception:
        pass

    # 3) 扫描段内，找终止符（按 BPU 构造 0 序列）
    seg = idaapi.getseg(ea)
    if not seg:
        return None
    try:
        st = ida_nalt.get_str_type(ea)
        bpu = ida_nalt.get_strtype_bpu(st) if st is not None and st != -1 else 1
    except Exception:
        bpu = 1

    max_scan = min(0x10000, seg.end_ea - ea)  # 防御性上限
    blob = ida_bytes.get_bytes(ea, max_scan) or b""
    term = b"\x00" * max(1, bpu)
    pos = blob.find(term)
    if pos != -1:
        return pos + len(term)

    return None


def _get_array_size_from_tinfo_or_bounds(ea, tif):
    """
    当 tinfo 表示数组，但元素数未知时，尝试：
    - 读取数组细节（元素大小 * 元素数）
    - 退回用 item 边界估算
    返回 int 或 None
    """
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
    """当无 tinfo 且非字符串时，基于 flags 的宽松类型名称。"""
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
    """
    返回 (type_str, size_bytes)
    - type_str: 例如 "const char[]", "uint32_t", "struct /*unnamed*/"；
                无法推导则返回 "undefined"
    - size_bytes: int；无法获取则返回 "unknown"
    """
    tif = ida_typeinf.tinfo_t()
    has_ti = False
    try:
        has_ti = ida_nalt.get_tinfo(tif, var_ea)
    except Exception:
        has_ti = False

    # ---------- 类型字符串 ----------
    type_str = None
    if has_ti:
        try:
            type_str = tif.dstr() or idc.get_type(var_ea)
        except Exception:
            type_str = idc.get_type(var_ea)
    if not type_str:
        flags = ida_bytes.get_full_flags(var_ea)
        if ida_bytes.is_strlit(flags):
            # 基于字符宽度选择 base 类型名
            try:
                st = ida_nalt.get_str_type(var_ea)
                bpu = ida_nalt.get_strtype_bpu(st) if st not in (None, -1) else 1
            except Exception:
                bpu = 1
            if bpu == 1:
                base = "char"
            elif bpu == 2:
                base = "char16_t"   # 如需 Windows 语义可改 "wchar_t"
            elif bpu == 4:
                base = "char32_t"
            else:
                base = "char"
            seg = idaapi.getseg(var_ea)
            is_const = bool(seg and not (seg.perm & idaapi.SEGPERM_WRITE))
            type_str = ("const " if is_const else "") + f"{base}[]"
        else:
            type_str = _type_from_flags(flags)

    # ---------- 尺寸 ----------
    flags = ida_bytes.get_full_flags(var_ea)

    # A) 若为字符串，走字符串专用通道
    if ida_bytes.is_strlit(flags):
        sz = _get_string_size_bytes(var_ea)
        return (type_str or "const char[]",
                sz if isinstance(sz, int) and sz > 0 else "unknown")

    # B) 非字符串，优先 tinfo.get_size()
    if has_ti:
        try:
            sz = tif.get_size()
            if isinstance(sz, int) and sz > 0:
                return (type_str or "undefined", sz)
        except Exception:
            pass

        # tinfo 是数组但大小拿不到 -> 读数组细节或退回边界估算
        sz = _get_array_size_from_tinfo_or_bounds(var_ea, tif)
        if isinstance(sz, int) and sz > 0:
            return (type_str or "undefined", sz)

    # C) 最终：通用 item 边界
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
# 新增：初始值提取
# ------------------------------------------------------------
def _safe_get_db_bytes(ea, size):
    """
    统一封装 idc.get_bytes 的返回，尽量得到 bytes 或 None。
    """
    try:
        data = idc.get_bytes(ea, size, False)
    except TypeError:
        # 兼容某些环境下没有 use_dbg 形参的情况
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
        # 把 0x00-0xFF 按 latin-1 映射回字节（更接近“原始字节串”的语义）
        try:
            return data.encode("latin-1", errors="ignore")
        except Exception:
            return None

    try:
        return bytes(data)
    except Exception:
        return None


def deduce_init_value(var_ea, type_str, size_bytes):
    """
    返回可 JSON 序列化的 init_value：
    - 字符串：返回解码后的 str
    - 标量（<=8 bytes）：返回 int / float
    - 未初始化：返回 "uninitialized"
    - 其他：返回 "0x..." hex 字符串（过大时截断）
    """
    flags = ida_bytes.get_full_flags(var_ea)

    # 1) 字符串（.rodata/.data 的字符串字面量）
    if ida_bytes.is_strlit(flags):
        # 优先用 strlit API（能处理 UTF-16 等，返回 UTF-8 编码的 codepoints）
        try:
            st = ida_nalt.get_str_type(var_ea)
            if st not in (None, -1):
                raw = ida_bytes.get_strlit_contents(var_ea, 0, st)
                if raw:
                    if isinstance(raw, str):
                        # 极少数情况下 raw 可能是 str；保守处理
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

        # 兜底：按估算长度读原始字节再解码
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

    # 2) 非字符串：先确定 size
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

    # 3) 未初始化（例如 .bss）：优先判断 is_loaded/has_value
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

    # 4) float/double（仅在 size 匹配时解析）
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

    # 5) 标量（<=8 bytes）：按端序转 int
    if size_bytes <= 8:
        b = _safe_get_db_bytes(var_ea, size_bytes)
        if b and len(b) == size_bytes:
            try:
                v = int.from_bytes(b, endian_name, signed=False)
                ts = type_str or ""
                # 指针/ptr 类型：返回更直观的 0x... 字符串
                if (("*" in ts) or ("ptr" in ts.lower())) and size_bytes in (4, 8):
                    return "0x{:X}".format(v)
                return v
            except Exception:
                pass

    # 6) 其他：输出 hex（防止 JSON 过大，设置上限）
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
# 反编译 ctree 中查找对某个全局地址的引用
# ------------------------------------------------------------
def visit_cfunc_for_var(cfunc, var_ea):
    """
    在给定 cfunc 的 ctree 中查找对 var_ea 的所有引用。
    返回形如 [ (ref_ea1, line_num1), (ref_ea2, line_num2), ... ]
    """
    references = []
    if not cfunc:
        return references

    # 预热：生成伪代码文本，以便后续定位行号
    _ = cfunc.get_pseudocode()

    class VarRefVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            # e.op == cot_obj => 引用了某个全局/局部对象；e.obj_ea 为其地址
            if e.op == ida_hexrays.cot_obj and e.obj_ea == var_ea:
                line_num = None
                ea_int = e.ea
                try:
                    col, row = cfunc.find_item_coords(e)
                    if row >= 0:
                        line_num = row + 1  # 行号从 1 开始
                except Exception:
                    pass
                references.append((ea_int, line_num))
            return 0

    mv = VarRefVisitor()
    mv.apply_to(cfunc.body, None)
    return references


# ------------------------------------------------------------
# 主逻辑
# ------------------------------------------------------------
def main():
    # 初始化 Hex-Rays 反编译器
    if not ida_hexrays.init_hexrays_plugin():
        print("No decompiler available!")
        return

    # 收集候选全局变量 & 全部函数入口
    gvars = collect_global_variables()
    all_func_starts = [f for f in idautils.Functions()]

    result_dict = {}

    for var_ea in gvars:
        seg = idaapi.getseg(var_ea)
        if not seg:
            continue

        var_name = idc.get_name(var_ea) or "unnamed_global"
        var_rwx = get_segment_rwx(seg)

        # 类型与尺寸推导
        deduced_type, size_bytes = deduce_type_and_size(var_ea)

        # 新增：初始值提取（init_value）
        init_value = deduce_init_value(var_ea, deduced_type, size_bytes)

        # 在所有函数中查找引用
        references = []
        for f_ea in all_func_starts:
            # 反编译函数（容错）
            try:
                cfunc = ida_hexrays.decompile(f_ea)
            except Exception:
                cfunc = None
            if not cfunc:
                continue

            refs_in_func = visit_cfunc_for_var(cfunc, var_ea)
            if not refs_in_func:
                continue

            func_name = idaapi.get_name(f_ea) or ""
            for (ref_ea, line_num) in refs_in_func:
                ref_ea_str = "0x{:X}".format(ref_ea) if ref_ea != BADADDR else None
                references.append({
                    "function_name": func_name,
                    "function_ea": "0x{:X}".format(f_ea),
                    "ref_ea": ref_ea_str,
                    "decompiled_line": line_num
                })

        # 仅记录确有引用的全局
        if references:
            var_key = "0x{:X}".format(var_ea)
            result_dict[var_key] = {
                "name": var_name,
                "segment_rwx": var_rwx,
                "type": deduced_type,
                "size_bytes": size_bytes,
                "init_value": init_value,
                "references": references
            }

    # 导出 JSON
    out_file = "global_var_ctree_refs.json"
    with open(out_file, "w", encoding="utf-8") as fp:
        json.dump(result_dict, fp, ensure_ascii=False, indent=2)

    idc.msg("Analysis done. Results saved to: {}\n".format(out_file))


# ------------------------------------------------------------
# 静默模式启动：等待分析完毕后执行脚本并退出
# ------------------------------------------------------------
if __name__ == '__main__':
    idc.auto_wait()
    main()
    idaapi.qexit(0)
