# global_find_v3_ctree_only.py
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

若无法确定，类型为 'undefined'，尺寸为 'unknown'。
输出文件：global_var_ctree_refs.json
"""

import json

import idaapi
import idc
import idautils
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_typeinf
import ida_nalt

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

        # 新增：类型与尺寸推导
        deduced_type, size_bytes = deduce_type_and_size(var_ea)

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