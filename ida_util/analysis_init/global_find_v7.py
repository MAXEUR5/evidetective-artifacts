# global_find_v5_fast.py
# -*- coding: utf-8 -*-
"""
IDA 9.1 / IDAPython

Optimized global variable reference finder.

Idea:
- First, scan all functions once, decompile each function only once,
  and collect all cot_obj->obj_ea uses from the ctree.
- Only for global variables that are actually referenced, perform
  heavier analysis (type/size/init_value inference).

Output file: global_var_ctree_refs.json
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
import ida_funcs  # for function address detection

BADADDR = idaapi.BADADDR


# ------------------------------------------------------------
# helpers
# ------------------------------------------------------------
def get_segment_rwx(seg):
    perms = []
    if seg.perm & idaapi.SEGPERM_READ:
        perms.append("R")
    if seg.perm & idaapi.SEGPERM_WRITE:
        perms.append("W")
    if seg.perm & idaapi.SEGPERM_EXEC:
        perms.append("X")
    return "".join(perms)


def is_data_candidate(ea):
    """
    Decide whether an address can be treated as a global data candidate:
    - It must be in a non-executable segment.
    - It must not be clearly marked as code.

    We intentionally accept "unknown" and tail items as candidates
    to catch things like _UNKNOWN in .rodata.
    """
    seg = idaapi.getseg(ea)
    if not seg:
        return False

    # exclude executable segments (e.g. .text)
    if seg.perm & idaapi.SEGPERM_EXEC:
        return False

    flags = ida_bytes.get_full_flags(ea)
    if ida_bytes.is_code(flags):
        return False

    return True


# ------------------------------------------------------------
# type and size inference
# ------------------------------------------------------------
def _get_string_size_bytes(ea):
    # 1) item size: only trust size > 1, otherwise a 1-byte item may cut string
    try:
        sz = ida_bytes.get_item_size(ea)
        if isinstance(sz, int) and sz > 1:
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

    flags = ida_bytes.get_full_flags(var_ea)
    seg = idaapi.getseg(var_ea)

    # is tinfo "unknown"?
    unknown_ti = False
    if has_ti:
        try:
            unknown_ti = tif.is_unknown()
        except Exception:
            # some versions may not have is_unknown; fallback to dstr check
            try:
                if tif.dstr() in (None, "", "_UNKNOWN"):
                    unknown_ti = True
            except Exception:
                unknown_ti = False

    # heuristic: readonly & non-exec segment, no meaningful type info, try treat as C string
    if (not has_ti or unknown_ti) and not ida_bytes.is_strlit(flags) and seg:
        if (seg.perm & idaapi.SEGPERM_WRITE) == 0 and (seg.perm & idaapi.SEGPERM_EXEC) == 0:
            sz_guess = None
            try:
                sz_guess = _get_string_size_bytes(var_ea)
            except Exception:
                sz_guess = None

            if isinstance(sz_guess, int) and sz_guess > 1:
                # check if bytes look like ASCII string
                try:
                    b = idc.get_bytes(var_ea, min(sz_guess, 16))
                except Exception:
                    b = None
                if b:
                    if isinstance(b, str):
                        b = b.encode("latin-1", errors="ignore")
                    b = bytes(b)
                    trimmed = b.rstrip(b"\x00")
                    if trimmed:
                        all_printable = True
                        for ch in trimmed:
                            if not (32 <= ch < 127):
                                all_printable = False
                                break
                        if all_printable:
                            # e.g. .rodata:unk_2008 -> type "const char[]", size_bytes = 3
                            return ("const char[]", sz_guess)

    # original type inference
    type_str = None
    if has_ti:
        try:
            type_str = tif.dstr() or idc.get_type(var_ea)
        except Exception:
            type_str = idc.get_type(var_ea)

    if not type_str:
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
            seg2 = idaapi.getseg(var_ea)
            is_const = bool(seg2 and not (seg2.perm & idaapi.SEGPERM_WRITE))
            type_str = ("const " if is_const else "") + f"{base}[]"
        else:
            type_str = _type_from_flags(flags)

    # A) IDA-marked string
    if ida_bytes.is_strlit(flags):
        sz = _get_string_size_bytes(var_ea)
        return (
            type_str or "const char[]",
            sz if isinstance(sz, int) and sz > 0 else "unknown",
        )

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
# init_value inference
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

    # 1) IDA string literal (strlit)
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

    # 1.b) readonly segment, type inferred as char[] / const char[]
    seg = idaapi.getseg(var_ea)
    if seg and (seg.perm & idaapi.SEGPERM_WRITE) == 0:
        if isinstance(type_str, str) and "char" in type_str:
            sz = None
            try:
                sz = _get_string_size_bytes(var_ea)
            except Exception:
                sz = None

            if not (isinstance(sz, int) and sz > 0):
                if isinstance(size_bytes, int) and size_bytes > 0:
                    sz = size_bytes

            if isinstance(sz, int) and sz > 0:
                b = _safe_get_db_bytes(var_ea, sz)
                if b:
                    b = b.rstrip(b"\x00")
                    try:
                        return b.decode("utf-8", errors="replace")
                    except Exception:
                        return b.decode("latin-1", errors="replace")

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

    # 5) scalar int / pointer / function pointer
    if size_bytes <= 8:
        b = _safe_get_db_bytes(var_ea, size_bytes)
        if b and len(b) == size_bytes:
            try:
                v = int.from_bytes(b, endian_name, signed=False)

                # 5.a) check if value is a function entry (function pointer)
                try:
                    f = ida_funcs.get_func(v)
                except Exception:
                    f = None
                if f is not None and f.start_ea == v:
                    func_name = idaapi.get_name(v) or "sub_{:X}".format(v)
                    func_decl = None

                    # try to print full prototype (ret type, cc, args) from tinfo
                    try:
                        func_tif = ida_typeinf.tinfo_t()
                        if ida_nalt.get_tinfo(func_tif, v) and func_tif.is_func():
                            try:
                                pr_flags = (
                                    ida_typeinf.PRTYPE_1LINE
                                    | ida_typeinf.PRTYPE_SEMI
                                )
                                func_decl = ida_typeinf.print_tinfo(
                                    "", 0, 0, pr_flags, func_tif, func_name, ""
                                )
                            except Exception:
                                func_decl = None
                    except Exception:
                        func_decl = None

                    # fallback to idc.get_type if print_tinfo failed
                    if not func_decl:
                        try:
                            t = idc.get_type(v)
                            if t:
                                func_decl = t
                        except Exception:
                            func_decl = None

                    # final fallback: function name only
                    if not func_decl:
                        func_decl = func_name + "(/* unknown */)"

                    # func_decl is usually like:
                    #   unsigned __int64 __fastcall sub_132A(__int64 a1, unsigned int *a2);
                    return "func: {}; addr: 0x{:X}".format(func_decl.strip(), v)

                # 5.b) normal pointer (based on type_str)
                ts = type_str or ""
                if (("*" in ts) or ("ptr" in ts.lower())) and size_bytes in (4, 8):
                    return "0x{:X}".format(v)

                # 5.c) plain integer scalar
                return v
            except Exception:
                pass

    # 6) hex dump for larger or unknown data
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
# ctree traversal: collect all global references per cfunc
# ------------------------------------------------------------
def collect_global_refs_from_cfunc(cfunc):
    """
    Return: list of (obj_ea, ref_ea, line_num)
    - obj_ea: address of the referenced global object (ctree cot_obj->obj_ea)
    - ref_ea: ea of the expression (may be BADADDR)
    - line_num: decompiled line number (1-based), may be None
    """
    out = []
    if not cfunc:
        return out

    # warm up pseudocode, otherwise find_item_coords may be unstable
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
# main logic
# ------------------------------------------------------------
def main():
    if not ida_hexrays.init_hexrays_plugin():
        print("No decompiler available!")
        return

    all_func_starts = list(idautils.Functions())

    # var_ea -> {"references":[...], "name":..., "segment_rwx":...}
    # do not infer type/value yet
    var_map = {}

    # 1) decompile each function once, collect all global references via ctree
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

        # avoid duplicates inside the same function:
        # key: (obj_ea, ref_ea, line_num)
        seen = set()

        for (obj_ea, ref_ea, line_num) in refs:
            k = (obj_ea, ref_ea, line_num)
            if k in seen:
                continue
            seen.add(k)

            # keep only global data candidates (exclude .text/code/invalid)
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
                    "references": [],
                }
                var_map[obj_ea] = entry

            ref_ea_str = "0x{:X}".format(ref_ea) if ref_ea not in (None, BADADDR) else None
            entry["references"].append(
                {
                    "function_name": func_name,
                    "function_ea": "0x{:X}".format(f_ea),
                    "ref_ea": ref_ea_str,
                    "decompiled_line": line_num,
                }
            )

    # 2) perform expensive inference (type/size/init_value) only for globals that are actually referenced
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
            "references": info["references"],
        }

    # 3) export JSON
    out_file = "global_var_ctree_refs.json"
    with open(out_file, "w", encoding="utf-8") as fp:
        json.dump(result_dict, fp, ensure_ascii=False, indent=2)

    idc.msg("Analysis done. Results saved to: {}\n".format(out_file))


if __name__ == "__main__":
    idc.auto_wait()
    main()
    idaapi.qexit(0)
