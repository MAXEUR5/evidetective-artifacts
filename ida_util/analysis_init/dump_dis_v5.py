# -*- coding: utf-8 -*-
"""
dump_dis_v5.py -- IDA 9.1 + Hex-Rays

Exports, for a given function name list:
  - raw disassembly (instructions only)
  - pseudocode
  - enhanced disassembly (labels + nearby pseudocode lines)

Before exporting, if a target function has PR_BADSTACK,
it runs an "alloca-neighbor assignment fix" to improve
both decompilation and eamap accuracy.

New in this version:
  - extra field "demangle_name" per function, which is a
    normalized demangled short name (no return type/params).
  - Hex-Rays level transformation:
        for assignments of the form "lhs = <integer-constant>",
        if the RHS is a pure integer constant > 255, and if its
        minimal big-endian byte representation consists only of
        printable ASCII characters (0x20..0x7E),
        then rewrite its representation to a character literal,
        equivalent to right-clicking the number in the decompiler
        and choosing "Char".

Usage example (Linux):
  ./ida -A -L"output.log" -S"/path/dump_dis_v5.py funcs_list=[goodG2B,bad]" /path/to/binary
"""

from __future__ import annotations

import json
import os
import re
import subprocess  # used as a demangle fallback via c++filt

import idaapi
import idc
import idautils

import ida_auto
import ida_bytes
import ida_funcs
import ida_lines
import ida_name
import ida_ida
import ida_idaapi
import ida_problems

# =========================================================
# 0) Wait for auto-analysis to finish
# =========================================================

if callable(getattr(idaapi, "auto_wait", None)):
    idaapi.auto_wait()
ida_auto.auto_wait()

# =========================================================
# 1) Parse funcs_list argument from idc.ARGV
# =========================================================


def parse_funcs_from_argv() -> list[str]:
    """
    Extract 'funcs_list=' from idc.ARGV and return function name list.

    Format examples:
      funcs_list=foo
      funcs_list=[foo,bar,baz]
    """
    for arg in idc.ARGV[1:]:  # ARGV[0] is script path
        if arg.startswith("funcs_list="):
            value = arg.partition("=")[2].strip()
            if value.startswith("[") and value.endswith("]"):
                raw_items = value[1:-1].split(",")
                return [item.strip() for item in raw_items if item.strip()]
            return [value]
    idc.warning("Parameter 'funcs_list=...' not found, exiting")
    idaapi.qexit(1)


FUNC_NAMES: list[str] = parse_funcs_from_argv()
idc.msg(f"[*] parsed function list: {FUNC_NAMES}\n")

# =========================================================
# 2) Ensure Hex-Rays is available
# =========================================================

try:
    import ida_hexrays

    if not ida_hexrays.init_hexrays_plugin():
        idc.warning("Hex-Rays decompiler is not available, cannot export pseudocode/enhanced disassembly")
        idaapi.qexit(1)
except Exception as e:
    idc.warning(f"Failed to load Hex-Rays: {e}")
    idaapi.qexit(1)

# =========================================================
# 3) Common helpers
# =========================================================


def is_code(ea: int) -> bool:
    return ida_bytes.is_code(ida_bytes.get_full_flags(ea))


def get_disasm_text(ea: int) -> str:
    """
    Return plain disassembly line without IDA tags.
    """
    try:
        s = ida_lines.generate_disasm_line(ea, 0)
        if s:
            return ida_lines.tag_remove(s)
    except Exception:
        pass
    return idc.GetDisasm(ea) or ""


def get_label_at(ea: int, func_start_ea: int) -> str | None:
    """
    Return label text (e.g., 'loc_...:') if any, for enhanced disassembly.
    """
    try:
        name = ida_name.get_name(ea)
    except Exception:
        name = None
    if not name:
        return None
    # If you do not want the function name at function start:
    # if ea == func_start_ea:
    #     return None
    return f"{name}:"


def is_meaningful_pseudoline(text: str) -> bool:
    """
    Filter out purely syntactic lines that do not add much value
    when injected into assembly.
    """
    s = text.strip()
    if not s:
        return False
    if s in ("{", "}"):
        return False
    if s in ("else", "do"):
        return False
    return True


def build_ea_to_pseudorows(cfunc: ida_hexrays.cfunc_t) -> dict[int, list[int]]:
    """
    Build mapping: EA -> list of pseudocode line indexes (y coordinates)
    using the eamap of the cfunc.
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


def make_enhanced_disasm_for_func(f: ida_funcs.func_t, cfunc: ida_hexrays.cfunc_t) -> str:
    """
    Build enhanced disassembly:
      - insert label lines
      - insert pseudocode comments (similar to "Copy to assembly")
      - then output raw instruction lines
    """
    sv = cfunc.get_pseudocode()  # strvec_t
    ea2rows = build_ea_to_pseudorows(cfunc)
    printed_rows: set[int] = set()

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


# =========================================================
# 4) alloca-based PR_BADSTACK fix (only necessary parts)
# =========================================================

ALLOC_NAMES = {
    "alloca",
    "__alloca",
    "_alloca",
    "__chkstk",
    "__chkstk_ms",
    "_chkstk",
    "___chkstk_ms",
    "alloca_probe",
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


def _process_any(cfunc: ida_hexrays.cfunc_t, node, debug: bool = False) -> int:
    """
    Perform "alloca -> immediate next assignment" pairing in cblock/cinsn_t.
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


def _process_block_seq(cfunc: ida_hexrays.cfunc_t, blk: ida_hexrays.cblock_t, debug: bool = False) -> int:
    changed = 0
    i = 0
    n = blk.size()
    while i < n:
        insn = blk[i]
        op = insn.op

        # recurse into nested statements
        if op == ida_hexrays.cit_block and insn.cblock:
            changed += _process_any(cfunc, insn.cblock, debug)
        elif op == ida_hexrays.cit_if:
            if insn.cif.ithen:
                changed += _process_any(cfunc, insn.cif.ithen, debug)
            if insn.cif.ielse:
                changed += _process_any(cfunc, insn.cif.ielse, debug)
        elif op == ida_hexrays.cit_for:
            if insn.cfor.body:
                changed += _process_any(cfunc, insn.cfor.body, debug)
        elif op == ida_hexrays.cit_while:
            if insn.cwhile.body:
                changed += _process_any(cfunc, insn.cwhile.body, debug)
        elif op == ida_hexrays.cit_do:
            if insn.cdo.body:
                changed += _process_any(cfunc, insn.cdo.body, debug)
        elif op == ida_hexrays.cit_switch:
            if insn.cswitch.body:
                changed += _process_any(cfunc, insn.cswitch.body, debug)

        # look for "x = alloca(...)" and pair it with the next assignment
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
                            i = j  # skip over the paired statement
                        except Exception as ex:
                            idc.msg("[alloca-fix] replace failed at 0x%X: %s\n" % (nxt.cexpr.ea, ex))

        i += 1
    return changed


def fix_cfunc(cfunc: ida_hexrays.cfunc_t, debug: bool = False) -> int:
    changed = _process_any(cfunc, cfunc.body, debug=debug)
    if changed:
        cfunc.refresh_func_ctext()
        try:
            ida_hexrays.mark_cfunc_dirty(cfunc.func_ea)
        except Exception:
            pass
    return changed


def fix_function(ea: int, require_badstack: bool = True, debug: bool = False) -> int:
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
    idc.msg("[alloca-fix] %s: sequence replacements = %d\n" % (ida_funcs.get_func_name(f.start_ea), n))
    return n


# =========================================================
# 4.5) Demangle helpers
# =========================================================


def _normalize_demangled(d: str) -> str:
    """
    Normalize demangled result to a short name:
      - strip parameter list "(...)"
      - remove common calling convention markers
      - if '::' is present: keep only scope+func name (drop return type)
      - if 'operator' is present: keep from 'operator'
      - otherwise keep the last token
    """
    if not d:
        return d

    s = d.strip()

    # 1) drop parameter list
    if "(" in s:
        s = s.split("(", 1)[0].strip()

    # 2) remove common calling conventions
    s = re.sub(r"\b__(?:cdecl|thiscall|fastcall|vectorcall)\b", "", s)
    s = re.sub(r"\s+", " ", s).strip()

    # 3) scope-qualified name "A::B::func"
    if "::" in s:
        first_scope = s.find("::")
        cut = s.rfind(" ", 0, first_scope)
        s = s[0 if cut == -1 else (cut + 1):].strip()
        return s

    # 4) operator forms: keep from "operator"
    m = re.search(r"\boperator\b", s)
    if m:
        return s[m.start():].strip()

    # 5) normal function: take last token
    if " " in s:
        return s.split()[-1].strip()

    return s


def demangle_best_effort(maybe_mangled: str) -> str | None:
    """
    Try IDA demanglers first, then fall back to external c++filt.
    Return normalized short name on success, or None.
    """
    if not maybe_mangled:
        return None

    # 1) IDA: ida_name.demangle_name
    try:
        flags = 0
        dm = ida_name.demangle_name(maybe_mangled, flags)
        if dm:
            return _normalize_demangled(dm)
    except Exception:
        pass

    # 2) IDA: idc.Demangle
    try:
        dm = idc.Demangle(maybe_mangled, 0)
        if dm:
            return _normalize_demangled(dm)
    except Exception:
        pass

    # 3) external fallback: c++filt (Itanium ABI)
    try:
        out = subprocess.check_output(
            ["c++filt", "-t", maybe_mangled],
            stderr=subprocess.DEVNULL,
        ).decode("utf-8", "ignore").strip()
        if out and out != maybe_mangled:
            return _normalize_demangled(out)
    except Exception:
        pass

    return None


def get_func_demangled_name(ea: int) -> str:
    """
    Return a demangled short name for the function at 'ea'.
    The strategy is:
      - first try to demangle the "raw name" (may be mangled),
      - if that fails, try to normalize the decompiler prototype head line,
      - finally fall back to the original name.
    """
    raw = ida_name.get_name(ea) or ida_funcs.get_func_name(ea) or ""
    dm = demangle_best_effort(raw)
    if dm:
        return dm
    try:
        cfunc = ida_hexrays.decompile(ea)
        head_line = ida_lines.tag_remove(cfunc.get_pseudocode()[0].line)
        dm2 = _normalize_demangled(head_line)
        if dm2:
            return dm2
    except Exception:
        pass
    return _normalize_demangled(raw) or raw


# =========================================================
# 4.6) New feature: integer-to-char literal rewrite on Hex-Rays level
# =========================================================


def _int_to_ascii_bytes_be(val: int) -> bytes | None:
    """
    Convert a positive integer to its minimal big-endian byte string,
    but only if:
      - val > 255
      - length is between 2 and 8 bytes
      - all bytes are printable ASCII (0x20..0x7E)
    Return the bytes on success, or None.
    """
    if not isinstance(val, int):
        return None
    if val <= 255:
        return None
    if val < 0:
        return None

    # minimal number of bytes to represent val
    nbytes = (val.bit_length() + 7) // 8
    if nbytes < 2:
        return None
    if nbytes > 8:
        return None

    try:
        b = val.to_bytes(nbytes, byteorder="big", signed=False)
    except OverflowError:
        return None

    # printable ASCII (including space)
    if not all(0x20 <= ch <= 0x7E for ch in b):
        return None

    return b


class AsciiCharNumberRewriter(ida_hexrays.ctree_visitor_t):
    """
    Hex-Rays ctree visitor that, for plain assignments 'lhs = rhs',
    checks the RHS. If RHS is a pure integer constant whose minimal
    big-endian bytes are all printable ASCII characters, mark that
    number to be rendered as a character literal (same effect as
    right-click -> "Char" in the decompiler).
    """

    def __init__(self, cfunc: ida_hexrays.cfunc_t) -> None:
        super().__init__(ida_hexrays.CV_FAST)
        self.cfunc = cfunc
        self.changed = 0

    # visit_expr is called in pre-order on expressions
    def visit_expr(self, e: ida_hexrays.cexpr_t) -> int:
        if e.op == ida_hexrays.cot_asg:
            rhs = e.y
            self._try_convert_rhs(rhs)
        return 0

    def _try_convert_rhs(self, rhs: ida_hexrays.cexpr_t) -> None:
        # only standalone integer constants
        if rhs.op != ida_hexrays.cot_num:
            return

        cnum = rhs.n  # cnumber_t

        # obtain integer value using expression type if available
        try:
            tif = rhs.type
            if tif is None:
                return
            val = cnum.value(tif)
        except Exception:
            return

        ascii_bytes = _int_to_ascii_bytes_be(val)
        if ascii_bytes is None:
            return

        # at this point we consider it a candidate string-like constant
        try:
            nf = cnum.nf  # number_format_t embedded in cnumber_t
        except Exception:
            return

        try:
            # mark as char-type representation; keep it simple
            nf.flags = idaapi.char_flag()

            # build operand locator (ea + operand index)
            ol = ida_hexrays.operand_locator_t()
            ol.ea = rhs.ea
            # nf.opnum is exposed as a 1-char string in IDAPython
            try:
                opnum = nf.opnum
                if isinstance(opnum, str):
                    ol.opnum = ord(opnum)
                else:
                    ol.opnum = int(opnum)
            except Exception:
                # fallback: assume operand 0
                ol.opnum = 0

            # update user number formats map
            self.cfunc.numforms[ol] = nf
            self.changed += 1
        except Exception as ex:
            idc.msg(f"[ascii-char-rewrite] failed at 0x{rhs.ea:X}: {ex}\n")


def apply_ascii_char_rewrites(cfunc: ida_hexrays.cfunc_t) -> int:
    """
    Run AsciiCharNumberRewriter over cfunc and persist the resulting
    number formats via save_user_numforms(), so that:
      - current cfunc.pseudocode reflects changes,
      - future decompilations of this function also keep them.
    """
    rewriter = AsciiCharNumberRewriter(cfunc)
    try:
        rewriter.apply_to_exprs(cfunc.body, None)
    except Exception as ex:
        idc.msg(f"[ascii-char-rewrite] traversal failed for 0x{cfunc.entry_ea:X}: {ex}\n")
        return 0

    if rewriter.changed > 0:
        try:
            ida_hexrays.save_user_numforms(cfunc.entry_ea, cfunc.numforms)
        except Exception as ex:
            idc.msg(f"[ascii-char-rewrite] save_user_numforms failed for 0x{cfunc.entry_ea:X}: {ex}\n")
        try:
            cfunc.refresh_func_ctext()
        except Exception:
            pass

    return rewriter.changed


# =========================================================
# 5) Main: per-function fix (PR_BADSTACK) and export
# =========================================================

result: dict[str, dict[str, str]] = {}

for func_name in FUNC_NAMES:
    func_ea = idc.get_name_ea_simple(func_name)
    if func_ea == idc.BADADDR:
        idc.msg(f"[!] function '{func_name}' not found, skipping\n")
        continue

    f = ida_funcs.get_func(func_ea)
    if not f:
        idc.msg(f"[!] failed to get function object for '{func_name}', skipping\n")
        continue

    # 5-0) if PR_BADSTACK present, run the alloca fix once
    try:
        if function_has_badstack(f):
            idc.msg(f"[*] PR_BADSTACK detected: {func_name}, running alloca fix...\n")
            fix_function(func_ea, require_badstack=True, debug=False)
        else:
            idc.msg(f"[*] no PR_BADSTACK: {func_name}, exporting directly\n")
    except Exception as _ex:
        idc.msg(f"[!] exception while checking/fixing PR_BADSTACK for {func_name}: {_ex}\n")

    # 5-1) raw disassembly (instructions only, no labels)
    dis_lines: list[str] = [
        idc.GetDisasm(ea)
        for ea in idautils.Heads(f.start_ea, f.end_ea)
        if is_code(ea)
    ]
    disasm_text = "\n".join(dis_lines)

    # 5-2) decompile and export pseudocode (after alloca fix)
    try:
        cfunc = ida_hexrays.decompile(func_ea)

        # new: run ASCII char-literal rewrite on ctree / numforms
        n_changed = apply_ascii_char_rewrites(cfunc)
        if n_changed > 0:
            idc.msg(f"[*] ascii-char-rewrite: {func_name}, updated {n_changed} numeric constants\n")

        pcode_lines = [ida_lines.tag_remove(sline.line) for sline in cfunc.get_pseudocode()]
        pcode_text = "\n".join(pcode_lines)
    except ida_hexrays.DecompilationFailure as e:
        idc.msg(f"[!] decompilation failed for '{func_name}': {e}\n")
        cfunc = None
        pcode_text = ""

    # 5-3) enhanced disassembly (needs cfunc)
    if cfunc:
        try:
            disasm_enhanced = make_enhanced_disasm_for_func(f, cfunc)
        except Exception as ee:
            idc.msg(f"[!] failed to build enhanced disassembly for '{func_name}': {ee}\n")
            disasm_enhanced = ""
    else:
        disasm_enhanced = ""

    # 5-4) compute demangled short name
    demangle_name = get_func_demangled_name(func_ea)

    # 5-5) collect results
    result[func_name] = {
        "pcode": pcode_text,
        "disasm": disasm_text,
        "disasm_enhanced": disasm_enhanced,
        "demangle_name": demangle_name,
    }

# =========================================================
# 6) Write JSON output and exit
# =========================================================

out_path = "func_dis.json"
try:
    with open(out_path, "w", encoding="utf-8") as fp:
        json.dump(result, fp, ensure_ascii=False, indent=2)
    idc.msg(f"[*] results saved to {out_path}\n")
except Exception as err:
    fallback = os.path.join(os.getcwd(), "func_dis.json")
    with open(fallback, "w", encoding="utf-8") as fp:
        json.dump(result, fp, ensure_ascii=False, indent=2)
    idc.msg(f"[!] failed to write {out_path} ({err}), saved to {fallback}\n")

idaapi.qexit(0)

# Example:
# ./ida -A -L"output.log" -S"/path/dump_dis_v5.py funcs_list=CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_loop_01_bad" /path/to/bin
# ./ida -A -L"output.log" -S"/path/dump_dis_v5.py funcs_list=_ZN59CWE121_Stack_Based_Buffer_Overflow__src_char_declare_cpy_8467CWE121_Stack_Based_Buffer_Overflow__src_char_declare_cpy_84_goodG2BD2Ev" /path/to/bin
