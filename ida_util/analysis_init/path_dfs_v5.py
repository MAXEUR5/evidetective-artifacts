# --------------------------------------------------------------------------
#  IDA 9.1  -  Path DFS v4 (fixed global table scanning)
#
#  Feature:
#    - End-to-end function call chain search.
#    - Supports constant / table / XOR-obfuscated function pointers.
#    - Additionally infers edges from global variables whose value is a
#      function entry (e.g. vtables like off_3CE8 dq offset sub_136A).
#
#  Usage example:
#    ./ida -A -L"output.log" \
#      -S"path_dfs_v4_fixed.py start_func=entry end_func=endpoint4" \
#      /path/to/binary
# --------------------------------------------------------------------------

import idaapi          # type: ignore
import ida_auto        # type: ignore
import ida_hexrays     # type: ignore
import ida_funcs       # type: ignore
import ida_xref        # type: ignore
import idautils        # type: ignore
import idc             # type: ignore
import ida_bytes       # type: ignore
import ida_ida         # type: ignore

import json
import os
from typing import List, Dict, Set, Optional, Tuple

OUT_FILE = "cc_dfs_path.json"      # fixed output filename
MAX_DEF_SEARCH = 1000              # max statements for backward slicing

# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------


def parse_args() -> Tuple[str, str]:
    start = end = None
    for a in idc.ARGV:
        if "=" in a:
            k, v = map(str.strip, a.split("=", 1))
            if k == "start_func":
                start = v
            elif k == "end_func":
                end = v
    if not (start and end):
        idc.msg('Usage: -S"path_dfs_v4_fixed.py start_func=<name> end_func=<name>"\n')
        idaapi.qexit(1)
    return start, end


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def resolve(name: str) -> int:
    ea = idc.get_name_ea_simple(name)
    f = ida_funcs.get_func(ea) if ea != idc.BADADDR else None
    if not f:
        idc.msg(f"[!] Function '{name}' not found!\n")
        idaapi.qexit(1)
    return f.start_ea


def is_internal(ea: int) -> bool:
    """
    Filter out imports / PLT / library functions, keep only user code.
    """
    if not isinstance(ea, int):
        return False
    f = ida_funcs.get_func(ea)
    if not f:
        return False
    seg = idaapi.getseg(ea)
    if seg and seg.type in (idaapi.SEG_XTRN, idaapi.SEG_GRP):
        return False
    if f.flags & ida_funcs.FUNC_LIB:
        return False
    return True


def is_tail_jump(insn_ea: int, target_ea: int) -> bool:
    """
    Detect tail calls (jump to the beginning of another function).
    """
    if idaapi.is_call_insn(insn_ea):
        return False
    if ida_bytes.is_flow(idaapi.get_full_flags(insn_ea)):
        return False
    tgt_func = ida_funcs.get_func(target_ea)
    return tgt_func is not None and tgt_func.start_ea == target_ea


def pointer_size() -> int:
    """
    Return pointer size (4 or 8) depending on current file bitness.

    This version intentionally avoids ida_ida.cvar / get_inf_structure
    to be compatible with environments where those attributes do not
    exist. It relies only on idc.__EA64__, which is widely available.
    """
    try:
        return 8 if getattr(idc, "__EA64__", False) else 4
    except Exception:
        # Extremely defensive fallback: assume 8-byte pointers.
        return 8


# --------------------------------------------------------------------------
# v3: backward data slicing helpers
# --------------------------------------------------------------------------


def collect_func_objs(expr) -> Set[int]:
    """
    Collect function addresses (cot_obj directly referencing a code ea)
    from an expression tree.
    """
    found: Set[int] = set()

    class _Visitor(ida_hexrays.ctree_visitor_t):
        def __init__(self) -> None:
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_obj:
                if is_internal(e.obj_ea):
                    found.add(e.obj_ea)
            return 0

    _Visitor().apply_to(expr, None)
    return found


def expr_uses_lvar(expr, lvar_idx_set: Set[int]) -> bool:
    """
    Check whether the expression uses any of the given local variable indices.
    """

    class _Chk(ida_hexrays.ctree_visitor_t):
        def __init__(self) -> None:
            super().__init__(ida_hexrays.CV_FAST)
            self.hit = False

        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_var and e.v.idx in lvar_idx_set:
                self.hit = True
                return 1  # stop
            return 0

    c = _Chk()
    c.apply_to(expr, None)
    return c.hit


def resolve_callee_via_defs(cfunc, callee_expr) -> List[int]:
    """
    When we cannot directly resolve the callee, perform a light-weight
    backward slice inside the same function:
      * Find local variables used by callee_expr
      * Walk assignments; if LHS depends on those lvars, inspect RHS for
        function addresses
    """
    results: Set[int] = set()

    # 1) Collect lvar indices used in callee_expr
    lvar_idx_set: Set[int] = set()

    class _VarGrab(ida_hexrays.ctree_visitor_t):
        def __init__(self) -> None:
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_var:
                lvar_idx_set.add(e.v.idx)
            return 0

    _VarGrab().apply_to(callee_expr, None)
    if not lvar_idx_set:
        return []

    # 2) Scan assignments in cfunc.body and track definitions
    visited = 0

    class _DefFinder(ida_hexrays.ctree_visitor_t):
        def __init__(self) -> None:
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            nonlocal visited
            if visited > MAX_DEF_SEARCH:
                return 1  # stop

            if e.op == ida_hexrays.cot_asg:
                lhs, rhs = e.x, e.y
                if expr_uses_lvar(lhs, lvar_idx_set):
                    objs = collect_func_objs(rhs)
                    results.update(objs)
            visited += 1
            return 0

    _DefFinder().apply_to(cfunc.body, None)
    return list(results)


# --------------------------------------------------------------------------
# Global-variable-to-function edge helpers
# --------------------------------------------------------------------------


def collect_global_objs(expr) -> Set[int]:
    """
    Collect global data objects (cot_obj in data segment) referenced in expr.
    This is used to detect patterns like:
        *a1 = &off_3CE8;
    where off_3CE8 is a global table whose entries are function pointers.
    """
    found: Set[int] = set()

    class _Visitor(ida_hexrays.ctree_visitor_t):
        def __init__(self) -> None:
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_obj:
                ea = e.obj_ea
                flags = ida_bytes.get_full_flags(ea)
                if ida_bytes.is_data(flags):
                    found.add(ea)
            return 0

    _Visitor().apply_to(expr, None)
    return found


def collect_funcs_from_global_table(base_ea: int, max_slots: int = 16) -> Set[int]:
    """
    Given the address of a global data object, scan the first max_slots
    pointer-sized entries and treat each entry that is a function entry
    as a potential callee.

    Fix note (important):
      - The previous version simply scanned max_slots pointers starting
        from base_ea and only checked is_data(), which could accidentally
        walk into subsequent global objects (for example, from off_3CC0
        through to off_3CD8) and thus create spurious edges such as:
            sub_16AE -> off_3CC0 -> ... -> off_3CD8 -> sub_1420
      - The new version strictly limits the scan range to the current
        data item:
            [base_ea, ida_bytes.get_item_end(base_ea))
        while still respecting max_slots as an upper bound, so it will
        not cross into the next global object.
    """
    res: Set[int] = set()
    ps = pointer_size()

    # End address of the current data item (for a single dq, usually base_ea + ps)
    item_end = ida_bytes.get_item_end(base_ea)
    if item_end == idc.BADADDR or item_end <= base_ea:
        # If IDA does not provide reliable item size info, fall back to max_slots range
        item_end = base_ea + max_slots * ps

    # The maximum address we are allowed to scan: must not exceed item_end
    # and must not exceed the theoretical max_slots range.
    max_ea = min(item_end, base_ea + max_slots * ps)

    ea = base_ea
    slots = 0
    while ea + ps <= max_ea and slots < max_slots:
        flags = ida_bytes.get_full_flags(ea)
        if not ida_bytes.is_data(flags):
            break

        if ps == 8:
            tgt = ida_bytes.get_qword(ea)
        else:
            tgt = ida_bytes.get_dword(ea)

        if tgt not in (idc.BADADDR, 0):
            f = ida_funcs.get_func(tgt)
            if f and f.start_ea == tgt and is_internal(tgt):
                res.add(tgt)

        ea += ps
        slots += 1

    return res


# --------------------------------------------------------------------------
# Hex-Rays: collect callees (including obfuscated / table pointers)
# --------------------------------------------------------------------------


def try_resolve_callee(callee_expr) -> Optional[int]:
    """
    Try to resolve the callee address directly from the expression tree.
    """
    if callee_expr.op == ida_hexrays.cot_obj:
        return callee_expr.obj_ea
    elif callee_expr.op in (
        ida_hexrays.cot_cast,
        ida_hexrays.cot_ref,
        ida_hexrays.cot_ptr,
        ida_hexrays.cot_memptr,
        ida_hexrays.cot_memref,
    ):
        return try_resolve_callee(callee_expr.x)
    return None


def collect_callees_from_hexrays(func_ea: int) -> List[int]:
    """
    Decompile and traverse ctree to extract possible callees.

    It handles:
      * Direct calls
      * Calls through local variables after light-weight backward slicing
      * Calls encoded via expressions with a single function address
      * Additional edges from global function-pointer tables:
            *a1 = &off_3CE8;
        where off_3CE8 data contains function pointers like sub_136A.
    """
    if not ida_hexrays.init_hexrays_plugin():
        return []

    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        return []

    found: Set[int] = set()
    global_fp_targets: Set[int] = set()

    class _CallVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self) -> None:
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            if e.op != ida_hexrays.cot_call:
                return 0

            callee_expr = e.x

            # (1) direct resolution
            direct = try_resolve_callee(callee_expr)
            if direct and is_internal(direct):
                found.add(direct)
            else:
                # (2) expression containing a unique function address
                inline_objs = collect_func_objs(callee_expr)
                if len(inline_objs) == 1:
                    found.update(inline_objs)

                # (3) unresolved => backward slicing
                if not inline_objs:
                    for tgt in resolve_callee_via_defs(cfunc, callee_expr):
                        if is_internal(tgt):
                            found.add(tgt)
            return 0

    class _GlobalFuncptrVisitor(ida_hexrays.ctree_visitor_t):
        """
        Detect usage of global variables whose value is a function entry
        (or a small table of function entries). We approximate by scanning
        assignment RHS expressions where the global is used as rvalue.
        """

        def __init__(self) -> None:
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_asg:
                rhs = e.y
                globals_in_rhs = collect_global_objs(rhs)
                for gv_ea in globals_in_rhs:
                    for tgt in collect_funcs_from_global_table(gv_ea):
                        global_fp_targets.add(tgt)
            return 0

    _CallVisitor().apply_to(cfunc.body, None)
    _GlobalFuncptrVisitor().apply_to(cfunc.body, None)

    found.update(global_fp_targets)
    return list(found)


# --------------------------------------------------------------------------
# v2 logic (assembly layer + thunk + tail calls) retained
# --------------------------------------------------------------------------

callees_cache: Dict[int, List[int]] = {}


def direct_callees(func_ea: int) -> List[int]:
    """
    Return the list of internal functions directly reachable from func_ea.

    v4 = v2 (asm scan + thunk + tail calls) + Hex-Rays based resolution,
    and now also global function-pointer table based edges.
    """
    if func_ea in callees_cache:
        return callees_cache[func_ea]

    res: Set[int] = set()

    # (1) normal / indirect calls via assembly scanning
    for insn in idautils.FuncItems(func_ea):
        if idaapi.is_call_insn(insn):
            for xr in idautils.XrefsFrom(insn, ida_xref.XREF_FAR):
                if not xr.iscode:
                    continue
                tgt_func = ida_funcs.get_func(xr.to)
                if (
                    tgt_func
                    and tgt_func.start_ea != func_ea
                    and is_internal(tgt_func.start_ea)
                ):
                    res.add(tgt_func.start_ea)
            continue

        # (2) tail calls
        first_xref = next(idautils.XrefsFrom(insn, ida_xref.XREF_FAR), None)
        if first_xref and is_tail_jump(insn, first_xref.to):
            tgt = first_xref.to
            if is_internal(tgt) and tgt != func_ea:
                res.add(tgt)

    # (3) thunk
    f = ida_funcs.get_func(func_ea)
    if f and (f.flags & ida_funcs.FUNC_THUNK):
        tgt = ida_funcs.calc_thunk_func_target(f)
        if isinstance(tgt, int) and is_internal(tgt):
            res.add(tgt)

    # (4) Hex-Rays (including obfuscated / table pointers and global edges)
    res.update(collect_callees_from_hexrays(func_ea))

    callees_cache[func_ea] = sorted(res)
    return callees_cache[func_ea]


# --------------------------------------------------------------------------
# DFS + memoization
# --------------------------------------------------------------------------

good_paths: Dict[int, List[List[int]]] = {}
bad_funcs: Set[int] = set()


def dfs(ea: int, end_ea: int, visiting: Set[int]) -> List[List[int]]:
    """
    Memoized DFS. A function appears at most once in a single path.
    """
    if ea in good_paths:
        return good_paths[ea]
    if ea in bad_funcs or ea in visiting:
        return []

    paths: List[List[int]] = []
    for cal in direct_callees(ea):
        if cal == end_ea:
            paths.append([ea, end_ea])
        else:
            for sub in dfs(cal, end_ea, visiting | {ea}):
                paths.append([ea] + sub)

    if paths:
        good_paths[ea] = paths
    else:
        bad_funcs.add(ea)
    return paths


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def main() -> None:
    ida_auto.auto_wait()

    if ida_hexrays.init_hexrays_plugin():
        idc.msg(f"Hex-Rays {ida_hexrays.get_hexrays_version()} loaded\n")

    start_name, end_name = parse_args()
    idc.msg(f"[+] start_func = {start_name}\n")
    idc.msg(f"[+] end_func   = {end_name}\n")
    idc.msg(f"[+] output     = {OUT_FILE}\n")

    start_ea = resolve(start_name)
    end_ea = resolve(end_name)

    paths_ea = dfs(start_ea, end_ea, set())

    # de-duplicate
    paths_ea = [list(t) for t in {tuple(p) for p in paths_ea}]

    paths_name = [
        [idc.get_func_name(ea) or f"{ea:#x}" for ea in p] for p in paths_ea
    ]

    with open(OUT_FILE, "w", encoding="utf-8") as fp:
        json.dump(paths_name, fp, ensure_ascii=False, indent=2)

    idc.msg(
        f"[+] {len(paths_name)} paths written to {os.path.abspath(OUT_FILE)}\n"
    )
    idaapi.qexit(0)


# --------------------------------------------------------------------------
if __name__ == "__main__":
    main()
# Example:
#   ./ida -A -L"output.log" \
#     -S"/home/user/ida_util/analysis_init/path_dfs_v4_fixed.py start_func=main end_func=sub_1320" \
#     /home/user/small_case/test_dfs/CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cpy_82-bad
