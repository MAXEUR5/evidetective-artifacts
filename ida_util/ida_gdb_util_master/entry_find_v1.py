# IDA 9.1 / Python 3
# Resolve user entry function ('main') on Linux ELF (x86/x64) robustly via
# __libc_start_main/__uClibc_main first-argument; fallback to "first call's first arg"
# inside the entry function's CTree — all at decompiler level (no ASM heuristics).
#
# Output: entry_point.json with {"enrty_func": "<name or empty>"}.
#
# Refs:
# - Porting guide & 9.x APIs: ida_nalt.enum_import_names, ida_entry.get_entry*, inf.start_ip
# - Hex-Rays CTree visitor: ctree_visitor_t / cot_call
# - libc startup semantics: __libc_start_main/__uClibc_main first arg is 'main'
#
# NOTE: This script does not rename anything.

import json
import os
from typing import List, Tuple, Optional

import idaapi
import ida_entry
import ida_nalt
import ida_name
import ida_funcs
import idautils
import ida_auto

# Hex-Rays is required for CTree-based extraction
try:
    import ida_hexrays
    HAS_HEXRAYS = ida_hexrays.init_hexrays_plugin()
except Exception:
    HAS_HEXRAYS = False


# ---------- Util ----------

def get_program_entry_ea() -> int:
    """Prefer inf.start_ip; fallback to the first entry in ida_entry."""
    inf = idaapi.get_inf_structure()
    start = getattr(inf, "start_ip", idaapi.BADADDR)
    if start != idaapi.BADADDR:
        return start
    qty = ida_entry.get_entry_qty()
    if qty > 0:
        ord0 = ida_entry.get_entry_ordinal(0)
        return ida_entry.get_entry(ord0)
    return idaapi.BADADDR


def find_names_like(substrs: List[str]) -> List[Tuple[int, str]]:
    res = []
    lowers = [s.lower() for s in substrs]
    for ea, name in idautils.Names():
        if any(k in (name or "").lower() for k in lowers):
            res.append((ea, name))
    return res


def enumerate_imports_for(symbols: List[str]) -> List[Tuple[int, str]]:
    """Enumerate imports and return matches (ea, name) for wanted symbols."""
    matches = []
    try:
        mod_qty = ida_nalt.get_import_module_qty()
        for i in range(mod_qty):
            ida_nalt.enum_import_names(i, lambda ea, n, o: matches.append((ea, n or "")) or True)
    except Exception:
        pass
    wanted = {s.lower() for s in symbols}
    return [(ea, n) for ea, n in matches if n and any(k in n.lower() for k in wanted)]


def collect_start_routine_callees() -> List[Tuple[int, str]]:
    keys = ["__libc_start_main", "libc_start_main", "__uClibc_main"]
    cands = find_names_like(keys)
    cands += enumerate_imports_for(keys)
    # de-duplicate by EA
    seen = set()
    uniq = []
    for ea, n in cands:
        if ea in seen:
            continue
        seen.add(ea)
        uniq.append((ea, n))
    return uniq


def get_xref_callers(callee_ea: int) -> List[ida_funcs.func_t]:
    funcs = []
    seen = set()
    for x in idautils.XrefsTo(callee_ea, 0):
        if not x.iscode:
            continue
        f = ida_funcs.get_func(x.frm)
        if f and f.start_ea not in seen:
            seen.add(f.start_ea)
            funcs.append(f)
    return funcs


# ---------- Decompiler visitors ----------

def _unwrap_expr(e):
    """Peel casts/&/* to reach the underlying expression."""
    # These CTree op constants exist in Hex-Rays; fallback-safe if missing.
    try:
        while e.op in (ida_hexrays.cot_cast, ida_hexrays.cot_ref, ida_hexrays.cot_ptr):
            e = e.x
        return e
    except Exception:
        return e


class _LibcStartMainFinder(ida_hexrays.ctree_visitor_t):
    """Find calls to __libc_start_main/__uClibc_main and take arg0 as 'main'."""
    def __init__(self, cfunc, target_names: List[str], target_eas: List[int]):
        super().__init__(ida_hexrays.CV_FAST)
        self.target_names = [n.split('@')[0].lower() for n in target_names if n]
        self.target_eas = set(target_eas or [])
        self.main_ea = idaapi.BADADDR
        self.cfunc = cfunc

    def _callee_match(self, callee) -> bool:
        # EA match
        if callee.op == ida_hexrays.cot_obj and callee.obj_ea in self.target_eas:
            return True
        # name/helper match
        name = ""
        if callee.op == ida_hexrays.cot_obj:
            name = ida_name.get_name(callee.obj_ea) or ""
        elif callee.op == ida_hexrays.cot_helper:
            name = callee.helper or ""
        return any(k in (name or "").lower() for k in self.target_names)

    def visit_expr(self, e):
        if e.op != ida_hexrays.cot_call:
            return 0
        callee = e.x
        if not self._callee_match(callee):
            return 0
        # Take first argument
        if e.a.size() >= 1:
            a0 = _unwrap_expr(e.a[0])
            if a0.op == ida_hexrays.cot_obj:
                self.main_ea = a0.obj_ea
                return 1  # stop
        return 0


class _AssignFuncptrCollector(ida_hexrays.ctree_visitor_t):
    """Collect assignments like: var = &sub_xxx; to resolve function pointers."""
    def __init__(self):
        super().__init__(ida_hexrays.CV_FAST)
        self.map_var_to_ea = {}

    @staticmethod
    def _var_key(e):
        # robust key for a variable node
        try:
            return ("idx", e.v.idx)
        except Exception:
            try:
                return ("name", e.v.name)
            except Exception:
                return ("obj", repr(e.v))

    def visit_expr(self, e):
        try:
            if e.op == ida_hexrays.cot_asg and e.x.op == ida_hexrays.cot_var:
                rhs = _unwrap_expr(e.y)
                if rhs.op == ida_hexrays.cot_obj:
                    self.map_var_to_ea[self._var_key(e.x)] = rhs.obj_ea
        except Exception:
            pass
        return 0


class _FirstCallFinder(ida_hexrays.ctree_visitor_t):
    """Find the first function call in a function body."""
    def __init__(self):
        super().__init__(ida_hexrays.CV_FAST)
        self.first_call = None

    def visit_expr(self, e):
        if self.first_call is not None:
            return 0
        if e.op == ida_hexrays.cot_call:
            self.first_call = e
            return 1  # stop
        return 0


def decompile_func(f: ida_funcs.func_t):
    try:
        return ida_hexrays.decompile(f)
    except Exception:
        return None


def find_main_via_libc(funcs_to_try: List[ida_funcs.func_t],
                       callee_names: List[str],
                       callee_eas: List[int]) -> int:
    if not HAS_HEXRAYS:
        return idaapi.BADADDR
    for f in funcs_to_try:
        cfunc = decompile_func(f)
        if not cfunc:
            continue
        v = _LibcStartMainFinder(cfunc, callee_names, callee_eas)
        v.apply_to_exprs(cfunc.body, None)
        if v.main_ea != idaapi.BADADDR:
            return v.main_ea
    return idaapi.BADADDR


def fallback_first_call_first_arg(entry_func: ida_funcs.func_t) -> int:
    """Extreme fallback (decompiler-level): in the entry function,
    take the first call's first argument; if it resolves to a function (&sub_xxx),
    return its EA."""
    if not HAS_HEXRAYS or not entry_func:
        return idaapi.BADADDR

    cfunc = decompile_func(entry_func)
    if not cfunc:
        return idaapi.BADADDR

    # Pass 1: collect simple "var = &func" assignments
    assign_col = _AssignFuncptrCollector()
    assign_col.apply_to_exprs(cfunc.body, None)

    # Pass 2: locate the first call
    call_finder = _FirstCallFinder()
    call_finder.apply_to_exprs(cfunc.body, None)
    call = call_finder.first_call
    if not call or call.a.size() < 1:
        return idaapi.BADADDR

    a0 = _unwrap_expr(call.a[0])
    try:
        if a0.op == ida_hexrays.cot_obj:
            return a0.obj_ea
        if a0.op == ida_hexrays.cot_var:
            key = _AssignFuncptrCollector._var_key(a0)
            return assign_col.map_var_to_ea.get(key, idaapi.BADADDR)
    except Exception:
        pass
    return idaapi.BADADDR


# ---------- Orchestration & output ----------

def resolve_user_entry_ea() -> int:
    # If already named "main", return it immediately
    ea = ida_name.get_name_ea(idaapi.BADADDR, "main")
    if ea != idaapi.BADADDR:
        return ea

    # Prepare callee list (__libc_start_main / __uClibc_main)
    callee_pairs = collect_start_routine_callees()  # [(ea, name), ...]
    callee_eas = [x[0] for x in callee_pairs]
    callee_names = [x[1] for x in callee_pairs]

    # Candidate callers: entry function first, then any function that calls the start routine
    funcs_to_try = []
    start_ea = get_program_entry_ea()
    entry_func = ida_funcs.get_func(start_ea) if start_ea != idaapi.BADADDR else None
    if entry_func:
        funcs_to_try.append(entry_func)
    for ce in callee_eas:
        for f in get_xref_callers(ce):
            if f not in funcs_to_try:
                funcs_to_try.append(f)

    # Primary approach: libc start routine's first argument
    main_ea = find_main_via_libc(funcs_to_try, callee_names, callee_eas)
    if main_ea != idaapi.BADADDR:
        return main_ea

    # Extreme fallback (your requirement): first call's first argument within entry function
    if entry_func:
        main_ea = fallback_first_call_first_arg(entry_func)
        if main_ea != idaapi.BADADDR:
            return main_ea

    return idaapi.BADADDR


def write_json_result(func_name: str, out_path: Optional[str] = None) -> str:
    data = {"enrty_func": func_name or ""}
    if not out_path:
        out_path = os.path.join(os.getcwd(), "entry_point.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=True, indent=2)
    print(f"[+] Wrote {out_path}: {data}")
    return out_path


def main():
    ida_auto.auto_wait()
    if not HAS_HEXRAYS:
        print("[!] Hex-Rays is required for this script (CTree-based).")
    main_ea = resolve_user_entry_ea()
    name = ida_name.get_name(main_ea) if main_ea != idaapi.BADADDR else ""
    write_json_result(name)
    idaapi.qexit(0)

if __name__ == "__main__":
    main()
