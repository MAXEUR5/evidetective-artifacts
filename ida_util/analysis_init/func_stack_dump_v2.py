import idc  # type: ignore
import idaapi  # type: ignore
import ida_funcs  # type: ignore
import ida_lines  # type: ignore
import ida_hexrays  # type: ignore
import ida_typeinf  # type: ignore
import ida_frame  # type: ignore
import idautils  # type: ignore
import ida_auto  # type: ignore
import json  # type: ignore

try:
    import ida_regs  # type: ignore
    get_reg_name_func = ida_regs.get_reg_name
except ImportError:
    import ida_idp  # type: ignore
    get_reg_name_func = ida_idp.get_reg_name

def build_ea2line_map_via_eamap(cfunc):
    """
    Build a mapping from ea to pseudocode line number using cfunc.get_eamap().
    """
    ea2line = {}
    if not cfunc:
        return ea2line
    _ = cfunc.get_pseudocode()
    em = cfunc.get_eamap()
    if not em:
        return ea2line
    for ea, items in em.items():
        best_line = None
        for it in items:
            try:
                c, r = cfunc.find_item_coords(it)
                if r >= 0 and (best_line is None or r < best_line):
                    best_line = r
            except:
                pass
        if best_line is not None:
            ea2line[ea] = best_line + 1
    return ea2line

def build_ea2line_map_via_ctree(cfunc):
    """
    Build a mapping from ea to line number by traversing the ctree.
    """
    ea2line = {}
    ln = 1
    if not cfunc:
        return ea2line

    class MyCtreeVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_stmt(self, s):
            nonlocal ln
            if s.ea != idc.BADADDR and s.ea not in ea2line:
                ea2line[s.ea] = ln
            ln += 1
            return 0

    visitor = MyCtreeVisitor()
    visitor.apply_to(cfunc.body, None)
    return ea2line

def choose_ea2line_map_builder(cfunc):
    """
    Attempt to build via eamap first. If empty or fails, fallback to ctree.
    """
    try:
        m = build_ea2line_map_via_eamap(cfunc)
        if m:
            return m
    except:
        pass
    return build_ea2line_map_via_ctree(cfunc)

def find_var_usage_lines(cfunc):
    """
    Create a dict mapping each local var index to a set of pseudocode lines.
    """
    usage_map = {}
    ea2line = choose_ea2line_map_builder(cfunc)
    lvars = cfunc.get_lvars()
    for idx in range(len(lvars)):
        usage_map[idx] = set()

    class VarRefVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_var:
                var_idx = e.v.idx
                if e.ea in ea2line:
                    usage_map[var_idx].add(ea2line[e.ea])
            return 0

    visitor = VarRefVisitor()
    visitor.apply_to(cfunc.body, None)
    return usage_map

def main():
    """
    1) Run with: -S"this_script.py <function_name>"
    2) Analyze local variables and their usage lines.
    3) Distinguish register vs stack variables.
    4) Output results to JSON.
    """
    ida_auto.auto_wait()

    if not ida_hexrays.init_hexrays_plugin():
        idc.msg("Hex-Rays decompiler plugin not available!\n")
        idaapi.qexit(1)
    idc.msg("Hex-rays version {} detected\n".format(ida_hexrays.get_hexrays_version()))

    if len(idc.ARGV) < 2:
        idc.msg("Usage: this_script.py <function_name>\n")
        idaapi.qexit(1)

    func_name = idc.ARGV[1]
    idc.msg("Analyzing function: {}\n".format(func_name))

    func_ea = idc.get_name_ea_simple(func_name)
    if func_ea == idc.BADADDR:
        idc.msg("Function '{}' not found!\n".format(func_name))
        idaapi.qexit(1)

    seg = idaapi.getseg(func_ea)
    if seg and seg.bitness == 2:
        is_64 = True
    else:
        is_64 = False

    f = ida_funcs.get_func(func_ea)
    if not f:
        idc.msg("Failed to get function object for '{}'\n".format(func_name))
        idaapi.qexit(1)

    cfunc = ida_hexrays.decompile(f)
    if not cfunc:
        idc.msg("Decompilation of '{}' failed!\n".format(func_name))
        idaapi.qexit(1)

    tinfo = ida_typeinf.tinfo_t()
    if not ida_frame.get_func_frame(tinfo, f):
        idc.msg("No function frame recognized for '{}'\n".format(func_name))
        idaapi.qexit(1)

    udt = ida_typeinf.udt_type_data_t()
    if not tinfo.get_udt_details(udt):
        idc.msg("Unable to get UDT details for '{}'\n".format(func_name))
        idaapi.qexit(1)

    ret_addr_offset = None
    for m in udt:
        if m.name == "__return_address":
            ret_addr_offset = m.offset // 8
            break

    if ret_addr_offset is None:
        ret_addr_offset = 8 if is_64 else 4
        idc.msg("Warning: __return_address not found; using default offset = {}\n".format(ret_addr_offset))
    idc.msg("__return_address offset = {}\n".format(ret_addr_offset))

    udt_map = {}
    for m in udt:
        mem_off_in_frame = m.offset // 8
        mem_tinfo = m.type
        mem_size = mem_tinfo.get_size()
        mem_type_str = mem_tinfo.dstr()
        udt_map[mem_off_in_frame] = {
            "name": m.name,
            "type_str": mem_type_str,
            "size": mem_size
        }

    var_usage_map = find_var_usage_lines(cfunc)
    results = []
    lvars = cfunc.get_lvars()
    platform_width = 8 if is_64 else 4

    for idx, lvar in enumerate(lvars):
        if not lvar.name:
            continue

        lvar_tinfo = lvar.type()
        lvar_type_str = lvar_tinfo.dstr()
        lvar_size = lvar.width

        if lvar.is_reg_var():
            loc_obj = lvar.location

            # Check if location is a single register
            if loc_obj.is_reg1():
                reg_id = loc_obj.reg1()
            elif loc_obj.is_reg2():
                raise ValueError("Location uses two registers, not handled: index {}".format(idx))
            else:
                raise ValueError("Unsupported register location type for var index {}".format(idx))

            # Directly call the register name function
            reg_name = get_reg_name_func(reg_id, platform_width)
            idc.msg("\nname: "+str(reg_name)+"; regid: "+str(reg_id)+"\n")
            reg_rec = {
                "lvar_idx": idx,
                "lvar_name": lvar.name,
                "lvar_type": lvar_type_str,
                "lvar_size": lvar_size,
                "usage_lines": sorted(list(var_usage_map[idx])),
                "reg_name": reg_name
            }
            results.append(reg_rec)
            continue

        if not lvar.is_stk_var():
            continue

        lvar_off_in_frame = lvar.location.stkoff() + cfunc.get_stkoff_delta()
        rec = {
            "lvar_idx": idx,
            "lvar_name": lvar.name,
            "lvar_offset": lvar_off_in_frame,
            "lvar_type": lvar_type_str,
            "lvar_size": lvar_size,
            "usage_lines": sorted(list(var_usage_map[idx])),
            "udt_name": None,
            "udt_type": None,
            "udt_size": None,
            "dist_from_ret_addr": None
        }

        udt_member = udt_map.get(lvar_off_in_frame, None)
        if udt_member:
            rec["udt_name"] = udt_member["name"]
            rec["udt_type"] = udt_member["type_str"]
            rec["udt_size"] = udt_member["size"]
            dist = lvar_off_in_frame - ret_addr_offset
            rec["dist_from_ret_addr"] = dist

        results.append(rec)

    json_filename = "func_{}_varmatch.json".format(func_name)
    output_data = {
        "function_name": func_name,
        "__return_address_offset": ret_addr_offset,
        "variables": results
    }

    with open(json_filename, "w", encoding="utf-8", errors="replace") as outf:
        json.dump(output_data, outf, indent=2, ensure_ascii=False)

    idc.msg("JSON result saved to: {}\n".format(json_filename))
    idaapi.qexit(0)

if __name__ == "__main__":
    main()
