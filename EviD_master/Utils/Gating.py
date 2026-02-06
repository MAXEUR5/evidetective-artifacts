from typing import Dict, List


def lead_has_any_indirect_call(
    call_chain: List[str], func_call_dict: Dict[str, List[dict]]
) -> bool:
    for fn in call_chain or []:
        for c in func_call_dict.get(fn) or []:
            if (c.get("call_type") or "").upper() == "INDIRECT":
                return True
    return False


def lead_has_stack_lvars(call_chain, local_var_dict):
    for fn in call_chain or []:
        vars_list = local_var_dict.get(fn) or []
        for v in vars_list:
            if v.get("reg_id") is None:
                return True
    return False

def lead_uses_any_global(call_chain, global_var_dict):
    if not call_chain:
        return False
    func_set = set(call_chain)
    for gname, ginfo in global_var_dict.items():
        ref_list = ginfo.get("references") or []
        for ref in ref_list:
            if ref.get("function_name") in func_set:
                return True
    return False

def lead_needs_fetch_pcode(call_chain, func_call_dict):
    for fn in call_chain or []:
        call_list = func_call_dict.get(fn) or []
        for c in call_list:
            cat = (c.get("cat") or "").upper()
            if cat in ("USER_DEF", "OTHER"):
                return True
    return False

def lead_needs_fetch_disasm(call_chain, pcode_dict):
    lifting_inst = {" alloca("}
    for fn in call_chain or []:
        code = pcode_dict.get(fn)
        if not code:
            continue
        for pat in lifting_inst:
            if pat in code:
                return True
    return False

import itertools


def compute_min_primitives_to_cover_obligations(obligation_gate, mandatory_prims=None):

    if mandatory_prims is None:
        mandatory_prims = set()

    required_obs = [oid for oid, opts in obligation_gate.items() if opts]
    if not required_obs:

        return len(mandatory_prims)

    remaining_obs = []
    for oid in required_obs:
        gate = set(obligation_gate[oid])

        if gate.isdisjoint(mandatory_prims):
            remaining_obs.append(oid)

    if not remaining_obs:
        return len(mandatory_prims)

    candidate_prims = sorted(
        {p for oid in remaining_obs for p in obligation_gate[oid]} - mandatory_prims
    )

    if not candidate_prims:

        return float("inf")

    for k in range(1, len(candidate_prims) + 1):
        for comb in itertools.combinations(candidate_prims, k):
            chosen_extra = set(comb)
            chosen_all = mandatory_prims | chosen_extra
            ok = True
            for oid in remaining_obs:
                if chosen_all.isdisjoint(obligation_gate[oid]):
                    ok = False
                    break
            if ok:
                return len(chosen_all)

    return float("inf")


def make_obligation_gate(call_chain, func_call_dict, local_var_dict,
                         global_var_dict, pcode_dict, cwe_type):

    obligation_gate = {}
    obligation_gate[1] = ["inner_call"]
    obligation_gate[2] = ["global_var", "fetch_pcode", "stack_lvar"]
    obligation_gate[3] = ["global_var", "fetch_pcode"]
    obligation_gate[4] = ["stack_lvar", "fetch_disasm"]

    if not lead_has_any_indirect_call(call_chain, func_call_dict):
        obligation_gate[1].remove("inner_call")

    has_stack_lvars = lead_has_stack_lvars(call_chain, local_var_dict)
    if not has_stack_lvars:
        if "stack_lvar" in obligation_gate[2]:
            obligation_gate[2].remove("stack_lvar")
        if "stack_lvar" in obligation_gate[4]:
            obligation_gate[4].remove("stack_lvar")

    if not lead_uses_any_global(call_chain, global_var_dict):
        if "global_var" in obligation_gate[2]:
            obligation_gate[2].remove("global_var")
        if "global_var" in obligation_gate[3]:
            obligation_gate[3].remove("global_var")

    if not lead_needs_fetch_pcode(call_chain, func_call_dict):
        if "fetch_pcode" in obligation_gate[2]:
            obligation_gate[2].remove("fetch_pcode")
        if "fetch_pcode" in obligation_gate[3]:
            obligation_gate[3].remove("fetch_pcode")

    needs_disasm = lead_needs_fetch_disasm(call_chain, pcode_dict)
    if not needs_disasm:
        if "fetch_disasm" in obligation_gate[4]:
            obligation_gate[4].remove("fetch_disasm")

    mandatory_prims = set()

    if cwe_type in ("121", "122","125","787") and has_stack_lvars:
        mandatory_prims.add("stack_lvar")

    if needs_disasm:
        mandatory_prims.add("fetch_disasm")

    mini_num = compute_min_primitives_to_cover_obligations(obligation_gate, mandatory_prims)
    return obligation_gate, mini_num



def build_mini_primitives_table(obligation_gate: dict[int, list[str]]) -> str:
    if not isinstance(obligation_gate, dict):
        raise TypeError("obligation_gate must be a dict[int, list[str]]")

    gates = sorted(obligation_gate.keys())
    width = max((len(str(g)) for g in gates), default=1)

    def fmt_items(items) -> str:
        if not items:
            return "[]"
        items_sorted = sorted(set(items))
        return "[" + ", ".join(items_sorted) + "]"

    lines = []
    for g in gates:
        items = obligation_gate.get(g, [])
        lines.append(f"O{str(g)}'s minimum primitive set: {fmt_items(items)}")

    header = "Minimum Primitive Set for Satisfying Obligation Requirements:"
    return f"{header}\n" + "\n".join(lines)


def updated_obligations(prev: dict, curr: dict):

    OB_KEYS = ("O1", "O2", "O3", "O4")
    updated = []
    for k in OB_KEYS:
        if prev.get(k, "Unknown") == "Unknown" and curr.get(k, "Unknown") != "Unknown":
            updated.append(k)
    return updated



def check_obligation_gate(diff_obligations: list,
                          update_from: list,
                          pass_cache_list: list,
                          obligation_gate: dict):

    if not diff_obligations:
        return True, []


    invalid_eid = False

    evid_types = set()
    n = len(pass_cache_list)


    for eid in (update_from or []):

        if not isinstance(eid, int):
            invalid_eid = True
            continue

        idx = eid - 1  # 1-based -> 0-based
        if idx < 0 or idx >= n:

            invalid_eid = True
            continue

        item = pass_cache_list[idx]
        if isinstance(item, dict):
            evid_types.add(item.get("type"))

    failed = []
    for ok_name in diff_obligations:
        i = int(ok_name[1:])
        required = obligation_gate.get(i, [])
        if not required:
            continue
        if not (set(required) & evid_types):
            failed.append({"obligation": ok_name, "required": list(required)})

    return (len(failed) == 0) and (not invalid_eid), failed



def refill_obligation_gate(mini_obligation_gate):
    """
    mini_obligation_gate: dict[int, list]
      - keys: 1..4
      - values: list (possibly empty)

    rule:
      - if mini_obligation_gate[i] is empty -> keep []
      - else -> overwrite with template list
    return:
      - new dict, do not mutate input
    """
    template = {
        1: ["inner_call"],
        2: ["global_var", "fetch_pcode", "stack_lvar"],
        3: ["global_var", "fetch_pcode"],
        4: ["stack_lvar", "fetch_disasm"],
    }


    refilled = {}

    for i in (1, 2, 3, 4):
        v = mini_obligation_gate.get(i, [])
        if v:
            refilled[i] = template[i].copy()
        else:
            refilled[i] = []
    return refilled