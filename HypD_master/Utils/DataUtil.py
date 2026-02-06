from typing import List, Dict, Any
import json
from pathlib import Path

def build_func_stack_var_dict(variables: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}

    for v in variables:
        name = v.get("lvar_name")
        if not name:
            continue

        in_stack = "dist_from_ret_addr" in v

        entry: Dict[str, Any] = {
            "in_stack": in_stack,
            "lvar_type": v.get("lvar_type"),
            "lvar_size": v.get("lvar_size"),
            "usage_lines": v.get("usage_lines")
        }

        if in_stack:
            entry["dist_from_ret_addr"] = v.get("dist_from_ret_addr")
        else:
            entry["reg_id"] = v.get("reg_id")

        result[name] = entry
    #print(result)
    return result


import re
import json
from typing import Optional

_CODE_FENCE_RE = re.compile(r'^\s*```(?:json|JSON)?\s*(.*?)\s*```\s*$', re.S)

def _strip_code_fence_and_bom(text: str) -> str:
    if not isinstance(text, str):
        text = str(text)

    s = text.lstrip("\ufeff")

    m = _CODE_FENCE_RE.match(s)
    return m.group(1) if m else s

def _whole_is_json_like(s: str) -> Optional[str]:

    if re.fullmatch(r'\s*\{.*\}\s*', s, flags=re.S):
        return s.strip()
    if re.fullmatch(r'\s*\[.*\]\s*', s, flags=re.S):
        return s.strip()
    return None

def _find_balanced_slice(s: str, open_ch: str, close_ch: str) -> Optional[str]:

    start = s.find(open_ch)
    if start == -1:
        return None

    depth = 0
    in_str = False
    esc = False

    for i in range(start, len(s)):
        ch = s[i]

        if in_str:
            if esc:
                esc = False
            elif ch == '\\':
                esc = True
            elif ch == '"':
                in_str = False

            continue

        if ch == '"':
            in_str = True
        elif ch == open_ch:
            depth += 1
        elif ch == close_ch:
            if depth > 0:
                depth -= 1
                if depth == 0:
                    return s[start:i+1]

    return None

def _rough_cut(s: str, open_ch: str, close_ch: str) -> Optional[str]:

    i = s.find(open_ch)
    j = s.rfind(close_ch)
    if i != -1 and j != -1 and j > i:
        return s[i:j+1]
    return None

def extract_json_string(text: str, *, allow_arrays: bool = True, validate: bool = False) -> str:

    s = _strip_code_fence_and_bom(text)

    whole = _whole_is_json_like(s)
    if whole is not None:
        cand = whole
        if not validate:
            return cand
        try:
            json.loads(cand)
            return cand
        except Exception:
            pass

    for pair in (('{', '}'), ('[', ']') if allow_arrays else ()):
        cand = _find_balanced_slice(s, pair[0], pair[1])
        if cand:
            if not validate:
                return cand.strip()
            try:
                json.loads(cand)
                return cand.strip()
            except Exception:
                continue

    best = None
    obj_cut = _rough_cut(s, '{', '}')
    arr_cut = _rough_cut(s, '[', ']') if allow_arrays else None

    for cand in (obj_cut, arr_cut):
        if cand and (best is None or len(cand) > len(best)):
            best = cand

    if best:
        best = best.strip()
        if validate:
            try:
                json.loads(best)
                return best
            except Exception:
                return best
        return best

    return s.strip()

def save_main_process_result(bin_path: str, static_sinks, result_tuple, out_dir="./Log"):

    vuln_cnt, evid_list, status_record = result_tuple

    prog_name = Path(bin_path).name  # datamash / a2ps

    callers = []
    for item in static_sinks or []:
        if not item:
            continue
        caller = item[0]
        if caller and caller not in callers:
            callers.append(caller)

    caller_part = "+".join(callers) if callers else "unknown_caller"

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    filename = f"{prog_name}_{caller_part}.json"
    save_path = out_path / filename

    payload = {
        "bin_path": bin_path,
        "program": prog_name,
        "static_sinks": static_sinks,
        "vuln_count": vuln_cnt,
        "evid_list": evid_list,
        "status_record": status_record,
    }

    with open(save_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    return str(save_path)

def count_sink_api_in_source(add_propagation_list, source_api_set):

    source_set = set(source_api_set or [])
    return sum(
        1
        for obj in (add_propagation_list or [])
        if (obj or {}).get("sink_api") in source_set
    )


def append_unique_by_call_chain(propagation_list, extra_list):

    if propagation_list is None:
        propagation_list = []

    existing_chains = {
        tuple(obj.get("call_chain") or [])
        for obj in (propagation_list or [])
    }

    for obj in (extra_list or []):
        chain = tuple(obj.get("call_chain") or [])
        if not chain:
            continue

        if chain in existing_chains:
            continue

        existing_chains.add(chain)
        propagation_list.append(obj)

    return propagation_list
