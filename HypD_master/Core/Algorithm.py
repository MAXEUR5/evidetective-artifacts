from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple, Set
from Utils.Logger import slog
from Utils.DataUtil import extract_json_string
import json


def make_callchains_edges(func_use_api_dict, source_api_set, sink_api_set, runner):
    api_to_callers = defaultdict(set)
    for caller_func, apis in (func_use_api_dict or {}).items():
        if not apis:
            continue
        for api in apis:
            if not api:
                continue
            api_to_callers[api].add(caller_func)
    slog.info(api_to_callers)

    both_roles_apis = set(source_api_set) & set(sink_api_set)
    slog.info(both_roles_apis)

    source_sink_edges = []
    edge_visited_pairs = set()
    dfs_cache = {}

    for src_api in source_api_set:
        src_callers = api_to_callers.get(src_api, set())
        if not src_callers:
            continue

        for sink_api in sink_api_set:
            sink_callers = api_to_callers.get(sink_api, set())
            if not sink_callers:
                continue

            if src_api != sink_api and sink_api in both_roles_apis:
                continue

            for src_caller in src_callers:
                for sink_caller in sink_callers:
                    key = (src_api, sink_api, src_caller, sink_caller)
                    if key in edge_visited_pairs:
                        continue
                    edge_visited_pairs.add(key)

                    dfs_key = (src_caller, sink_caller)
                    if dfs_key in dfs_cache:
                        path = dfs_cache[dfs_key]
                    else:
                        try:
                            path = (
                                runner.get_dfs_call_chains(src_caller, sink_caller)
                                or []
                            )
                        except Exception as e:
                            slog.warning(
                                f"[DFS_ERROR] {src_caller} -> {sink_caller}: {e}"
                            )
                            path = []
                        dfs_cache[dfs_key] = path

                    if len(path) > 0:
                        slog.info(
                            f"[EDGE] {src_api} (caller: {src_caller}) -> "
                            f"{sink_api} (caller: {sink_caller}); path={path}"
                        )
                        source_sink_edges.append(
                            {
                                "source_api": src_api,
                                "source_caller": src_caller,
                                "sink_api": sink_api,
                                "sink_caller": sink_caller,
                                "path": path,
                            }
                        )

    slog.info(f"[SRC_SNK_EDGE_SUMMARY] total={len(source_sink_edges)}")
    return source_sink_edges


# HEU1
def make_propagation_across_from_main(
    entry_point_func,
    internal_func_list,
    func_use_api_dict,
    sink_api_set,
    pcode_dict,
    runner,
    slog=None,
):
    """
    internal_func_list: [ {"name": <func_name>}, ... ]
    func_use_api_dict: { func_name: [api1, api2, ...] }
    sink_api_set: [sink_api1, sink_api2, ...]
    pcode_dict: { func_name: <pcode> }
    runner: provides get_dfs_call_chains(entry, target)
    """
    result = []
    reason_str = (
        "This is a potential path: there is a sink on the path, but its corresponding source is currently unknown or lies outside the current chain. Conversely, there may be a source on the path while the sink is unclear or lies outside the chain. When one endpoint is missing but there is certain key data-flow evidence, you must treat it as an incomplete but extensible chain and perform topological completion on it. "
        "The payload produced by the source may originate from parameters accepted by the program, or from external input obtained via wrapped input functions it calls; it may also originate from non-user input, such as the program's own constants, static values, results of string operations, or generated data. If such sources exist and propagate along the data flow into the sink, then they constitute potential sources that can influence the vulnerability. "
        "Similarly, the sink on this path itself may not directly exhibit a vulnerability, but certain data-flow-related memory read and write operations either along the path or in out-of-chain functions connected via the data flow may still pose additional vulnerability risks and therefore also require analysis and inspection. As a result, more thorough checking of the data flow is necessary. "
        "Whenever pointers or references are passed between functions, treat them as tainted-data carriers and keep tracking every dereference, since the real sink often appears downstream."
    )

    sink_api_set_local = set(sink_api_set or [])

    for item in internal_func_list or []:
        fn = item.get("name")
        if not fn:
            continue

        api_use_list = (func_use_api_dict or {}).get(fn, []) or []
        if not api_use_list:
            continue

        matched_sink_apis = [api for api in api_use_list if api in sink_api_set_local]
        if not matched_sink_apis:
            continue
        try:
            paths = runner.get_dfs_call_chains(entry_point_func, fn) or []
        except Exception as e:
            if slog:
                slog.warning(f"get_dfs_call_chains failed for {fn}: {e}")
            paths = []

        if not paths:
            if slog:
                slog.info(
                    f"No path from entry '{entry_point_func}' to sink caller '{fn}', skip."
                )
            continue

        for path in paths:
            pcode_list = [
                pcode_dict.get(node) if isinstance(pcode_dict, dict) else None
                for node in (path or [])
            ]

            for sink_api in matched_sink_apis:
                propagation_object = {
                    "source_api": "currently unknown or nonexistent source",
                    "source_caller": "currently unknown or nonexistent source",
                    "sink_api": sink_api,
                    "sink_caller": fn,
                    "call_chain": path,
                    "pcode_list": pcode_list,
                    "reason": reason_str,
                }
                result.append(propagation_object)

    result = _dedupe_leaf_equivalent_paths(result)
    if slog:
        slog.info(
            f"[make_propagation_across_from_main] generated {len(result)} propagation objects."
        )

    return result


def dep_list_by_name(func_call_list):
    seen = set()
    dedup_func_call_list = []

    for item in func_call_list:
        n = item["name"]
        if n not in seen:
            seen.add(n)
            dedup_func_call_list.append(item)
    return dedup_func_call_list


def parse_poc_str(agent_resp):
    if agent_resp.find("POC HEAD") >= 1 and agent_resp.find("POC END") >= 1:
        return {"state": "fianl", "poc_flag": True, "poc_code": str(agent_resp)}
    else:
        agent_resp = extract_json_string(agent_resp)
        json_parse = json.loads(agent_resp)
        return json_parse


def parse_debug_str(agent_resp):
    if agent_resp.find("POC HEAD") >= 1 and agent_resp.find("POC END") >= 1:
        return {"state": "fianl", "poc_flag": True, "poc_code": str(agent_resp)}
    else:
        agent_resp = extract_json_string(agent_resp)
        json_parse = json.loads(agent_resp)
        return json_parse


def pass_cache_reform(pass_cache_list):
    idx = 0
    prior_knowledge_list = []
    for iter_pass_cache in pass_cache_list:
        prior_knowledge_str = ""
        func_name = iter_pass_cache.get("func_name")
        var_name = iter_pass_cache.get("var_name")
        node_type = iter_pass_cache.get("type")
        pass_params = iter_pass_cache.get("pass_params")
        idx += 1

        if node_type == "stack_lvar":
            is_reg = pass_params.get("reg_or_stack") == "Register"
            lvar_size = pass_params.get("lvar_size")
            dist_to_ret = "None" if is_reg else pass_params.get("dist_to_ret")
            offset_to_sp = "None" if is_reg else pass_params.get("offset_to_sp")
            lvar_type = pass_params.get("lvar_type")
            reg_or_stack = pass_params.get("reg_or_stack")

            prior_knowledge_str = (
                f"{idx}.{node_type} for Function: {func_name} | Variable: {var_name}\n"
            )
            prior_knowledge_str += (
                f"The local variable is stored in the {reg_or_stack}.\n"
            )
            prior_knowledge_str += (
                f"Its data type is {lvar_type}, with a size of {lvar_size} bytes.\n"
            )
            if not is_reg:
                prior_knowledge_str += (
                    f"It is located {dist_to_ret} bytes away from the return address "
                    f"and has an offset of {offset_to_sp} from the stack pointer.\n"
                )
        elif node_type == "inner_call":
            func_name_list = pass_params.get("func_name")
            func_type_list = pass_params.get("func_type")
            prior_knowledge_str = f"{idx}.{node_type} for Function: {func_name}\n"
            for i in range(len(func_name_list)):
                callee = func_name_list[i]
                ctype = func_type_list[i]
                prior_knowledge_str += (
                    f"It internally calls {callee}, which is classified as {ctype}.\n"
                )

        elif node_type == "fetch_pcode":
            pcode = pass_params.get("pcode")
            prior_knowledge_str = f"{idx}.{node_type} for Function: {func_name}\n"
            prior_knowledge_str += f"The function's decompiled P-code is: {pcode}"

        elif node_type == "fetch_disasm":
            ehasm = pass_params.get("ehasm")
            prior_knowledge_str = f"{idx}.{node_type} for Function: {func_name}\n"
            prior_knowledge_str += f"The function's disassembly is: {ehasm}"

        elif node_type == "global_var":
            g_type = pass_params.get("global_var_type")
            g_size = pass_params.get("global_var_size")
            ref_funcs = pass_params.get("ref_func_list")
            # print(pass_params)
            # print(ref_funcs)
            ref_func_str = ", ".join(ref_funcs)
            ea = pass_params.get("addr_ea")
            prior_knowledge_str = f"{idx}.{node_type} for Variable: {var_name}\n"
            prior_knowledge_str += f"The global variable has type {g_type} and size {g_size} bytes, located at address {ea}.\n"
            if ref_funcs:
                prior_knowledge_str += (
                    f"It is referenced by the following functions: {ref_func_str}\n"
                )

        prior_knowledge_str = prior_knowledge_str.rstrip("\n")
        prior_knowledge_list.append(prior_knowledge_str)

    return prior_knowledge_list


# HEU2
def build_userdef_graph(func_call_dict: Dict[str, List[Dict]]) -> Dict[str, List[str]]:
    graph: Dict[str, List[str]] = {}
    all_funcs: Set[str] = set(func_call_dict.keys())

    for caller, calls in func_call_dict.items():
        for call in calls or []:
            if call.get("cat") == "USER_DEF":
                callee = call.get("name")
                if not callee:
                    continue
                graph.setdefault(caller, []).append(callee)
                all_funcs.add(callee)

    for caller, neigh in list(graph.items()):
        graph[caller] = list(dict.fromkeys(neigh))

    for f in all_funcs:
        graph.setdefault(f, [])

    return graph


def find_all_complete_call_chains(
    entry_point_func: str, func_call_dict: Dict[str, List[Dict]]
) -> List[List[str]]:

    graph = build_userdef_graph(func_call_dict)

    if entry_point_func not in graph:
        graph[entry_point_func] = []

    results: List[List[str]] = []

    def dfs(node: str, path: List[str], onpath: Set[str]):
        children = [c for c in graph.get(node, []) if c not in onpath]

        if not children:
            results.append(path.copy())
            return

        for c in children:
            onpath.add(c)
            path.append(c)
            dfs(c, path, onpath)
            path.pop()
            onpath.remove(c)

    dfs(entry_point_func, [entry_point_func], {entry_point_func})
    return results


def _dedupe_paths(paths: List[List[str]]) -> List[List[str]]:
    seen = set()
    uniq: List[List[str]] = []
    for p in paths:
        t = tuple(p)
        if t not in seen:
            seen.add(t)
            uniq.append(p)
    return uniq


def package_call_chains(
    entry_point_func: str,
    func_call_dict: Dict[str, List[Dict]],
    pcode_dict: Optional[Dict[str, Any]],
    slog: Optional[Any] = None,
) -> List[Dict[str, Any]]:

    reason_str = (
        "This is a complete function-call path starting from the entry function, with no explicit source or sink. "
        "Calls to randomness functions may influence data flow and control flow; "
        "although there is no directly observable sink API, some memory read/write operations along the path may still pose security risks. "
        "The path begins at the entry function and ends at the leaf function at the end of the call chain."
    )

    if slog:
        slog.debug(
            "Building all complete USER_DEF call chains from entry: %s",
            entry_point_func,
        )

    paths = find_all_complete_call_chains(entry_point_func, func_call_dict)

    paths = _dedupe_paths(paths)

    result: List[Dict[str, Any]] = []
    for path in paths:
        pcode_list = [
            pcode_dict.get(fn) if isinstance(pcode_dict, dict) else None
            for fn in (path or [])
        ]

        propagation_object = {
            "source_api": "currently unknown or nonexistent source",
            "source_caller": "currently unknown or nonexistent source",
            "sink_api": "currently unknown or nonexistent sink",
            "sink_caller": "currently unknown or nonexistent sink",
            "call_chain": path,
            "pcode_list": pcode_list,
            "reason": reason_str,
        }
        result.append(propagation_object)

    if slog:
        slog.info("Packaged %d call-chain objects (unique)", len(result))

    return result


if __name__ == "__main__":
    func_call_dict = {
        "main": [
            {"name": "printLine", "cat": "USER_DEF", "ln": 10},
            {"name": "foo", "cat": "USER_DEF", "ln": 11},
            {"name": "printLine", "cat": "USER_DEF", "ln": 12},  # duplicate callee
        ],
        "printLine": [],
        "foo": [{"name": "bar", "cat": "USER_DEF", "ln": 20}],
        "bar": [],
    }

    pcode_dict = {k: f"pcode({k})" for k in func_call_dict.keys()}
    packaged = package_call_chains("main", func_call_dict, pcode_dict)

    from pprint import pprint

    pprint(packaged)


def lookup_all(target_object, func_name, remap_name):
    return target_object.get(func_name) or target_object.get(remap_name)


def build_propagation_list_from_static_sinks(
    entry_point_func: str,
    static_sinks: List[Tuple[str, str]],  # [(sink_caller, sink_api), ...]
    runner: Any,
    pcode_dict: Optional[Dict[str, Any]] = None,
    slog: Optional[Any] = None,
    max_paths_per_sink: Optional[int] = None,
) -> List[Dict[str, Any]]:

    reason_str = (
        "This is a potential path: a sink is present on the path, but the source is currently unknown. "
        "The payload produced by the source may originate from parameters accepted by the program, or from external input obtained via wrapped input functions it calls; it may also originate from non-user input, such as the program's own constants, static values, results of string operations, or generated data. "
        "If such sources exist and propagate along the data flow into the sink, then they constitute potential sources that can influence the vulnerability. "
        "Similarly, the sink itself on this path may not exhibit a vulnerability, but some memory reads and writes along the path may still be vulnerable and therefore also require analysis and inspection. "
        "This path begins at the entry function and ends at the caller of the sink."
    )

    if not entry_point_func:
        if slog:
            slog.warning("[STATIC_SINK] entry_point_func is empty")
        return []

    if not static_sinks:
        if slog:
            slog.info("[STATIC_SINK] static_sinks is empty")
        return []

    dfs_cache: Dict[Tuple[str, str], List[List[str]]] = {}

    seen = set()

    propagation_list: List[Dict[str, Any]] = []

    for sink_caller, sink_api in static_sinks:
        if not sink_caller or not sink_api:
            if slog:
                slog.warning(
                    f"[STATIC_SINK] invalid item: sink_caller={sink_caller}, sink_api={sink_api}"
                )
            continue

        dfs_key = (entry_point_func, sink_caller)
        if dfs_key in dfs_cache:
            paths = dfs_cache[dfs_key]
        else:
            try:
                paths = runner.get_dfs_call_chains(entry_point_func, sink_caller) or []
            except Exception as e:
                if slog:
                    slog.warning(
                        f"[DFS_ERROR] {entry_point_func} -> {sink_caller} (sink_api={sink_api}): {e}"
                    )
                paths = []
            dfs_cache[dfs_key] = paths

        if not paths:
            if slog:
                slog.info(
                    f"[STATIC_SINK] No path: {entry_point_func} -> {sink_caller}, skip (sink_api={sink_api})"
                )
            continue

        if paths and isinstance(paths, list) and paths and isinstance(paths[0], str):
            paths = [paths]

        if max_paths_per_sink is not None and max_paths_per_sink > 0:
            paths = paths[:max_paths_per_sink]

        for path in paths:
            if not path:
                continue

            pcode_list = [
                (pcode_dict.get(fn) if isinstance(pcode_dict, dict) else None)
                for fn in path
            ]

            obj = {
                "source_api": "currently unknown or nonexistent source",
                "source_caller": "currently unknown or nonexistent source",
                "sink_api": sink_api,
                "sink_caller": sink_caller,
                "call_chain": path,
                "pcode_list": pcode_list,
                "reason": reason_str,
            }

            dedup_key = (sink_caller, sink_api, tuple(path))
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            propagation_list.append(obj)

        if slog:
            slog.info(
                f"[STATIC_SINK] target=({sink_caller}, {sink_api}) paths={len(paths)}"
            )

    if slog:
        slog.info(
            f"[STATIC_SINK_SUMMARY] total_items={len(propagation_list)} targets={len(static_sinks)}"
        )

    return propagation_list


import re

_ASSIGN_NONZERO_PATTERN = re.compile(
    r'^\s*[^=]+ = (?!0(?:$|;)|0x0(?:$|;)|0\.0(?:$|;)|0d(?:$|;)|__readfsqword).+'
)


def _has_nonzero_assignment_simple(pcode):

    if not pcode:
        return False

    for line in pcode.splitlines():
        # Match the regex directly without extra handling
        if _ASSIGN_NONZERO_PATTERN.match(line):
            return True

    return False

def _filter_max_coverage_propagations(propagation_list):

    chains = [tuple(obj.get("call_chain") or []) for obj in propagation_list]
    keep_idx = set(range(len(chains)))

    for i, ci in enumerate(chains):
        if not ci:
            continue
        for j, cj in enumerate(chains):
            if i == j:
                continue
            if len(ci) < len(cj) and cj[:len(ci)] == ci:
                if i in keep_idx:
                    keep_idx.remove(i)
                break

    return [propagation_list[i] for i in range(len(propagation_list)) if i in keep_idx]


def _normalize_pcode_body(pcode: Optional[str]) -> Optional[str]:
    if not pcode or not isinstance(pcode, str):
        return None

    lines = pcode.splitlines()
    if not lines:
        return None

    if lines[0].startswith("Real symbol name:"):
        lines = lines[1:]

    if not lines:
        return ""
    first = lines[0].strip()
    if (
        "(" in first
        and ")" in first
        and not first.endswith(";")
        and not first.startswith("{")
    ):
        lines = lines[1:]

    if not lines:
        return ""

    body = "\n".join(lines).strip()
    return body



def _dedupe_leaf_equivalent_paths(propagation_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = {}  # key -> first index
    keep_flags = [True] * len(propagation_list)

    for idx, obj in enumerate(propagation_list):
        chain = obj.get("call_chain") or []
        pcode_list = obj.get("pcode_list") or []

        if not chain:
            continue

        leaf_pcode = pcode_list[-1] if pcode_list else None

        norm_body = _normalize_pcode_body(leaf_pcode)
        if norm_body is None:
            continue

        prefix = tuple(chain[:-1])

        key = (prefix, norm_body)

        if key in seen:
            keep_flags[idx] = False
        else:
            seen[key] = idx

    return [
        obj
        for i, obj in enumerate(propagation_list)
        if keep_flags[i]
    ]



# HEU2
def make_propagation_across_memwrite_from_main(
    entry_point_func,
    internal_func_list,
    pcode_dict,
    runner,
    slog=None,
):

    result = []
    reason_str = (
        "This is a potential path: there is a sink on the path, but its corresponding source is currently unknown or lies outside the current chain. Conversely, there may be a source on the path while the sink is unclear or lies outside the chain. When one endpoint is missing but there is certain key data-flow evidence, you must treat it as an incomplete but extensible chain and perform topological completion on it. "
        "The payload produced by the source may originate from parameters accepted by the program, or from external input obtained via wrapped input functions it calls; it may also originate from non-user input, such as the program's own constants, static values, results of string operations, or generated data. If such sources exist and propagate along the data flow into the sink, then they constitute potential sources that can influence the vulnerability. "
        "Similarly, the sink on this path itself may not directly exhibit a vulnerability, but certain data-flow-related memory read and write operations either along the path or in out-of-chain functions connected via the data flow may still pose additional vulnerability risks and therefore also require analysis and inspection. As a result, more thorough checking of the data flow is necessary. "
        "Whenever pointers or references are passed between functions, treat them as tainted-data carriers and keep tracking every dereference, since the real sink often appears downstream."
    )

    for item in internal_func_list or []:
        fn = item.get("name")
        if not fn:
            continue

        pcode = pcode_dict.get(fn) if isinstance(pcode_dict, dict) else None
        if not pcode:
            continue

        if not _has_nonzero_assignment_simple(pcode):
            continue

        try:
            paths = runner.get_dfs_call_chains(entry_point_func, fn) or []
        except Exception as e:
            if slog:
                slog.warning(f"get_dfs_call_chains failed for {fn}: {e}")
            paths = []

        if not paths:
            continue

        for path in paths:
            pcode_list = [
                pcode_dict.get(node) if isinstance(pcode_dict, dict) else None
                for node in (path or [])
            ]

            propagation_object = {
                "source_api": "currently unknown or nonexistent source",
                "source_caller": "currently unknown or nonexistent source",
                "sink_api": "memory write operations",
                "sink_caller": fn,
                "call_chain": path,
                "pcode_list": pcode_list,
                "reason": reason_str,
            }
            result.append(propagation_object)

    before_filter = len(result)
    result = _filter_max_coverage_propagations(result)
    after_maxcov = len(result)

    result = _dedupe_leaf_equivalent_paths(result)
    after_leaf_dedupe = len(result)

    if slog:
        slog.info(
            "[HEU2] memwrite paths: before=%d, after_maxcov=%d, after_leaf_dedupe=%d",
            before_filter, after_maxcov, after_leaf_dedupe,
    )

    return result
