from Core.Runner import RunnerEntity
from Core.Algorithm import *
from Core.GdbBridge import GdbDebugger, GdbTimeoutError
from Agents.AgentsRole import *
from Utils.Logger import slog, ObjectLogger
from Utils.DataCache import  both_reason_str, cwe121_api_ans_cache, cwe122_api_ans_cache, cwe78_api_ans_cache, cwe134_api_ans_cache
from Utils.DataUtil import count_sink_api_in_source, append_unique_by_call_chain
from pathlib import Path


def main_process(bin_path, cwe_type, direct_flag=False, static_sinks=[]):
    ida_path = "/home/workspace/ida-pro-9.1/ida"
    log_path = "/home/workspace/HypD_master/Log/output.log"
    ida_util_path = "/home/workspace/ida_util"
    gdb_tracebreak_path = "/home/workspace/ida_util/trace_break2.py"
    base_addr = "0x555555554000"
    runner = RunnerEntity(
        ida_path=ida_path,
        log_path=log_path,
        ida_util_path=ida_util_path,
        target_bin_path=bin_path,
    )

    # obj_logger = ObjectLogger(bin_path)

    target_dir = Path(bin_path).resolve().parent

    slog.info("START")

    runner.ext_clean()
    runner.funcname_clean()

    entry_point_func = runner.get_entry_point().get("entry_func")
    # slog.info(entry_point_func)

    internal_func_list = runner.fetch_internal_func()
    # slog.info(str(internal_func_list))

    import_api_list = runner.fetct_import_api()
    # slog.info(str(import_api_list))

    symbols_length = runner.build_syms_object()
    syms_path = target_dir / "syms.o"
    # slog.info(f"{symbols_length} - {syms_path}")

    """
    cg = runner.get_reachable_callgraph_from_entry(entry_point_func) or {}
    reachable_names = (cg.get("reachable_funcs") or []) if isinstance(cg, dict) else []
    reachable_set = set(reachable_names)
    #slog.info(reachable_names)
    #slog.info(reachable_set)

    reachable_funcs = []
    for iter_func in list(internal_func_list):
        fn = iter_func.get("name")
        if fn == entry_point_func:
            reachable_funcs.append(iter_func)
            continue
        if fn in reachable_set:
            reachable_funcs.append(iter_func)
        else:
            pass
            #slog.info(f"Drop unreachable func: {fn} (from {entry_point_func})")

    internal_func_list = reachable_funcs
    """
    # slog.info(f"Reachable funcs ({len(internal_func_list)}): {internal_func_list}")

    # ApiDetecter

    # api_detector = ApiDetecter(cwe_type=cwe_type, api_list=import_api_list)
    # api_ans_str = api_detector.create().read()
    # api_ans = json.loads(api_ans_str)
    # slog.info(str(api_ans))

    # api_ans = api_ans_cache
    if cwe_type == "121":
        api_ans = cwe121_api_ans_cache
    if cwe_type == "122":
        api_ans = cwe122_api_ans_cache
    if cwe_type == "78":
        api_ans = cwe78_api_ans_cache
    if cwe_type == "134":
        api_ans = cwe134_api_ans_cache

    source_api_set = []
    sink_api_set = []
    for iter_api in api_ans:
        if not iter_api:
            continue
        func_name, info = next(iter(iter_api.items()))
        t = (info.get("type") or "").strip().lower()
        if t == "source":
            source_api_set.append(func_name)
        if t == "sink":
            sink_api_set.append(func_name)
    # slog.info(source_api_set)
    # slog.info(sink_api_set)

    # call
    slog.debug("---CALL---")
    internal_func_names_list = [item.get("name") for item in internal_func_list]
    all_call_dict = runner.fetch_func_calls(internal_func_names_list)
    func_use_api_dict = {}
    func_call_dict = {}
    # call_type_dict = {}

    for iter_func in internal_func_list:
        iter_func_name = iter_func.get("name")
        # call_find_v7 returns JSON shaped like { func_name: [calls...] }
        call_list = all_call_dict.get(iter_func_name, [])
        func_call_dict[iter_func_name] = call_list
        # slog.info(func_call_dict)
        api_use_list = [
            c.get("name") for c in call_list if c.get("cat") == "IMPORT_API"
        ]
        # Deduplicate while preserving order
        api_use_list = list(dict.fromkeys(api_use_list))
        func_use_api_dict[iter_func_name] = api_use_list
    # slog.info(func_call_dict)

    # stack
    slog.debug("---STACK---")
    all_stack_dict = runner.fetch_func_local_vars(internal_func_names_list)
    local_var_dict = {}

    for iter_func in internal_func_list:
        iter_func_name = iter_func.get("name")
        func_stack_info = all_stack_dict.get(iter_func_name, {})
        local_var_list = func_stack_info.get("variables", [])
        local_var_dict[iter_func_name] = local_var_list
    # slog.info(local_var_dict)

    # global
    # slog.debug("---GLOBAL---")
    global_var_dict = {}
    global_var_dict_re = runner.fetch_global_var()
    for ea, info in global_var_dict_re.items():
        item = info.copy()
        name = item.pop("name")
        item["addr_ea"] = ea
        global_var_dict[name] = item
    # slog.info(global_var_dict)

    # pcode
    # slog.debug("---PCODE---")
    internal_func_names_list = [item.get("name") for item in internal_func_list]
    all_disasm_dict = runner.fetch_internal_disasm(internal_func_names_list)
    pcode_dict = {}
    ehasm_dict = {}
    demangle_to_symbol_dict = {}
    symbol_to_demangle_dict = {}
    for func_name, dis_code in all_disasm_dict.items():
        pcode_dict[func_name] = f"Real symbol name: {func_name}\n"
        pcode_dict[func_name] += dis_code.get("pcode")
        ehasm_dict[func_name] = dis_code.get("disasm_enhanced")
        demangle_to_symbol_dict[dis_code.get("demangle_name")] = func_name
        symbol_to_demangle_dict[func_name] = dis_code.get("demangle_name")
        """
        if pcode_dict[func_name].find("alloca(") >= 0:
            pcode_dict[func_name] += "\n" + ehasm_dict[func_name]
        """
    # slog.info(pcode_dict)

    # exit()

    # slog.info(source_sink_edges)

    propagation_list = []

    if direct_flag == False:
        
        if (True):
            source_sink_edges = []
        else:
            source_sink_edges = make_callchains_edges(
                func_use_api_dict, source_api_set, sink_api_set, runner
            )

        for edge in source_sink_edges:
            src_api = edge.get("source_api")
            src_caller = edge.get("source_caller")
            sink_api = edge.get("sink_api")
            sink_caller = edge.get("sink_caller")
            paths = edge.get("path") or []

            for path_seq in paths:
                pcode_list = []
                for func in path_seq:
                    pcode = pcode_dict.get(func)
                    if pcode is None:
                        slog.warning(f"[PCODE_MISS] missing pcode for: {func}")
                    pcode_list.append(pcode)
                # slog.info(f"[PATH] {src_api}({src_caller}) -> {sink_api}({sink_caller}) | path: {path_seq}")

                propagation_object = {
                    "source_api": src_api,
                    "source_caller": src_caller,
                    "sink_api": sink_api,
                    "sink_caller": sink_caller,
                    "call_chain": path_seq,
                    "pcode_list": pcode_list,
                    "reason": both_reason_str,
                }

                if src_caller == sink_caller:
                    propagation_list.append(propagation_object)
                    # slog.info(propagation_object)
                    continue

                path_tainter = PathTainter(
                    cwe_type=cwe_type,
                    source_api=src_api,
                    sink_api=sink_api,
                    call_chains=path_seq,
                    pcode_list=pcode_list,
                )
                taint_ans_str = path_tainter.create().read()
                taint_ans = json.loads(taint_ans_str)
                if taint_ans.get("is") == True:
                    propagation_object["reason"] = taint_ans.get("reason")
                    propagation_list.append(propagation_object)
                    # slog.info(propagation_object)

        slog.info(str(sink_api_set))
        # HEU PATH1
        add_propagation_list = make_propagation_across_from_main(
            entry_point_func=entry_point_func,
            internal_func_list=internal_func_list,
            func_use_api_dict=func_use_api_dict,
            sink_api_set=sink_api_set,
            pcode_dict=pcode_dict,
            runner=runner,
            slog=slog,
        )

        cnt = count_sink_api_in_source(add_propagation_list, source_api_set)
        slog.info(f"[HEU PATH1] sink_api in source_api_set count={cnt}")
        slog.info([p.get("call_chain") for p in add_propagation_list])
        propagation_list = propagation_list + add_propagation_list

        # HEU PATH2 trigger condition:
        # All newly added propagation entries have sink_api that also appear in source_api_set
        if (not add_propagation_list) or (cnt == len(add_propagation_list)):

            if (cnt > 0):
                slog.info("[HEU PATH1] All added propagation's sink_api are in source_api_set, need HEU PATH2")
            else:
                slog.info("[HEU PATH1] No propagation found, fallback to HEU PATH2")

            # Invoke HEU2 to locate explicit non-zero memory write paths starting from the entry
            heu2_propagation_list = make_propagation_across_memwrite_from_main(
                entry_point_func=entry_point_func,
                internal_func_list=internal_func_list,
                pcode_dict=pcode_dict,
                runner=runner,
                slog=slog,
            )

            slog.info(
                f"[HEU PATH2] extra propagation count={len(heu2_propagation_list or [])}"
            )
            slog.info([p.get("call_chain") for p in heu2_propagation_list])

            propagation_list = append_unique_by_call_chain(
                propagation_list,
                heu2_propagation_list,
            )

    elif direct_flag == True:
        propagation_list = build_propagation_list_from_static_sinks(
            entry_point_func=entry_point_func,
            static_sinks=static_sinks,
            runner=runner,
            pcode_dict=pcode_dict,
            slog=slog,
            max_paths_per_sink=20,
        )

    slog.info(f"[EDGE_PCODE_PATHS_SUMMARY] total_items={len(propagation_list)}")
    #slog.info(propagation_list)
    # obj_logger.save_log(propagation_list, log_type="propagation_final")
    # slog.debug("HIT")
    # exit()
    # return 0
    # VULN

    # HypDetective: one-shot, hypothesis-only chain-centric vulnerability reasoning.
    # For each propagation chain, we call VulnFinder exactly once, without any
    # evidence primitives or obligation gating. The model must decide based only
    # on the decompiled slice and taint report for that chain.
    vuln_list = []
    status_record = []
    idx = 0
    slog.info("---VULN START (HypDetective one-shot)---")
    for iter_propagation in propagation_list:

        idx += 1
        source_api = iter_propagation.get("source_api")
        sink_api = iter_propagation.get("sink_api")
        call_chains_list = iter_propagation.get("call_chain")
        pcode_list = iter_propagation.get("pcode_list")
        reason = iter_propagation.get("reason")

        # Direct one-shot VulnFinder invocation on the chain-local view.
        vuln_finder = VulnFinder(
            cwe_type=cwe_type,
            source_api=source_api,
            sink_api=sink_api,
            call_chains=call_chains_list,
            pcode_list=pcode_list,
            taint_report=reason,
            obligation_gate_str="",
            mini_primitives=[],
        )
        vuln_ans_str = extract_json_string(vuln_finder.create().read())
        try:
            vuln_ans = json.loads(vuln_ans_str)
        except json.JSONDecodeError as e:
            slog.error(f"[HypDetective] JSON decode error in VulnFinder response (idx={idx}): {e}")
            slog.error(f"[HypDetective] Raw output: {vuln_ans_str}")
            continue

        obligations_status = vuln_ans.get("obligations_status")
        if not isinstance(obligations_status, dict):
            # Fallback default when the model does not return per-aspect status.
            obligations_status = {
                "O1": "Unknown",
                "O2": "Unknown",
                "O3": "Unknown",
                "O4": "Unknown",
            }

        # Record a single non-interactive reasoning step.
        status_record.append(
            {
                "llm_reason": [vuln_ans.get("reason")],
                "llm_obligations_status": [obligations_status],
                "real_obligations_status": [obligations_status],
                "gating_flag": False,
                "pass_cache_list": [],
            }
        )

        if vuln_ans.get("is_vuln") is True:
            vuln_list.append(
                {
                    "propagation": iter_propagation,
                    "vuln_report": vuln_ans.get("reason"),
                    "pass_cache_list": [],
                }
            )
            # For Q4 ablation, we keep the behavior of stopping after the first
            # confirmed vulnerable propagation.
            break

    runner.db_clean()
    slog.info(f"[VULN_SUMMARY] total={len(vuln_list)}")
    return len(vuln_list), status_record

# POC
    poc_list = []
    for iter_vuln in vuln_list:
        iter_propagation = iter_vuln.get("propagation")
        iter_vuln_report = iter_vuln.get("vuln_report")
        pass_cache_list = iter_vuln.get("pass_cache_list")
        prior_knowledge_list = pass_cache_reform(pass_cache_list)
        # REUSE
        source_api = iter_propagation.get("source_api")
        sink_api = iter_propagation.get("sink_api")
        call_chains_list = iter_propagation.get("call_chain")
        pcode_list = iter_propagation.get("pcode_list")
        reason = iter_propagation.get("reason")

        # PREFIX
        first_func = call_chains_list[0]
        if entry_point_func != first_func:
            paths = runner.get_dfs_call_chains(entry_point_func, first_func) or []
            if paths:
                shortest = min(paths, key=len)
                prefix_path = shortest[:-1] if shortest else []
            else:
                prefix_path = []
            pre_pcode_list = [pcode_dict.get(f, None) for f in prefix_path]
            call_chains_list = prefix_path + call_chains_list
            pcode_list = pre_pcode_list + pcode_list

            iter_propagation["call_chain"] = call_chains_list
            iter_propagation["pcode_list"] = pcode_list
            # iter_vuln["propagation"] = iter_propagation

        poc_genner = PoCGenner(
            cwe_type=cwe_type,
            source_api=source_api,
            sink_api=sink_api,
            call_chains=call_chains_list,
            pcode_list=pcode_list,
            taint_report=reason,
            vuln_report=iter_vuln_report,
            bin_path=bin_path,
            prior_knowldege_list=prior_knowledge_list,
        )
        poc_ans_str = poc_genner.create().read()
        poc_ans = parse_poc_str(poc_ans_str)

        # obj_logger.save_log(poc_ans,log_type="poc")

        final_flag = False if poc_ans.get("state") == "interactive" else True
        while final_flag == False:
            query_type = poc_ans.get("query_type")
            func_name = poc_ans.get("func")
            var_name = poc_ans.get("var")
            if query_type == "stack_lvar":
                local_var_list = local_var_dict.get(func_name)
                if local_var_list == None:
                    pass_params = {
                        "lvar_size": "Error because unknown function name",
                        "dist_to_ret": "Error because unknown function name",
                        "offset_to_sp": "Error because unknown function name",
                        "lvar_type": "Error because unknown function name",
                        "reg_or_stack": "Error because unknown function name",
                    }
                else:
                    lvar_idx = next(
                        (
                            i
                            for i, d in enumerate(local_var_list)
                            if d.get("lvar_name") == var_name
                        ),
                        -1,
                    )
                    reg_flag = (
                        True
                        if local_var_list[lvar_idx].get("reg_id") != None
                        else False
                    )
                    pass_params = {
                        "lvar_size": local_var_list[lvar_idx].get("lvar_size"),
                        "dist_to_ret": local_var_list[lvar_idx].get(
                            "dist_from_ret_addr"
                        ),
                        "offset_to_sp": local_var_list[lvar_idx].get("lvar_offset"),
                        "lvar_type": local_var_list[lvar_idx].get("lvar_type"),
                        "reg_or_stack": "Register" if reg_flag else "Stack",
                    }
            elif query_type == "inner_call":
                func_call_list = func_call_dict.get(func_name)
                dep_func_call_list = dep_list_by_name(func_call_list)
                func_name_list = [d.get("name") for d in dep_func_call_list]
                func_type_list = [d.get("cat") for d in dep_func_call_list]
                call_type_list = [d.get("call_type") for d in dep_func_call_list]
                pass_params = {"func_name": func_name_list, "func_type": func_type_list}
            elif query_type == "fetch_pcode":
                pcode = pcode_dict.get(func_name)
                pass_params = {"pcode": pcode}
            elif query_type == "fetch_disasm":
                ehasm = ehasm_dict.get(func_name)
                pass_params = {"ehasm": ehasm}
            elif query_type == "global_var":
                global_var = global_var_dict.get(var_name)
                ref_list = global_var.get("references")
                ref_func_list = list(
                    dict.fromkeys(d.get("function_name") for d in ref_list)
                )
                pass_params = {
                    "global_var_type": global_var.get("type"),
                    "global_var_size": global_var.get("tsize_bytes"),
                    "ref_func_list": ref_func_list,
                    "addr_ea": global_var.get("addr_ea"),
                }

            pass_cache_list.append(
                {
                    "func_name": func_name,
                    "var_name": var_name,
                    "pass_params": pass_params,
                    "type": query_type,
                }
            )
            poc_ans_str = poc_genner.interact(
                prior_info=pass_params, type=query_type
            ).read()
            poc_ans = parse_poc_str(poc_ans_str)

            # obj_logger.save_log(poc_ans,log_type="poc")

            final_flag = False if poc_ans.get("state") == "interactive" else True

        poc_list.append(
            {
                "propagation": iter_propagation,
                "vuln_report": iter_vuln_report,
                "poc_code": poc_ans.get("poc_code"),
                "pass_cache_list": pass_cache_list,
            }
        )

    # slog.info(str(poc_list))
    slog.info(f"[POC_SUMMARY] total={len(poc_list)}")
    debug_flag = True

    obj_logger.save_log(vuln_list, log_type="vuln_final")
    obj_logger.save_log(poc_list, log_type="poc_final")
    slog.info("---END---")

    # return
    # DEBUG
    success_list = []
    for iter_poc in poc_list:
        poc_output = runner.poc_run_test(iter_poc.get("poc_code"))

        iter_propagation = iter_poc.get("propagation")
        iter_vuln_report = iter_poc.get("vuln_report")
        pass_cache_list = iter_poc.get("pass_cache_list")
        prior_knowledge_list = pass_cache_reform(pass_cache_list)
        # REUSE
        source_api = iter_propagation.get("source_api")
        sink_api = iter_propagation.get("sink_api")
        call_chains_list = iter_propagation.get("call_chain")
        pcode_list = iter_propagation.get("pcode_list")
        reason = iter_propagation.get("reason")

        if poc_output.find("VULN_FIND") >= 0:
            success_list.append(iter_propagation)
            slog.warning(f"PWN with :\n{iter_propagation}")
            obj_logger.save_log(
                {"p": iter_propagation, "poc": iter_poc.get("poc_code")}, log_type="poc"
            )

        else:
            code_adjustor = CodeAdjustor(iter_poc.get("poc_code"), bin_path)
            poc_debug_code = code_adjustor.create().read()
            slog.debug(poc_debug_code)

            async_flag = runner.poc_run_async(poc_debug_code)
            if async_flag == True:
                target_pid = runner.catch_pid()

                dbg = GdbDebugger(
                    pid=target_pid,
                    entry_function=entry_point_func,
                    symbol_path=syms_path,
                    base_addr=base_addr,
                    plugin_path=gdb_tracebreak_path,
                )
                dbg.attach_and_setup()
                for iter_func_name in call_chains_list:
                    dbg.interact(f"traceset *{iter_func_name}")
                dbg_output = dbg.interact(f"x/5i $pc").get("stdout")

                poc_debugger = PoCDebugger(
                    cwe_type=cwe_type,
                    source_api=source_api,
                    sink_api=sink_api,
                    call_chains=call_chains_list,
                    pcode_list=pcode_list,
                    taint_report=reason,
                    vuln_report=iter_vuln_report,
                    bin_path=bin_path,
                    prior_knowldege_list=prior_knowledge_list,
                    poc_code=iter_poc.get("poc_code"),
                    disasm=dbg_output,
                )
                pd_ans_str = poc_debugger.create().read()
                pd_ans = parse_debug_str(pd_ans_str)
                # obj_logger.save_log(pd_ans,log_type="debug")
                final_flag = False if pd_ans.get("state") == "interactive" else True
                while final_flag == False:
                    gdb_resp = []
                    gdb_command = pd_ans.get("gdb_cmd")
                    for iter_cmd in gdb_command:
                        try:
                            resp = dbg.interact(iter_cmd)
                            out = (resp or {}).get("stdout")
                            out = (
                                out if (out is not None and out != "") else "Stop/None"
                            )
                        except Exception as e:
                            if (
                                str(e).find("Did not get response") >= 0
                                or str(type(e).__name__.find("GdbTimeoutError")) >= 0
                            ):
                                msg = "During interaction, the target program terminated or ran away, causing a GDB timeout. The interaction phase is now over; proceed to the PoC output phase."
                                gdb_command = ["Useless now"]
                                gdb_resp = [msg]
                                slog.debug("%s - timeout: %s", iter_cmd, e)
                                break
                            else:
                                out = f"error: {type(e).__name__}: {e}"
                        slog.debug("%s - %s", iter_cmd, out)
                        gdb_resp.append(out)
                    pd_ans_str = poc_debugger.interact(gdb_command, gdb_resp).read()
                    pd_ans = parse_debug_str(pd_ans_str)
                    # obj_logger.save_log(pd_ans,log_type="debug")
                    final_flag = False if pd_ans.get("state") == "interactive" else True

                poc_output = runner.poc_run_test(pd_ans.get("poc_code"))
                if poc_output.find("VULN_FIND") >= 0:
                    success_list.append(iter_propagation)
                    slog.warning(f"PWN with :\n{iter_propagation}")
                    obj_logger.save_log(
                        {"p": iter_propagation, "poc": iter_poc.get("poc_code")},
                        log_type="poc",
                    )

    obj_logger.save_log(vuln_list, log_type="vuln_final")
    obj_logger.save_log(success_list, log_type="poc_final")
    slog.info("---END---")
