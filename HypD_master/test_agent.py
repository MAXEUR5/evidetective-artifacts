from Agents.AgentsRole import VulnFinder

vuln_finder = VulnFinder(
    "cwe_type", "source_api", "sink_api", "call_chains", "pcode_list", "taint_report"
)

call_prior={
    "func_name":['func1','func2','func3'],
    "func_type":['int','char *','Sturct XS']
}

#vuln_finder.interact(prior_info=call_prior,type='call',debug_enable=True)

global_prior={
    "global_var_type":'int',
    "global_var_size": 8,
    "ref_func_list":['func1','func2','func3']
}

#vuln_finder.interact(prior_info=global_prior,type='global',debug_enable=True)

stack_prior={
    "lvar_size": 8,
    "dist_to_ret": 0x10,
    "offset_to_sp": 0x20,
    "lvar_type": "double",
    "reg_or_stack": "Stack"
}
#vuln_finder.interact(prior_info=stack_prior,type='stack',debug_enable=True)

reg_prior={
    "lvar_size": 8,
    "lvar_type": "double",
    "reg_or_stack": "Register"
}
vuln_finder.interact(prior_info=reg_prior,type='stack',debug_enable=True)

