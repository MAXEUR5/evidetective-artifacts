from Core.Algorithm import *
pass_cache_list = []
pass_params = {
    "global_var_type": "int8",
    "global_var_size": 1,
    "ref_func_list": ["main", "pretender"],
    "addr_ea": 0x401000
}

pass_cache_list.append({"var_name": "bss_var",
                        "pass_params": pass_params, "type": "global_var"})

pass_params = {
                    "func_name": ["f1","gets","memcpy"],
                    "func_type": ["USER","API","API"]
                }

pass_cache_list.append({"func_name": "main",
                        "pass_params": pass_params, "type": "inner_call"})

print(pass_cache_reform(pass_cache_list))