from Core.Controller import *
from Utils.DataUtil import save_main_process_result
ans3=0
# exit()
# ans=main_process("/home/workspace/jc/juliet-test-suite-c/test/CWE121_Stack_Based_Buffer_Overflow__dest_char_alloca_cat_12-bad",cwe_type="121")
# ans=main_process("/home/workspace/jc/t1/CWE121_Stack_Based_Buffer_Overflow__src_char_declare_cat_82-bad",cwe_type="121")
'''
ans3 = main_process(
    "/home/workspace/juliet-test-suite-c/bin/CWE121/good/CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memmove_05-good",
    cwe_type="121",
)
ans4 = main_process(
    "/home/workspace/juliet-test-suite-c/bin/CWE121/bad/CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memmove_05-bad",
    cwe_type="121",
)
'''
'''
ans3 = main_process(
    "/home/workspace/juliet-test-suite-c/bin/CWE121/good/CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memmove_05-good",
    cwe_type="121",
    direct_flag=True,
    static_sinks=[("goodG2B1","memmove"),
                  ("goodG2B2","memmove")]
)

ans4 = main_process(
    "/home/workspace/juliet-test-suite-c/bin/CWE121/bad/CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memmove_05-bad",
    cwe_type="121",
    direct_flag=True,
    static_sinks=[("CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memmove_05_bad","memmove")]
)
'''
'''
ans3 = main_process(
    "/home/workspace/tp/bin/a2ps",
    cwe_type="121",
    direct_flag=True,
    static_sinks=[("subcontract","strcpy")]
)
'''

res3 = main_process(
    "/home/workspace/tp/bin/datamash",
    cwe_type="122",
    direct_flag=True,
    static_sinks=[("remove_dups_in_file","memcpy")]
)
res4 = main_process(
    "/home/workspace/tp/bin/a2ps",
    cwe_type="121",
    direct_flag=True,
    static_sinks=[("list_options","strcpy")]
)

ans3, evid_list3, status3 = res3
ans4, evid_list4, status4 = res4

p3 = save_main_process_result(
    bin_path="/home/workspace/tp/bin/datamash",
    static_sinks=[("remove_dups_in_file","memcpy")],
    result_tuple=res3,
    out_dir="./Log"
)
p4 = save_main_process_result(
    bin_path="/home/workspace/tp/bin/a2ps",
    static_sinks=[("list_options","strcpy")],
    result_tuple=res4,
    out_dir="./Log"
)

slog.info(f"{ans3} {ans4}")
slog.info(f"saved: {p3}")
slog.info(f"saved: {p4}")
