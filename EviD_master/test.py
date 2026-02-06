from Core.Controller import *
from Utils.DataUtil import save_main_process_result
TARGET_BIN_NAME = "unrtf"
BIN_DIR = "/home/workspace/small_case/realcase"
BIN_PATH = f"{BIN_DIR}/{TARGET_BIN_NAME}"

static_sinks = [("pp_open", "popen")]

res = main_process(
    BIN_PATH,
    cwe_type="476",
    direct_flag=True,
    static_sinks=static_sinks,
)

ans, status = res

p = save_main_process_result(
    bin_path=BIN_PATH,
    static_sinks=static_sinks,
    result_tuple=res,
    out_dir="./Log",
)

slog.info(f"{ans}")
slog.info(f"saved: {p}")