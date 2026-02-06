import json
import subprocess
import os
from typing import Tuple
from Utils.Logger import slog
from pathlib import Path
import time
import re

import os
import stat


def log_clean(log_path):
    if os.path.isfile(log_path):
        os.remove(log_path)

def read_log_and_output(log_path, output_path=None):
    encoding="utf-8"
    log_path = Path(log_path)
    output_path = Path(output_path) if output_path is not None else None

    with open(log_path, "r", encoding=encoding, errors="ignore") as fp:
        log_text = fp.read()

    script_result = None
    if output_path is not None:
        with open(output_path, "r", encoding=encoding) as fp:
            script_result = json.load(fp)

    return log_text, script_result

class RunnerEntity():
    SUB_TIMEOUT=600
    SLEEP_GAP=0.02
    IDA_PATH="/home/workspace/ida-pro-9.1/ida"
    LOG_PATH="/home/workspace/EviD_master/Log/output.log"
    IDA_S_PATH="/home/workspace/ida_util/"
    TARGET_BIN_PATH=""

    def __init__(self,ida_path,log_path,ida_util_path,target_bin_path):
        self.IDA_PATH=ida_path
        self.LOG_PATH=log_path
        self.IDA_S_PATH=ida_util_path
        self.TARGET_BIN_PATH=target_bin_path

    def funcname_clean(self):
        script_with_arg=self.IDA_S_PATH+r'/analysis_init/fn_clean_v1.py'
        log_clean(self.LOG_PATH)
        time.sleep(self.SLEEP_GAP)
        cmd=f'{self.IDA_PATH} -A -L"{self.LOG_PATH}" -S"{script_with_arg}" "{self.TARGET_BIN_PATH}"'
        slog.debug(cmd)

        try:
            subprocess.run(cmd, check=True, timeout=self.SUB_TIMEOUT,shell=True)
        except:
            time.sleep(self.SLEEP_GAP)
            subprocess.run(cmd, check=True, timeout=self.SUB_TIMEOUT,shell=True)

        try:
            log_text=read_log_and_output(log_path=self.LOG_PATH,output_path=None)[0]
        except:
            return self.funcname_clean();
        return None
    
    def get_entry_point(self):
        script_with_arg=self.IDA_S_PATH+r'/analysis_init/entry_find_v1.py'
        target_dir = Path(self.TARGET_BIN_PATH).resolve().parent
        output_path = target_dir / "entry_point.json"
        log_clean(self.LOG_PATH)
        cmd=f'{self.IDA_PATH} -A -L"{self.LOG_PATH}" -S"{script_with_arg}" "{self.TARGET_BIN_PATH}"'
        slog.debug(cmd)
        subprocess.run(cmd, check=True, timeout=self.SUB_TIMEOUT,shell=True)
        time.sleep(self.SLEEP_GAP)
        log_text,script_result=read_log_and_output(log_path=self.LOG_PATH,output_path=output_path)
        return script_result
 

    def fetch_internal_func(self):
        script_with_arg=self.IDA_S_PATH+r'/analysis_init/dump_all_internal_v2.py'
        target_dir = Path(self.TARGET_BIN_PATH).resolve().parent
        output_path = target_dir / "func_internal_list.json"
        log_clean(self.LOG_PATH)
        cmd=f'{self.IDA_PATH} -A -L"{self.LOG_PATH}" -S"{script_with_arg}" "{self.TARGET_BIN_PATH}"'
        slog.debug(cmd)
        subprocess.run(cmd, check=True, timeout=self.SUB_TIMEOUT,shell=True)
        time.sleep(self.SLEEP_GAP)
        log_text,script_result=read_log_and_output(log_path=self.LOG_PATH,output_path=output_path)
        return script_result

    def fetct_import_api(self):        
        script_with_arg=self.IDA_S_PATH+r'/analysis_init/imp_api_dump.py'
        target_dir = Path(self.TARGET_BIN_PATH).resolve().parent
        output_path = target_dir / "import_api_with_proto.json"
        log_clean(self.LOG_PATH)
        cmd=f'{self.IDA_PATH} -A -L"{self.LOG_PATH}" -S"{script_with_arg}" "{self.TARGET_BIN_PATH}"'
        slog.debug(cmd)
        subprocess.run(cmd, check=True, timeout=self.SUB_TIMEOUT,shell=True)
        time.sleep(self.SLEEP_GAP)
        log_text,script_result=read_log_and_output(log_path=self.LOG_PATH,output_path=output_path)
        return script_result

    def get_func_call(self,func_name):
        script_with_arg=self.IDA_S_PATH+r'/analysis_init/call_find_v7.py funcs_list={name}'.format(name=func_name)
        target_dir = Path(self.TARGET_BIN_PATH).resolve().parent
        output_path = target_dir / "func_call.json"
        log_clean(self.LOG_PATH)
        cmd=f'{self.IDA_PATH} -A -L"{self.LOG_PATH}" -S"{script_with_arg}" "{self.TARGET_BIN_PATH}"'
        slog.debug(cmd)
        subprocess.run(cmd, check=True, timeout=self.SUB_TIMEOUT,shell=True)
        time.sleep(self.SLEEP_GAP)
        log_text,script_result=read_log_and_output(log_path=self.LOG_PATH,output_path=output_path)
        return script_result


    #NEW FETCH START
    def fetch_func_calls(self, func_names):
        if not func_names:
            return {}

        # funcs_list=foo,bar,baz
        funcs_arg = ",".join(func_names)
        script_with_arg = (
            self.IDA_S_PATH
            + r'/analysis_init/call_find_v7.py funcs_list={names}'.format(names=funcs_arg)
        )

        target_dir = Path(self.TARGET_BIN_PATH).resolve().parent
        output_path = target_dir / "func_call.json"

        log_clean(self.LOG_PATH)
        cmd = f'{self.IDA_PATH} -A -L"{self.LOG_PATH}" ' \
              f'-S"{script_with_arg}" "{self.TARGET_BIN_PATH}"'
        slog.debug(cmd)
        subprocess.run(cmd, check=True, timeout=self.SUB_TIMEOUT, shell=True)
        time.sleep(self.SLEEP_GAP)

        log_text, script_result = read_log_and_output(
            log_path=self.LOG_PATH,
            output_path=output_path
        )
        return script_result
    

    def fetch_func_local_vars(self, func_names):
        if not func_names:
            return {}

        funcs_arg = ",".join(func_names)
        script_with_arg = (
            self.IDA_S_PATH
            + r'/analysis_init/func_stack_dump_v6.py funcs_list={names}'.format(names=funcs_arg)
        )

        target_dir = Path(self.TARGET_BIN_PATH).resolve().parent
        output_path = target_dir / "func_stack_varmatch.json"

        log_clean(self.LOG_PATH)
        cmd = f'{self.IDA_PATH} -A -L"{self.LOG_PATH}" ' \
              f'-S"{script_with_arg}" "{self.TARGET_BIN_PATH}"'
        slog.debug(cmd)
        subprocess.run(cmd, check=True, timeout=self.SUB_TIMEOUT, shell=True)
        time.sleep(self.SLEEP_GAP)

        log_text, script_result = read_log_and_output(
            log_path=self.LOG_PATH,
            output_path=output_path
        )
        return script_result
    #NEW FETCH END
        
    def fetch_internal_disasm(self,func_name_list):
        str_func_name_list=str(func_name_list).replace(" ","").replace("'","")
        script_with_arg=self.IDA_S_PATH+r'/analysis_init/dump_dis_v5.py funcs_list={fn_list}'.format(fn_list=str_func_name_list)
        target_dir = Path(self.TARGET_BIN_PATH).resolve().parent
        output_path = target_dir / "func_dis.json"
        log_clean(self.LOG_PATH)
        cmd=f'{self.IDA_PATH} -A -L"{self.LOG_PATH}" -S"{script_with_arg}" "{self.TARGET_BIN_PATH}"'
        slog.debug(cmd)
        subprocess.run(cmd, check=True, timeout=self.SUB_TIMEOUT,shell=True)
        time.sleep(self.SLEEP_GAP)
        log_text,script_result=read_log_and_output(log_path=self.LOG_PATH,output_path=output_path)
        return script_result

    def get_dfs_call_chains(self,source_caller,sink_caller):
        if(source_caller==sink_caller):
            return [[source_caller]]
        script_with_arg=self.IDA_S_PATH+r'/analysis_init/path_dfs_v5.py start_func={start_f} end_func={end_f}'.format(start_f=source_caller,end_f=sink_caller)
        target_dir = Path(self.TARGET_BIN_PATH).resolve().parent
        output_path = target_dir / "cc_dfs_path.json"
        log_clean(self.LOG_PATH)
        cmd=f'{self.IDA_PATH} -A -L"{self.LOG_PATH}" -S"{script_with_arg}" "{self.TARGET_BIN_PATH}"'
        slog.debug(cmd)
        subprocess.run(cmd, check=True, timeout=self.SUB_TIMEOUT,shell=True)
        time.sleep(self.SLEEP_GAP)
        log_text,script_result=read_log_and_output(log_path=self.LOG_PATH,output_path=output_path)
        return script_result
    
    def get_func_local_var(self,func_name):
        script_with_arg=self.IDA_S_PATH+r'/analysis_init/func_stack_dump_v5.py {name}'.format(name=func_name)
        target_dir = Path(self.TARGET_BIN_PATH).resolve().parent
        output_path = target_dir / "func_stack_varmatch.json"
        log_clean(self.LOG_PATH)
        cmd=f'{self.IDA_PATH} -A -L"{self.LOG_PATH}" -S"{script_with_arg}" "{self.TARGET_BIN_PATH}"'
        slog.debug(cmd)
        subprocess.run(cmd, check=True, timeout=self.SUB_TIMEOUT,shell=True)
        time.sleep(self.SLEEP_GAP)
        log_text,script_result=read_log_and_output(log_path=self.LOG_PATH,output_path=output_path)
        return script_result
    
    def fetch_global_var(self):
        script_with_arg=self.IDA_S_PATH+r'/analysis_init/global_find_v7.py'
        target_dir = Path(self.TARGET_BIN_PATH).resolve().parent
        output_path = target_dir / "global_var_ctree_refs.json"
        log_clean(self.LOG_PATH)
        cmd=f'{self.IDA_PATH} -A -L"{self.LOG_PATH}" -S"{script_with_arg}" "{self.TARGET_BIN_PATH}"'
        slog.debug(cmd)
        subprocess.run(cmd, check=True, timeout=self.SUB_TIMEOUT,shell=True)
        time.sleep(self.SLEEP_GAP)
        log_text,script_result=read_log_and_output(log_path=self.LOG_PATH,output_path=output_path)
        return script_result

    def poc_run_test(self, poc_code):
        target_dir = Path(self.TARGET_BIN_PATH).resolve().parent
        target_dir.mkdir(parents=True, exist_ok=True)
        poc_path = target_dir / "poc_by_pocgenner.py"

        with open(poc_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(poc_code)
        cmd = f'python3 "{poc_path}"'
        slog.debug(cmd)
        try:
            completed = subprocess.run(
                cmd,
                shell=True,
                check=True,
                cwd=str(target_dir),
                timeout=self.SUB_TIMEOUT,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
            )
        except:
            return "TIMEOUT_ERROR"

        time.sleep(self.SLEEP_GAP)

        output = (completed.stdout or "").strip()
        if not output:
            output = (completed.stderr or "").strip()
        return output

    def build_syms_object(self):
        target_dir = Path(self.TARGET_BIN_PATH).resolve().parent
        input_path = target_dir / "func_internal_list.json"
        output_path = target_dir / "syms.o"
        json_path = Path(input_path)
        if not json_path.exists():
            raise FileNotFoundError(f"JSON not found: {json_path}")
        try:
            items = json.loads(json_path.read_text())
        except Exception as e:
            raise ValueError(f"bad JSON: {e}") from e

        if not isinstance(items, list):
            raise ValueError("JSON top-level must be a list of function objects")

        def parse_int(v) -> int:
            if isinstance(v, int):
                return v
            if isinstance(v, str):
                return int(v.strip(), 0)
            raise ValueError(f"invalid int: {v!r}")

        _BAD = re.compile(r"[^A-Za-z0-9_]")
        def sanitize(name: str) -> str:
            if not name:
                name = "noname"
            name = name.replace(" ", "_")
            name = _BAD.sub("_", name)
            if name.startswith("."):
                name = "_" + name[1:]
            if name[0].isdigit():
                name = "f_" + name
            return name

        ents = []
        for obj in items:
            if not isinstance(obj, dict):
                continue
            if "start_ea" not in obj or "size" not in obj:
                continue
            off  = parse_int(obj["start_ea"])
            size = parse_int(obj["size"])
            if size <= 0:
                raise ValueError(f"non-positive size for entry at {off:#x}")
            name = str(obj.get("name") or f"sub_{off:x}")
            ents.append([off, name, size])

        if not ents:
            raise ValueError("no valid entries parsed from JSON")

        ents.sort(key=lambda x: x[0])

        used = {}
        for e in ents:
            s = sanitize(e[1])
            if s in used:
                k = used[s] + 1
                used[s] = k
                s = f"{s}_{k}"
            else:
                used[s] = 1
            e[1] = s

        asm_lines = ['.section .text,"ax",@progbits']
        prev_end = 0
        for off, name, size in ents:
            if off < prev_end:
                raise ValueError(f"overlap at {name}: off<{prev_end:#x}")
            gap = off - prev_end
            if gap > 0:
                asm_lines.append(f".space 0x{gap:x}")
            asm_lines += [
                f".globl {name}",
                f".type  {name}, @function",
                f"{name}:",
                f".space 0x{size:x}",
                f".size  {name}, 0x{size:x}",
            ]
            prev_end = off + size

        obj_path = Path(output_path)
        obj_path.parent.mkdir(parents=True, exist_ok=True)

        asm_path = obj_path.with_suffix(".s")
        asm_path.write_text("\n".join(asm_lines) + "\n")

        subprocess.run(
            ["gcc", "-c", str(asm_path), "-o", str(obj_path)],
            check=True
        )
        return len(ents)

    def poc_run_async(self, poc_code: str) -> bool:
        target_dir = Path(self.TARGET_BIN_PATH).resolve().parent
        target_dir.mkdir(parents=True, exist_ok=True)

        poc_path = target_dir / "poc_by_codeadjustor.py"
        log_path = target_dir / "poc_by_codeadjustor.out.log"

        with open(poc_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(poc_code)

        with open(log_path, "wb") as _:
            pass

        cmd = f'python3 "{poc_path}"'
        slog.debug(cmd)
        with open(log_path, "ab", buffering=0) as log_f:
            proc = subprocess.Popen(
                cmd,
                shell=True,
                cwd=str(target_dir),
                stdout=log_f,
                stderr=log_f,
                start_new_session=True,
            )

        signature = "Starting local process"
        max_attempts = 5

        for i in range(max_attempts):
            time.sleep(self.SLEEP_GAP)

            with open(log_path, "r", encoding="utf-8", errors="ignore") as rf:
                log_text = rf.read()

            if log_text:
                slog.debug(log_text)

            if log_text and signature in log_text:
                slog.debug("[poc_run_async] signature detected on attempt %d/%d, leave process running in background.", i + 1, max_attempts)
                return True

        slog.debug("[poc_run_async] signature not found after %d attempts. log_path=%s", max_attempts, str(log_path))
        return False


    def catch_pid(self) -> int:
        target_dir = Path(self.TARGET_BIN_PATH).resolve().parent
        pid_path = target_dir / "pwn_target.pid"
        slog.debug(f'read pid from "{pid_path}"')

        with open(pid_path, "r", encoding="utf-8") as f:
            pid_str = f.read().strip()

        pid_val = int(pid_str)
        return pid_val
    
    def db_clean(self):
        script_with_arg=self.IDA_S_PATH+r'/analysis_init/db_clean.py'
        target_dir = Path(self.TARGET_BIN_PATH).resolve().parent
        output_path = target_dir / "global_var_ctree_refs.json"
        cmd=f'python3 "{script_with_arg}" "{self.TARGET_BIN_PATH}"'
        slog.debug(cmd)
        subprocess.run(cmd, check=True, timeout=self.SUB_TIMEOUT,shell=True)
        time.sleep(self.SLEEP_GAP)
        return
    
    def ext_clean(self):
        suffixes = {".json", ".til", ".o", ".s", ".i64",".i32",".id0",".id1",".id2",".id3",".nam"}

        target_dir = Path(self.TARGET_BIN_PATH).resolve().parent
        if not target_dir.is_dir():
            try:
                slog.error(f"ext_clean: not exist: {target_dir}")
            except NameError:
                pass
            return

        deleted = 0
        failed = 0

        try:
            slog.debug(f"ext_clean: start cleaning directory {target_dir}")
        except NameError:
            pass

        for p in target_dir.iterdir():
            try:
                if not p.is_file():
                    continue
                if p.suffix.lower() not in suffixes:
                    continue
            except Exception:
                continue

            try:
                p.unlink()
                deleted += 1
                continue
            except PermissionError:
                try:
                    os.chmod(p, os.stat(p).st_mode | stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
                    p.unlink()
                    deleted += 1
                    continue
                except Exception as e:
                    failed += 1
                    try:
                        slog.warning(f"ext_clean: cannot delete (permission/lock?): {p} -> {e}")
                    except NameError:
                        pass
            except Exception as e:
                failed += 1
                try:
                    slog.warning(f"ext_clean: delete error: {p} -> {e}")
                except NameError:
                    pass

        time.sleep(self.SLEEP_GAP)
        return
    
    def get_reachable_callgraph_from_entry(self, source_caller):
        script_with_arg = (
            self.IDA_S_PATH
            + r'/analysis_init/reachable_callgraph_from_entry.py start_func={start_f}'.format(
                start_f=source_caller
            )
        )
        target_dir = Path(self.TARGET_BIN_PATH).resolve().parent
        output_path = target_dir / "cc_reachable_callgraph.json"

        log_clean(self.LOG_PATH)
        cmd = f'{self.IDA_PATH} -A -L"{self.LOG_PATH}" -S"{script_with_arg}" "{self.TARGET_BIN_PATH}"'
        slog.debug(cmd)
        subprocess.run(cmd, check=True, timeout=self.SUB_TIMEOUT, shell=True)
        time.sleep(self.SLEEP_GAP)

        log_text, script_result = read_log_and_output(
            log_path=self.LOG_PATH,
            output_path=output_path
        )
        return script_result
    
'''
    def read_func_stack(target_bin,output_path,func_name):
        script_with_arg=IDA_S_PATH+r'/analysis_init/func_stack_dump_v4.py {name}'.format(name=func_name)
        if os.path.isfile(LOG_PATH):
            os.remove(LOG_PATH)
        cmd=f'{IDA_PATH} -A -L"{LOG_PATH}" -S"{script_with_arg}" {target_bin}'
        subprocess.run(cmd, check=True, timeout=SUB_TIMEOUT,shell=True)
        with open(LOG_PATH, "r", encoding="utf-8", errors="ignore") as fp:
            log_text = fp.read()
            slog.debug(log_text)

        with open(output_path, "r", encoding="utf-8") as fp:
            script_result = json.load(fp)

        return script_result


    def read_dfs_call_chains(target_bin,output_path,source_func_name,sink_func_name):
        script_with_arg=IDA_S_PATH+r'/analysis_init/path_dfs_v3.py start_func={start_f} end_func={end_f}'.format(start_f=source_func_name,end_f=sink_func_name)
        if os.path.isfile(LOG_PATH):
            os.remove(LOG_PATH)
        cmd=f'{IDA_PATH} -A -L"{LOG_PATH}" -S"{script_with_arg}" {target_bin}'
        subprocess.run(cmd, check=True, timeout=SUB_TIMEOUT,shell=True)
        with open(LOG_PATH, "r", encoding="utf-8", errors="ignore") as fp:
            log_text = fp.read()
            slog.debug(log_text)

        with open(output_path, "r", encoding="utf-8") as fp:
            script_result = json.load(fp)

        return script_result

    def read_all_dis(target_bin,output_path,func_name_list):
        str_func_name_list=str(func_name_list).replace(" ","").replace("'","")
        slog.debug(str_func_name_list)
        script_with_arg=IDA_S_PATH+r'/analysis_init/dump_dis.py funcs_list={fn_list}'.format(fn_list=str_func_name_list)
        
        if os.path.isfile(LOG_PATH):
            os.remove(LOG_PATH)
        cmd=f'{IDA_PATH} -A -L"{LOG_PATH}" -S"{script_with_arg}" {target_bin}'
        slog.debug(cmd)
        subprocess.run(cmd, check=True, timeout=SUB_TIMEOUT,shell=True)
        with open(LOG_PATH, "r", encoding="utf-8", errors="ignore") as fp:
            log_text = fp.read()
            slog.debug(log_text)
        
        with open(output_path, "r", encoding="utf-8") as fp:
            script_result = json.load(fp)

        return script_result'''