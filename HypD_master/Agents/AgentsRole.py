# Agents/AgentsRole.py
from Agents.AgentFrame import AgentEntity
from Utils.TemplateUtil import template_render
import json
from typing import List, Dict, Any, Optional
import re

PATTERN_GENERIC = re.compile(r'(?<![A-Za-z0-9])alloca\(')

PATTERN_OPERATOR_NEW = re.compile(r'operator\s+new\(')

PATTERN_IDA_PARTIAL_WORD = re.compile(
    r'(?<![A-Za-z0-9_])'
    r'(?:S)?'
    r'(?:LO|HI)?'
    r'(?:BYTE|WORD|DWORD)'
    r'(?:\d+|n)?'
    r'\s*\('
)

cwe_config_list=["121","122","78","134","789","787","125","476","369"]

def _pretty_json(obj: Any) -> str:
    return json.dumps(obj, indent=4, ensure_ascii=False, sort_keys=True)


def _vuln_type_from_cwe(cwe_type: str) -> str:
    mapping = {
        "121": "CWE-121: Stack-based Buffer Overflow",
        "122": "CWE-122: Heap-based Buffer Overflow",
        "78": "CWE-78: OS Command Injection",
        "134": "CWE-134: Use of Externally-Controlled Format String",
        "789": "CWE-789: Memory Allocation with Excessive Size Value",
        "787": "CWE-787: Out-of-bounds Write",
        "125": "CWE-125: Out-of-bounds Read",
        "476": "CWE-476: NULL Pointer Dereference",
        "369": "CWE-369: Divide By Zero",
    }
    return mapping.get(cwe_type, f"CWE-{cwe_type}")


def _vuln_detect_from_cwe(cwe_type: str) -> str:
    mapping = {
        "121": "The overflow must affect adjacent variables or memory outside its own allocated address space, thereby causing observable memory corruption during program execution. This memory corruption must directly or indirectly cause the program to crash with an exception signal. It must satisfy at least one of the following examples: performing out-of-bounds reads/writes to an invalid address; overwriting a pointer that will later be dereferenced or an address value that will be dereferenced, thereby triggering an invalid memory access; or overwriting critical control data such as the return address or the stack canary, directly causing the program to crash.",
        "122": "The overflow must write beyond the bounds of a heap-allocated buffer, corrupting adjacent heap metadata or heap-resident objects, with empirically observable impact such as a crash, memory corruption symptoms, information disclosure, or control-flow hijacking during execution.",
        "78": "Its impact concretely manifests as the execution of the injected statements or character sequences, such as command execution, code execution, or instruction execution. Once triggered, it can be clearly observed and recorded through various means.",
        "134": "The issue must use format-string specifiers to overwrite critical addresses, resulting in control-flow hijacking, a crash, or observable memory corruption; or use format-string specifiers to disclose information about critical addresses, i.e., an observable memory leak.",
        "789": "The vulnerability must involve using an attacker-controlled or otherwise externally influenced size value as the argument to a memory-allocation primitive (including heap allocators, stack allocation mechanisms such as alloca, or equivalent abstractions) without enforcing an appropriate upper bound or sanity check, such that the excessive size can be empirically demonstrated to cause resource exhaustion, allocation failure, or memory-access errors. Its impact must be concretely observable during program execution, for example by triggering process termination, denial of service, or abnormal behavior resulting from the failed or oversized allocation and any subsequent operations that depend on it.",
        "787": "The vulnerability must involve a write operation that targets memory outside the bounds of a validly allocated object or buffer (including stack, heap, global, or mmap-backed regions), such that the written bytes corrupt adjacent data structures, metadata, or control information. The out-of-bounds write must be empirically shown to cause observable effects, such as a crash, data corruption, control-flow hijacking, or other abnormal program behavior that arises from the corruption of neighboring memory locations.",
        "125": "The vulnerability must involve reading memory beyond the valid bounds of an allocated object or buffer, or before the start of that object, such that data from adjacent memory is accessed without authorization. Its impact must be concretely observable, for example by leaking sensitive or unintended information, causing a crash due to dereferencing an invalid address, or influencing subsequent program behavior through the use of out-of-bounds data that was never intended to be read.",
        "476": "The vulnerability must involve dereferencing a pointer value that is NULL at the point of use, where the NULL value arises from attacker influence, error handling defects, missing initialization, or other logic flaws. The dereference must be empirically shown to cause observable abnormal behavior, typically a segmentation fault or equivalent hardware/software exception that terminates the process, thereby resulting in denial of service or other directly observable disruption.",
        "369": "The vulnerability must involve performing an arithmetic operation whose denominator or divisor is zero (or becomes zero due to attacker-controllable or otherwise unvalidated input), such as integer or floating-point division, modulo, or remainder. This condition must be demonstrably reachable at runtime and must produce an observable effect, for example triggering a hardware divide-by-zero exception (such as SIGFPE), raising a runtime error, or causing other abnormal termination or behavior attributable to the zero-divisor computation.",
    }
    return mapping.get(cwe_type, f"CWE-{cwe_type}")


def api_list_to_nature_language(api_list):
    nature_language = ""
    for iter_api in api_list:
        func_name = iter_api.get("func") or "UNKNOWN"
        lib_name = iter_api.get("lib") or "UNKNOWN"
        proto_info = iter_api.get("proto") or "UNKNOWN"
        nature_language += f"The {func_name} API comes from {lib_name}; its function prototype is '{proto_info}';\n"
    return nature_language.rstrip("\n")


def pcode_list_to_nature_language(pcode_list):
    nature_language = ""
    for pcode in pcode_list:
        nature_language += pcode + "\n\n"
    return nature_language.rstrip("\n\n")

def append_update_error_hint(user_message: str, update_flag: bool, failed_obligations):
    """
    Append ONE English sentence to user_message when obligation update gate-check fails.

    failed_obligations supports:
      1) ["O2", "O4", ...]
      2) [{"obligation":"O2","required":[...]}, ...]
    """
    if update_flag or not failed_obligations:
        return user_message

    if isinstance(failed_obligations[0], dict):
        bad = ",".join(
            x.get("obligation") for x in failed_obligations
            if isinstance(x, dict) and x.get("obligation")
        )
    else:
        bad = ",".join(str(x) for x in failed_obligations)

    user_message = user_message.rstrip("\n")
    return (
        user_message
        + f"\n\nObligation-status update gate check failed for {bad}; please re-update ONLY these obligations and ensure update_from cites at least one evidence ID whose query_type matches each obligation's minimum primitive set."
    )



# ---------- ApiDetecter ----------
class ApiDetecter(AgentEntity):
    def __init__(self, cwe_type, api_list):
        name = "api_detector"
        interactive = False
        super().__init__(name, interactive)
        api_list_nature_language = api_list_to_nature_language(api_list)
        template_dir: str = "ApiDetecter"
        vuln_type = _vuln_type_from_cwe(cwe_type)
        user_params = {"api_list_str": api_list_nature_language, "vuln_type": vuln_type}
        self.sys_msg = template_render(f"{template_dir}/init_sys_prompt.txt", {})
        self.user_msg = template_render(
            f"{template_dir}/init_user_prompt.txt", user_params
        )

    def create(self):
        return super().create(self.sys_msg, self.user_msg)


# ---------- PathTainter ----------
class PathTainter(AgentEntity):
    def __init__(self, cwe_type, source_api, sink_api, call_chains, pcode_list):
        name = "path_tainter"
        interactive = False
        super().__init__(name, interactive)
        pcode_list_str = "\n\n".join(pcode_list)
        call_list_str = "->".join(call_chains)
        template_dir: str = "PathTainter"
        # vuln_type = _vuln_type_from_cwe(cwe_type)
        user_params = {
            "call_list_str": call_list_str,
            "source_func": source_api,
            "sink_func": sink_api,
            "pcode_list_str": pcode_list_str,
        }
        self.sys_msg = template_render(f"{template_dir}/init_sys_prompt.txt", {})
        self.user_msg = template_render(
            f"{template_dir}/init_user_prompt.txt", user_params
        )

    def create(self):
        return super().create(self.sys_msg, self.user_msg)


# ---------- VulnFinder ----------
class VulnFinder(AgentEntity):
    count = 0

    def __init__(
            self, cwe_type, source_api, sink_api, call_chains, pcode_list, taint_report, obligation_gate_str,mini_primitives):
        name = "vuln_finder"
        interactive = True
        super().__init__(name, interactive)
        pcode_list_str = "\n\n".join(pcode_list)
        call_list_str = "->".join(call_chains)
        template_dir: str = "VulnFinder"
        vuln_type = _vuln_type_from_cwe(cwe_type)
        vuln_detect = _vuln_detect_from_cwe(cwe_type)
        
        key_cmd="None"
        key_cmd_list=[]
        
        if "__readfsqword(" in pcode_list_str and cwe_type== "121":
            key_cmd_list.append('Note: At function entry, __readfsqword is typically used to load the stack canary and store a copy of it into the current stack frame (in the slot closest to the saved return address). The corresponding stack-local variable is critical stack-protection metadata used for stack integrity checks. Any overwrite of this region will corrupt the stack canary, trigger the stack-protection mechanism, and cause the program to crash. From a memory-safety perspective, such corruption of the canary is considered stack memory corruption and can be treated as a form of stack overflow. The canary is usually located in the stack-variable slot farthest from the stack pointer (i.e., the variable slot with the highest address in the current stack frame), adjacent to the slots holding the saved return address and the saved base pointer (BP).')
        
        
        if PATTERN_GENERIC.search(pcode_list_str) and cwe_type=="121":
            key_cmd_list.append('Within the current call chain, a function that uses alloca to dynamically allocate stack memory has been detected. The decompiler\'s handling of references to a dynamic stack pointer (SP) is unreliable and may introduce defects into the decompilation; once the addresses of local variables affected by alloca are wrong, those errors can further propagate along downstream data flows within the function. Such decompilation errors may manifest as abnormal address-taking operations, strange array self-references, single-byte buffer usages, and other anomalous memory access patterns. In the presence of alloca, you must treat the disassembly of this function as the ground truth and use it to correct these faulty decompilation results: map the real local variables via the stack-frame objects referenced by BP-based offsets in the operands of mov instructions, reinterpret the true relationships of address passing and pointer references, repair the erroneous results, and avoid drawing incorrect conclusions in the final analysis.')
            key_cmd_list.append('alloca(n) allocates stack space by decreasing SP toward lower addresses and returns a pointer that is aligned to at least 16 bytes. Compilers typically round the allocation size up to a multiple of 16 bytes to preserve the 16-byte alignment invariant of SP, and may perform page-by-page write touches for large allocations that span pages to avoid crossing the guard page. alloca_with_align(n, a) allows explicitly specifying a higher alignment and returns a pointer aligned to (a/8) bytes. After the allocation process has fully completed, one more alignment is performed so that the address actually used thereafter to reference this memory satisfies 16-byte alignment (or, when using alloca_with_align, the alignment in bytes corresponding to a bits). Therefore, SP and the returned pointer aligned relative to SP can differ; the aligned address is typically stored in a register, and that address is then passed to other pointers for use.')
            key_cmd_list.append('Therefore, for functions that use alloca, the decompilation view has been augmented with the corresponding enhanced disassembly. You should analyze the disassembly and the decompilation side by side to verify accuracy; if any decompilation errors are found, treat the disassembly as authoritative and correct the decompilation accordingly. Most variables in a static stack frame are referenced via BP offsets, whereas variables dynamically allocated by alloca are referenced via SP; you can leverage this property for convenient verification and analysis. For variables that already exist in the static stack frame, as long as they are not affected by other forms of stack-frame reconstruction or dynamic stack allocation, you can still use "stack_lvar" to obtain accurate results. However, the stack memory region allocated by alloca can only be analyzed via disassembly: you need to combine the stack-frame information of the variable at the current lowest address (i.e., the variable with the smallest offset relative to the current SP anchor) to infer its layout and compute the corresponding offsets.')
        
        if PATTERN_IDA_PARTIAL_WORD.search(pcode_list_str) and cwe_type== "121":
            key_cmd_list.append('Note: IDA-style partial-word assignment macros such as LODWORD(x), HIDWORD(x), and related variants have been detected in the current decompiled code. These macros perform sub-object writes into a larger scalar or stack-frame slot. When their target object corresponds to the saved stack canary on the stack, such partial writes can silently corrupt the canary and trigger stack-protector crashes, even in the absence of a traditional linear buffer overflow. Therefore, you must treat these macros as stack-based write sinks: check whether they overlap with the canary slot or other critical stack protection data, and if they do, classify such cases as stack memory corruption rather than as harmless scalar assignments.')
        
        if PATTERN_OPERATOR_NEW.search(pcode_list_str) and cwe_type == "122":
            key_cmd_list.append('Within the current call chain, indirect call behavior has been detected, such as virtual dispatch or function wrappers. Pay close attention to the initialization of the relevant object layout.')
            key_cmd_list.append('Note: When analyzing indirect call chains at the binary level, including virtual dispatch, interface table dispatch, and callback dispatch, as well as the related construction, destruction, and initialization paths, pay close attention to the fact that the final target address is often not present at the immediate call site but is resolved through one or more layers of dispatch logic. In such cases, critical state may be hard-coded either immediately before the indirect call or within the dispatch and initialization sequence, such as fixed constant arguments, fixed offsets, fixed indices or selectors, or fixed context fields. As a result, some key values that determine the resolved target or influence call semantics may not be attacker controllable and instead are effectively constrained to constants. The values of these hard-coded constants may be insufficient to satisfy the defect triggering condition, making the path appear suspicious while remaining non-triggerable in practice.')
            key_cmd_list.append('For each such value that can affect the dispatch result or the call behavior, first confirm that the final effective value is a constant by treating the last write in the data flow as authoritative, and then check whether this constant can fall into the vulnerability triggering range, for example by producing an out-of-bounds slot or index, selecting a dangerous branch, or meeting a specific threshold condition. If, in the current candidate defect scenario, the constant always remains within a safe range, the corresponding path should not be classified as an exploitable vulnerability. Instead, treat it as a case where the relevant parameter is effectively constrained and thus non-triggerable, mark it as having a false positive risk, and continue searching for other reachable paths that may provide attacker controllable values capable of actually triggering the defect.')
            #print(key_cmd_list)
            #exit()
            
        if cwe_type== "121":
            key_cmd_list.append('On x86/x64 systems, stack allocation and growth are always toward lower memory addresses. Under normal linear memory write semantics, overflows and overwrites always extend toward higher addresses. Any analysis that assumes a downward overflow direction is incorrect.')
            
        if cwe_type== "78":
            key_cmd_list.append('A defining characteristic of command injection vulnerabilities is the act of injection itself. The program concatenates or copies attacker-controllable data into a command line string, and then passes this string to the shell or command interpreter via various command execution or code execution interfaces. In this process, it neither enforces strict whitelisting of the input nor properly constrains or neutralizes special characters that can alter the semantics of the command, thereby allowing an attacker to rewrite the intended command behavior.')
            key_cmd_list.append('In command injection attacks, attackers typically interfere with the semantics of an existing command sequence in two main ways: first, by inserting command separators (such as \';\', \'&&\', \'||\', etc.) to "close" the original command and append additional malicious commands; second, by leveraging command substitution or parameter/expression expansion mechanisms (such as \'`...`\' or \'$()\') to embed and execute malicious sub-commands within the original command. Essentially, these attacks operate by truncating, closing, or rewriting the syntactic structure of the original command in order to tamper with its normal execution semantics.')
            key_cmd_list.append('When a command string is constructed exclusively from constants, with no attacker-controllable data influencing its construction, command injection is not possible. If any data flow does contribute to the construction of the command, you must trace that flow back to its actual source rather than guessing where it comes from. Once you have verified that the main function\'s parameters do not feed into any downstream data flow used to build command strings, you can safely ignore argv/envp in your subsequent analysis.')
        if cwe_type == "134":
            key_cmd_list.append("For format-string vulnerabilities, the key question is not whether attacker-controlled data flows into any call to the printf family, but whether that data becomes the format string itself. When examining a suspicious call site, you should first determine which argument is actually used as the format parameter. The dangerous behavior of format-string vulnerabilities mainly comes from two capabilities of the formatting engine: out-of-bounds reads that lead to information disclosure, and out-of-bounds writes that lead to memory corruption or control-flow hijacking.")
            key_cmd_list.append("In the wide-character variants of the printf family (such as wprintf), the semantics of format strings are essentially the same as in the narrow-character versions: the interpretation of format specifiers, their positional arguments, and their length modifiers is very similar to that of the traditional printf. In typical implementations, attacker-controlled multibyte input is first converted into a wide-character string via functions such as mbstowcs or mbsrtowcs, and then passed as the format argument to a wide-character printf-style function. Therefore, the multibyte-to-wide-character conversion step should not be treated as a sanitization boundary; this step does not automatically remove or neutralize the format-string attack surface.")
            key_cmd_list.append("When assessing whether a suspicious format-string path is actually exploitable, it is important to clearly distinguish between format strings that are truly attacker-controlled and format strings that are effectively constrained to constants as uncontrollable, built-in default formats within the program.")

        if cwe_type in ("121", "122", "125", "787"):
            key_cmd_list.append("In memory-corruption analysis, you must not treat post-write or post-read checks as strong sanitization or mitigation.")
            key_cmd_list.append("When a bounds check or sentinel check is performed only after the write or read has already taken place (for example, in a loop that writes multiple bytes first and only then tests a guard, or in code that checks a sentinel one element past the last written slot), any payload data that corrupts memory has already been committed before the check executes.")
            key_cmd_list.append("Such checks are temporally too late to prevent the underlying out-of-bounds access and therefore cannot be considered effective sanitization in the sense of ruling out memory-safety vulnerabilities; they may at best limit secondary effects and exploitability after memory corruption has already occurred, but they do not eliminate the primary memory-safety violation itself.")
            
        key_cmd_list.append('We are working in a little-endian environment: when you see oddly ordered multi-character literals or integer immediates in the decompilation output that appear as strings like \' dwp\' or \' pot\' (which look like gibberish), you should first consider that this is the result of interpreting little-endian byte order using a big-endian rule; in these examples, the actual strings are \'pwd \' and \'top \', respectively. When you encounter such cases during analysis, interpret them both as C multi-character literals (most significant byte on the left), as currently displayed, and as little-endian byte sequences whose characters should be read in reverse order to recover the more realistic string meaning.')
            
        key_cmd_list.append('When performing numerical calculations related to memory layout, such as offsets and padding sizes, you must be rigorous; incorrect results will introduce errors that can lead to false positives or false negatives.')
        key_cmd="\n".join(key_cmd_list)
        
        if (cwe_type in cwe_config_list):
            sys_params = {
                "key_cmd" : key_cmd,
                "vuln_detect": vuln_detect,
                "mini_primitives_table": obligation_gate_str,
                "mini_primitives": str(mini_primitives),
            }
        else:
            sys_params = {
                "key_cmd" : "None",
                "vuln_detect": vuln_detect,
                "mini_primitives_table": obligation_gate_str,
                "mini_primitives": str(mini_primitives),
            }
            print(sys_params)
            exit()
        user_params = {
            "call_list_str": call_list_str,
            "source_func": source_api,
            "sink_func": sink_api,
            "pcode_list_str": pcode_list_str,
            "taint_report": taint_report,
            "vuln_type": vuln_type,
        }
        self.sys_msg = template_render(f"{template_dir}/init_sys_prompt.txt", sys_params)
        self.user_msg = template_render(
            f"{template_dir}/init_user_prompt.txt", user_params
        )

    def create(self):
        self.count = 1
        #print(self.sys_msg)
        #exit()
        return super().create(self.sys_msg, self.user_msg)

    def interact(self, prior_info=None, type=None, debug_enable=False,
                 update_flag=True, failed_obligations=[]):
        if debug_enable is True:
            self.count = 1

        template_dir: str = "VulnFinder"

        if self.count == 0:
            return self.create()

        if self.count > 0:
            template_path = None
            user_params = None

            if type == 'global_var':
                template_path = f"{template_dir}/react_global_find_prompt.txt"
                ref_func_str = ", ".join(prior_info.get("ref_func_list"))
                user_params = {
                    "global_var_type": prior_info.get("global_var_type"),
                    "global_var_size": prior_info.get("global_var_size"),
                    "ref_func": ref_func_str,
                    "ea": prior_info.get("addr_ea"),
                    "init_value": prior_info.get("init_value")
                }

            elif type == 'inner_call':
                template_path = f"{template_dir}/react_inner_call_prompt.txt"
                user_params = {
                    "func_name": prior_info.get("func_name"),
                    "func_type": prior_info.get("func_type"),
                    "demangle_name": prior_info.get("demangle_name")
                }

            elif type == 'fetch_pcode':
                template_path = f"{template_dir}/react_pcode_prompt.txt"
                user_params = {
                    "pcode": prior_info.get("pcode")
                }

            elif type == 'fetch_disasm':
                template_path = f"{template_dir}/react_ehsasm_prompt.txt"
                user_params = {
                    "ehasm": prior_info.get("ehasm")
                }

            elif type == 'stack_lvar':
                template_path = f"{template_dir}/react_stack_lvar_prompt.txt"
                is_reg = prior_info.get("reg_or_stack") == "Register"
                user_params = {
                    "lvar_size": prior_info.get("lvar_size"),
                    "dist_to_ret": 'None' if is_reg else prior_info.get("dist_to_ret"),
                    "offset_to_sp": 'None' if is_reg else prior_info.get("offset_to_sp"),
                    "lvar_type": prior_info.get("lvar_type"),
                    "reg_or_stack": prior_info.get("reg_or_stack"),
                }

            if template_path is not None and user_params is not None:
                user_message = template_render(template_path, user_params).rstrip("\n")
            else:
                user_message = (
                    "Request primitive is not specified or is unsupported. Please retry."
                )

            user_message = append_update_error_hint(user_message, update_flag, failed_obligations)

            if debug_enable is True:
                print(user_message)
                exit()

            return self.send(user_message)

        return None



# ---------- PoCGenner ----------
class PoCGenner(AgentEntity):
    count = 0

    def __init__(self, cwe_type, source_api, sink_api, call_chains, pcode_list, taint_report, vuln_report, bin_path, prior_knowldege_list):
        name = "poc_genner"
        interactive = True
        super().__init__(name, interactive)
        pcode_list_str = "\n\n".join(pcode_list)
        call_list_str = "->".join(call_chains)
        prior_knowldege_str = "\n-----\n".join(prior_knowldege_list)
        template_dir: str = "PoCGenner"
        vuln_type = _vuln_type_from_cwe(cwe_type)

        key_cmd="None"
        key_cmd_list=[]
        if PATTERN_GENERIC.search(pcode_list_str):
            key_cmd_list.append('Note: A function that uses alloca to dynamically allocate stack memory has been detected in the current call chain. The decompiler’s handling of references to a dynamic stack pointer (SP) is unreliable and may introduce defects in the decompilation; incorrect addresses of local variables affected by alloca can further propagate along downstream data flows within the function. Such decompilation errors may manifest as unusual address-taking operations, odd array self-references, and anomalous memory usage. Be sure to correct the erroneous decompilation based on the disassembly and the stack-frame information of local variables—that is, map the real local variables using the stack-frame objects referenced via BP offsets in the operands of mov instructions—in order to fix the decompilation and prevent incorrect conclusions in the final analysis.')
            key_cmd_list.append('alloca(n) allocates stack space by decreasing SP toward lower addresses and returns a pointer that is aligned to at least 16 bytes. Compilers typically round the allocation size up to a multiple of 16 bytes to preserve the 16-byte alignment invariant of SP, and may perform page-by-page write touches for large allocations that span pages to avoid crossing the guard page. alloca_with_align(n, a) allows explicitly specifying a higher alignment and returns a pointer aligned to (a/8) bytes. After the allocation process has fully completed, one more alignment is performed so that the address actually used thereafter to reference this memory satisfies 16-byte alignment (or, when using alloca_with_align, the alignment in bytes corresponding to a bits). Therefore, SP and the returned pointer aligned relative to SP can differ; the aligned address is typically stored in a register, and that address is then passed to other pointers for use.')
            key_cmd_list.append('Therefore, for functions that use alloca, the decompilation view has been augmented with the corresponding enhanced disassembly. You should analyze the disassembly and the decompilation side by side to verify accuracy; if any decompilation errors are found, treat the disassembly as authoritative and correct the decompilation accordingly. Most variables in a static stack frame are referenced via BP offsets, whereas variables dynamically allocated by alloca are referenced via SP; you can leverage this property for convenient verification and analysis. For variables that already exist in the static stack frame, as long as they are not affected by other forms of stack-frame reconstruction, you can still use "stack_lvar" to obtain accurate results.')
            key_cmd_list.append('On x86/x64 systems, stack allocation and growth are always toward lower memory addresses. Under normal linear memory write semantics, overflows and overwrites always extend toward higher addresses. Any analysis that assumes a downward overflow direction is incorrect.')
            key_cmd="\n".join(key_cmd_list)
        if (cwe_type == "121" or cwe_type=="122"):
            sys_params = {
                "key_cmd" : key_cmd
            }
        else:
            sys_params = {}

        user_params = {
            "bin_path": bin_path,
            "call_list_str": call_list_str,
            "source_func": source_api,
            "sink_func": sink_api,
            "pcode_list_str": pcode_list_str,
            "taint_report": taint_report,
            "vuln_type": vuln_type,
            "vuln_report": vuln_report,
            "prior_detail": prior_knowldege_str
        }
        self.sys_msg = template_render(f"{template_dir}/init_sys_prompt.txt", sys_params )
        self.user_msg = template_render(
            f"{template_dir}/init_user_prompt.txt", user_params
        )

    def create(self):
        self.count = 1
        return super().create(self.sys_msg, self.user_msg)

    def interact(self, prior_info=None, type=None, debug_enable=False):
        if (debug_enable == True):
            self.count = 1
        template_dir: str = "PoCGenner"
        if (self.count == 0):
            return self.create()
        if (self.count > 0):

            if (type == 'global_var'):
                template_path = f"{template_dir}/react_global_find_prompt.txt"
                ref_func_str = ", ".join(prior_info.get("ref_func_list"))
                user_params = {
                    "global_var_type": prior_info.get("global_var_type"),
                    "global_var_size": prior_info.get("global_var_size"),
                    "ref_func": ref_func_str,
                    "ea": prior_info.get("addr_ea")
                }
            elif (type == 'inner_call'):
                template_path = f"{template_dir}/react_inner_call_prompt.txt"
                user_params = {
                    "func_name": prior_info.get("func_name"),
                    "func_type": prior_info.get("func_type")
                }
            elif (type == 'fetch_pcode'):
                template_path = f"{template_dir}/react_pcode_prompt.txt"
                user_params = {
                    "pcode": prior_info.get("pcode")
                }
            elif (type == 'fetch_disasm'):
                template_path = f"{template_dir}/react_ehsasm_prompt.txt"
                user_params = {
                    "ehasm": prior_info.get("ehasm")
                } 
            elif (type == 'stack_lvar'):
                template_path = f"{template_dir}/react_stack_lvar_prompt.txt"
                is_reg = prior_info.get("reg_or_stack") == "Register"
                user_params = {
                    "lvar_size": prior_info.get("lvar_size"),
                    "dist_to_ret": 'None' if is_reg else -prior_info.get("dist_to_ret"),
                    "offset_to_sp": 'None' if is_reg else -prior_info.get("offset_to_sp"),
                    "lvar_type": prior_info.get("lvar_type"),
                    "reg_or_stack": prior_info.get("reg_or_stack"),
                }

            user_message = template_render(template_path, user_params).rstrip("\n")
            if (debug_enable == True):
                print(user_message)
                exit()
            return self.send(user_message)

        return None


# ---------- CodeAdjustor ----------
class CodeAdjustor(AgentEntity):
    def __init__(self, poc_code, bin_path):
        name = "code_adjustor"
        interactive = False
        super().__init__(name, interactive)
        template_dir: str = "CodeAdjustor"
        # vuln_type = _vuln_type_from_cwe(cwe_type)
        user_params = {
            "poc_code": poc_code,
            "bin_path": bin_path
        }
        self.sys_msg = template_render(f"{template_dir}/init_sys_prompt.txt", {})
        self.user_msg = template_render(
            f"{template_dir}/init_user_prompt.txt", user_params
        )

    def create(self):
        return super().create(self.sys_msg, self.user_msg)


# ---------- PoCDebugger ----------
class PoCDebugger(AgentEntity):
    count = 0

    def __init__(self, cwe_type, source_api, sink_api, call_chains, pcode_list, taint_report, vuln_report, bin_path, prior_knowldege_list, poc_code, disasm):
        name = "poc_debugger"
        interactive = True
        super().__init__(name, interactive)
        pcode_list_str = "\n\n".join(pcode_list)
        call_list_str = "->".join(call_chains)
        prior_knowldege_str = "\n-----\n".join(prior_knowldege_list)
        template_dir: str = "PoCDebugger"
        vuln_type = _vuln_type_from_cwe(cwe_type)
        user_params = {
            "bin_path": bin_path,
            "call_list_str": call_list_str,
            "source_func": source_api,
            "sink_func": sink_api,
            "pcode_list_str": pcode_list_str,
            "taint_report": taint_report,
            "vuln_type": vuln_type,
            "vuln_report": vuln_report,
            "prior_detail": prior_knowldege_str,
            "poc_code": poc_code,
            "disasm": disasm
        }
        self.sys_msg = template_render(f"{template_dir}/init_sys_prompt.txt", {})
        self.user_msg = template_render(
            f"{template_dir}/init_user_prompt.txt", user_params
        )

    def create(self):
        self.count = 1
        return super().create(self.sys_msg, self.user_msg)

    def interact(self, gdb_command, gdb_resp, debug_enable=False):
        if (debug_enable == True):
            self.count = 1
        template_dir: str = "PoCDebugger"
        if (self.count == 0):
            return self.create()
        if (self.count > 0):

            template_path = f"{template_dir}/react_gdb.txt"
            user_params = {
                "gdb_command": gdb_command,
                "gdb_resp": gdb_resp
            }

            user_message = template_render(template_path, user_params).rstrip("\n")
            if (debug_enable == True):
                print(user_message)
                exit()
            return self.send(user_message)

        return None
