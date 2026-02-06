import idaapi          # type: ignore
import ida_auto        # type: ignore
import ida_hexrays     # type: ignore
import ida_funcs       # type: ignore
import ida_xref        # type: ignore
import idautils        # type: ignore
import idc             # type: ignore
import ida_bytes       # type: ignore
import ida_name        # type: ignore

import json
import os
from typing import List, Dict, Set, Optional, Tuple

OUT_FILE = "cc_path.json"

# --------------------------------------------------------------------------
#   工具函数
# --------------------------------------------------------------------------

def parse_args() -> List[str]:
    """
    从命令行参数解析出 funcs_list 的内容
    假设调用类似：
      -S"path_dfs_v3.py funcs_list=funA,funB,funC"
    或者直接用 JSON 格式:
      -S"path_dfs_v3.py funcs_list=[\"funA\",\"funB\"]"
    下述仅演示用法，可根据需要灵活改写
    """
    funcs_list = []
    for a in idc.ARGV:
        if a.startswith("funcs_list="):
            raw_str = a.split("=", 1)[1].strip()
            # 简易处理：如果是逗号分隔
            if raw_str.startswith("["):
                # 假装是json
                try:
                    import json
                    funcs_list = json.loads(raw_str)
                except:
                    pass
            else:
                # 逗号分隔
                funcs_list = [x.strip() for x in raw_str.split(",") if x.strip()]
    if not funcs_list:
        idc.msg('Usage: -S"path_dfs_v3.py funcs_list=funA,funB,funC"\n')
        idaapi.qexit(1)
    return funcs_list


def get_ea_by_name(name: str) -> int:
    """
    根据函数名获取其入口地址
    """
    ea = idc.get_name_ea_simple(name)
    f = ida_funcs.get_func(ea) if ea != idc.BADADDR else None
    if not f:
        idc.msg(f"[!] Function '{name}' not found!\n")
        return idc.BADADDR
    return f.start_ea


def is_internal(ea: int) -> bool:
    """
    判断是否是“用户自定义”内部函数：
      - 非 BADADDR
      - 存在函数对象
      - 不在外部段 (SEG_XTRN, SEG_GRP)
      - 非库函数标记 (FUNC_LIB)
    """
    if ea == idc.BADADDR:
        return False
    f = ida_funcs.get_func(ea)
    if not f:
        return False
    seg = idaapi.getseg(ea)
    if seg and seg.type in (idaapi.SEG_XTRN, idaapi.SEG_GRP):
        return False
    if f.flags & ida_funcs.FUNC_LIB:
        return False
    return True


def is_import_api(ea: int) -> bool:
    """
    判断是否来自导入表 / 外部 API。
    以下逻辑可根据需要对接更精准的方式：
      - 枚举 import table；或
      - seg.type == SEG_XTRN 且查找 import entry；等等。
    """
    if ea == idc.BADADDR:
        return False
    seg = idaapi.getseg(ea)
    # 常见情况下，import table 会是 SEG_XTRN
    if seg and seg.type == idaapi.SEG_XTRN:
        return True

    # 也可加其他判断，如名字是否有 '.' 前缀等
    # name = idc.get_name(ea)
    # if name and name.startswith("."):
    #     return True

    return False


def get_call_type(ea: int) -> str:
    """
    返回 'USER_DEF', 'IMPORT_API' 或 'OTHER'。
    """
    if is_import_api(ea):
        return "IMPORT_API"
    elif is_internal(ea):
        return "USER_DEF"
    return "OTHER"


def strip_dot_prefix(name: str) -> str:
    """
    若函数名以 '.' 开头，则去掉它。可避免外部 API 名称前缀 '.' 的情况。
    """
    if name.startswith('.'):
        return name[1:]
    return name


# --------------------------------------------------------------------------
#   v3 中的分析函数：在 ctree 中识别各种可能的被调函数地址
# --------------------------------------------------------------------------

def collect_func_objs(expr) -> Set[int]:
    """
    在表达式树中搜集直接出现的函数地址（cot_obj）
    """
    found: Set[int] = set()

    class _Visitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_obj:
                found.add(e.obj_ea)
            return 0

    _Visitor().apply_to(expr, None)
    return found


def expr_uses_lvar(expr, lvar_idx_set: Set[int]) -> bool:
    """
    判断表达式是否直接或间接使用了指定局部变量
    """
    class _Chk(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
            self.hit = False

        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_var and e.v.idx in lvar_idx_set:
                self.hit = True
                return 1  # 终止
            return 0

    c = _Chk()
    c.apply_to(expr, None)
    return c.hit


def resolve_callee_via_defs(cfunc, callee_expr) -> List[int]:
    """
    轻量反向切片：若无法直接确定 callee，则分析 callee_expr 里所用到的局部变量；
    在同一函数体内搜索最近赋值语句，看看 RHS 是否含函数地址等。
      * 为避免过度耗时，限制遍历的语句条数到 MAX_DEF_SEARCH。
      * 若发现 RHS 直接是个函数调用（如 rand()），此处示例一律跳过，不再展开。
    """
    results: Set[int] = set()

    # 1) 收集本调用表达式中用到的局部变量 idx
    lvar_idx_set: Set[int] = set()

    class _VarGrab(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_var:
                lvar_idx_set.add(e.v.idx)
            return 0

    _VarGrab().apply_to(callee_expr, None)
    if not lvar_idx_set:
        return []

    # 2) 在 cfunc.body 内扫描赋值（cot_asg）语句，寻找 lhs 命中
    #    演示中设置一个遍历上限
    MAX_DEF_SEARCH = 1000
    visited = 0

    class _DefFinder(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            nonlocal visited
            if visited > MAX_DEF_SEARCH:
                return 1  # 终止遍历

            if e.op == ida_hexrays.cot_asg:
                lhs, rhs = e.x, e.y
                if expr_uses_lvar(lhs, lvar_idx_set):
                    # 如果 RHS 自身是一次函数调用，则跳过
                    if rhs.op == ida_hexrays.cot_call:
                        return 0
                    # 尝试看看 RHS 中有没有函数地址
                    objs = collect_func_objs(rhs)
                    if objs:
                        results.update(objs)
            visited += 1
            return 0

    _DefFinder().apply_to(cfunc.body, None)
    return list(results)


def try_resolve_callee(callee_expr) -> Optional[int]:
    """
    在表达式树中直接解析出被调用函数地址
      - 若是多层 (cast/ref/ptr/memref) 包裹，递归去找
    """
    if callee_expr.op == ida_hexrays.cot_obj:
        return callee_expr.obj_ea
    elif callee_expr.op in (
        ida_hexrays.cot_cast,
        ida_hexrays.cot_ref,
        ida_hexrays.cot_ptr,
        ida_hexrays.cot_memptr,
        ida_hexrays.cot_memref
    ):
        return try_resolve_callee(callee_expr.x)
    return None


# --------------------------------------------------------------------------
def collect_callees_from_hexrays(func_ea: int) -> List[Tuple[int,int]]:
    """
    反编译后 ctree 遍历，提取(被调用函数地址, 对应表达式所在EA)。
    之所以要记录所在EA，是为了在最终输出中可以关联到“行号”。
    """
    if not ida_hexrays.init_hexrays_plugin():
        return []

    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        return []

    found: List[Tuple[int,int]] = []

    class _CallVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            if e.op != ida_hexrays.cot_call:
                return 0

            callee_expr = e.x
            # ① 直接解析
            direct = try_resolve_callee(callee_expr)
            if direct and direct != idc.BADADDR:
                found.append((direct, e.ea))
            else:
                # ② 整棵表达式若仅含 1 个函数地址 ⇒ 采用
                inline_objs = collect_func_objs(callee_expr)
                if len(inline_objs) == 1:
                    for tgt in inline_objs:
                        found.append((tgt, e.ea))
                else:
                    # ③ 反向切片
                    back_defs = resolve_callee_via_defs(cfunc, callee_expr)
                    for tgt in back_defs:
                        found.append((tgt, e.ea))

            return 0

    _CallVisitor().apply_to(cfunc.body, None)
    return found


# --------------------------------------------------------------------------
def collect_callees_from_asm(func_ea: int) -> List[Tuple[int,int]]:
    """
    汇编层面常规扫描：包括正常call、间接call、尾调用等。
    返回 [(callee_ea, instr_ea), ...]
    """
    results: List[Tuple[int,int]] = []
    f = ida_funcs.get_func(func_ea)
    if not f:
        return results

    # 1) 正常 / 间接 call
    for insn_ea in idautils.FuncItems(func_ea):
        if idaapi.is_call_insn(insn_ea):
            # 拿 Xref
            for xr in idautils.XrefsFrom(insn_ea, ida_xref.XREF_FAR):
                if xr.iscode:
                    results.append((xr.to, insn_ea))
        else:
            # 2) 尾调用检查
            first_xref = next(idautils.XrefsFrom(insn_ea, ida_xref.XREF_FAR), None)
            if first_xref and is_tail_jump(insn_ea, first_xref.to):
                results.append((first_xref.to, insn_ea))

    # 3) thunk
    if f.flags & ida_funcs.FUNC_THUNK:
        tgt = ida_funcs.calc_thunk_func_target(f)
        if isinstance(tgt, int):
            # 伪造一下 instr_ea = 函数开头
            results.append((tgt, func_ea))

    return results


def is_tail_jump(insn_ea: int, target_ea: int) -> bool:
    """
    判定是否是 tail-call 优化
      - 对于某些编译器生成的 jump 到另一个函数
      - 需要排除是 call 指令或仅仅是 flow
    """
    if idaapi.is_call_insn(insn_ea):
        return False
    if ida_bytes.is_flow(idaapi.get_full_flags(insn_ea)):
        return False
    tgt_func = ida_funcs.get_func(target_ea)
    return tgt_func is not None and tgt_func.start_ea == target_ea


# --------------------------------------------------------------------------
def get_function_calls(func_ea: int) -> List[Tuple[str,str,int]]:
    """
    获取某个函数中所有被调用的函数信息：
      返回 [(callee_name, callee_type, line_no), ...]
    注意：可能重复，需要外层去重或保留所有出现。
    """
    callee_list: List[Tuple[str,str,int]] = []
    if func_ea == idc.BADADDR:
        return callee_list

    # ---- 1) 汇编层收集 ----
    asm_calls = collect_callees_from_asm(func_ea)

    # ---- 2) 反编译收集（含表/异或等混淆场景）----
    hr_calls = collect_callees_from_hexrays(func_ea)

    # 合并
    # 保留 (callee_ea, instr_ea) 形式以便后续关联行号
    combined = asm_calls + hr_calls

    # 若可反编译
    line_map = {}
    cfunc = ida_hexrays.decompile(func_ea)
    # 利用 find_line(ea) 获取行号（若 IDA 版本支持），否则写 0
    def get_decompiled_lineno(ea: int) -> int:
        if cfunc:
            try:
                return cfunc.find_line(ea)
            except:
                pass
        return 0

    for callee_ea, callsite_ea in combined:
        callee_type = get_call_type(callee_ea)
        callee_name = idc.get_name(callee_ea) or f"{callee_ea:#x}"
        callee_name = strip_dot_prefix(callee_name)
        line_no = get_decompiled_lineno(callsite_ea)

        callee_list.append((callee_name, callee_type, line_no))

    return callee_list


# --------------------------------------------------------------------------
def main():
    ida_auto.auto_wait()
    if ida_hexrays.init_hexrays_plugin():
        idc.msg(f"Hex‑Rays {ida_hexrays.get_hexrays_version()} loaded\n")

    funcs_list = parse_args()
    idc.msg("[+] funcs_list = {}\n".format(funcs_list))
    idc.msg(f"[+] output     = {OUT_FILE}\n")

    result = {}

    for fn in funcs_list:
        ea = get_ea_by_name(fn)
        if ea == idc.BADADDR:
            continue

        calls = get_function_calls(ea)
        # 去重（如果希望保留所有多次出现可去掉这一步）
        # 这里用 (callee_name, callee_type, line_no) 做去重
        unique_calls = list({(c[0], c[1], c[2]) for c in calls})

        # 按行号等进行排序，方便阅读
        unique_calls.sort(key=lambda x: (x[2], x[0]))

        result[fn] = unique_calls

    with open(OUT_FILE, "w", encoding="utf-8") as fp:
        json.dump(result, fp, ensure_ascii=False, indent=2)

    idc.msg(f"[+] Done! Wrote results to {os.path.abspath(OUT_FILE)}\n")
    idaapi.qexit(0)

# --------------------------------------------------------------------------
main()
