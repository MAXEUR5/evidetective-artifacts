# --------------------------------------------------------------------------
#  IDA 9.1  ‑  Call‑Map  v2-final (Multi‑Target Fixed + BugFix)
#  功能 : 给定函数列表，输出每个函数的直接调用图（含重复调用点、外部 API、异或表函数指针）
#  修正 : 修复了因为 rand() 赋值导致后续误将 rand() 认为是其它间接调用的问题
#  作者 : 2025‑04‑13  @ChatGPT‑o3
# --------------------------------------------------------------------------

import idaapi
import ida_auto
import ida_hexrays
import ida_funcs
import ida_xref
import idautils
import idc
import ida_bytes
import json
import os
from typing import List, Dict, Tuple, Set, Optional

OUT_FILE       = "callmap.json"
MAX_DEF_SEARCH = 1000          # 轻量切片遍历阈值

# --------------------------------------------------------------------------
# ---------------------------- parse_args ----------------------------------

def parse_args() -> List[str]:
    """
    从命令行参数中解析函数名称列表：
      ida.exe -S"callmap_v2_final.py funcs_list=f1,f2,..."
    """
    funcs: List[str] = []
    for a in idc.ARGV:
        if a.startswith("funcs_list="):
            funcs = [s.strip() for s in a.split("=", 1)[1].split(",") if s.strip()]
            break
    if not funcs:
        idc.msg('Usage: -S"callmap_v2_final.py funcs_list=f1,f2,..."\n')
        idaapi.qexit(1)
    return funcs

# --------------------------------------------------------------------------
# ---------------------------- 工具函数 -------------------------------------

def is_internal(ea: int) -> bool:
    """
    判断 ea 是否属于用户自定义函数（非导入/plt/lib）
    """
    f = ida_funcs.get_func(ea)
    if not f:
        return False
    seg = idaapi.getseg(ea)
    if seg and seg.type in (idaapi.SEG_XTRN, idaapi.SEG_GRP):
        return False
    if f.flags & ida_funcs.FUNC_LIB:
        return False
    return True

def is_plt(ea: int) -> bool:
    """
    判断 ea 是否落在 .plt / .plt.got 段
    """
    segname = idc.get_segm_name(ea)
    return bool(segname and segname.startswith(".plt"))

def normalize_api_name(name: str) -> str:
    """
    去掉前缀 . / _imp_ / __imp_
    """
    if name.startswith("."):
        return name[1:]
    for p in ("_imp_", "__imp_"):
        if name.startswith(p):
            return name[len(p):]
    return name

def ea_category(ea: int) -> str:
    """
    根据 EA 所在的段、函数标记判断类别：
      IMPORT_API / USER_DEF / OTHER
    """
    if ea == idaapi.BADADDR:
        return "OTHER"

    seg = idaapi.getseg(ea)
    if seg and seg.type == idaapi.SEG_XTRN:
        return "IMPORT_API"

    f = ida_funcs.get_func(ea)
    if not f:
        return "OTHER"

    # thunk 指向外部 / import
    if f.flags & ida_funcs.FUNC_THUNK:
        tgt = ida_funcs.calc_thunk_func_target(f)
        if isinstance(tgt, int):
            seg2 = idaapi.getseg(tgt)
            if seg2 and seg2.type == idaapi.SEG_XTRN:
                return "IMPORT_API"

    # 判断 plt / lib
    if is_plt(ea) or (f.flags & ida_funcs.FUNC_LIB):
        return "IMPORT_API"

    return "USER_DEF"

# --------------------------------------------------------------------------
# ----------------------- 反向切片辅助 (与 DFS 版一致) ----------------------

def try_resolve_callee(expr) -> Optional[int]:
    """
    递归寻找表达式树中的函数地址 (cot_obj)
    """
    if expr.op == ida_hexrays.cot_obj:
        return expr.obj_ea
    elif expr.op in (
        ida_hexrays.cot_cast, ida_hexrays.cot_ref, ida_hexrays.cot_ptr,
        ida_hexrays.cot_memptr, ida_hexrays.cot_memref
    ):
        return try_resolve_callee(expr.x)
    return None

def collect_func_objs(expr) -> Set[int]:
    """
    收集表达式树中出现的全部函数地址 (cot_obj)，需 is_internal() 过滤
    """
    found: Set[int] = set()
    class _V(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_obj and is_internal(e.obj_ea):
                found.add(e.obj_ea)
            return 0
    _V().apply_to(expr, None)
    return found

def expr_uses_lvar(expr, idx_set: Set[int]) -> bool:
    """
    检查表达式是否直接或间接使用了指定局部变量
    """
    class _C(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
            self.hit = False
        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_var and e.v.idx in idx_set:
                self.hit = True
                return 1  # 提前终止子树遍历
            return 0
    c = _C()
    c.apply_to(expr, None)
    return c.hit

def expr_has_calls(expr) -> bool:
    """
    检查表达式子树中是否包含函数调用 (cot_call)。
    若包含，则可以认为这条赋值是对函数返回值的赋值，不应继续把该函数再算做别的调用来源
    """
    class _Checker(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
            self.found_call = False
        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_call:
                self.found_call = True
                return 1  # 终止搜索
            return 0
    ck = _Checker()
    ck.apply_to(expr, None)
    return ck.found_call

def resolve_callee_via_defs(cfunc, callee_expr) -> List[int]:
    """
    反向切片，若 callee_expr 中无法直接解析出函数地址，
    就回溯定义 (cot_asg) 的 RHS 里搜函数地址（排除本身含 call 的情况）
    """
    results: Set[int] = set()
    lvar_idx: Set[int] = set()

    # 1) 收集 callee_expr 中出现的局部变量
    class _Grab(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_var:
                lvar_idx.add(e.v.idx)
            return 0
    _Grab().apply_to(callee_expr, None)
    if not lvar_idx:
        return []

    # 2) 在 cfunc.body 中找赋值语句
    visited = 0
    class _Back(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
        def visit_expr(self, e):
            nonlocal visited
            if visited > MAX_DEF_SEARCH:
                return 1
            if e.op == ida_hexrays.cot_asg:
                lhs, rhs = e.x, e.y
                # 如果赋值语句的 LHS 使用了我们的目标局部变量
                if expr_uses_lvar(lhs, lvar_idx):
                    # 若 RHS 本身包含函数调用，则跳过深度搜集，防止“rand()”这种被混淆
                    if expr_has_calls(rhs):
                        return 0
                    # 否则收集 RHS 中所有可能出现的函数地址
                    results.update(collect_func_objs(rhs))
            visited += 1
            return 0

    _Back().apply_to(cfunc.body, None)
    return list(results)

# --------------------------------------------------------------------------
# --------------------- 额外收集：Hex‑Rays 整体扫描 ------------------------

def collect_callees_from_hexrays(func_ea: int) -> List[int]:
    """
    对函数进行反编译，扫描所有 call 表达式，
    适配 ①直接解析 ②表达式含 obj ③反向切片
    """
    if not ida_hexrays.init_hexrays_plugin():
        return []
    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        return []

    found: Set[int] = set()

    class _CallVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
        def visit_expr(self, e):
            if e.op != ida_hexrays.cot_call:
                return 0
            callee_expr = e.x

            # a) 直接解析
            direct = try_resolve_callee(callee_expr)
            if direct and is_internal(direct):
                found.add(direct)
            else:
                # b) 若表达式中出现多个函数地址就都加进来，否则反向切片
                objs = collect_func_objs(callee_expr)
                if len(objs) == 1:
                    found.update(objs)
                # c) 仍未解析 ⇒ 反向切片
                if not objs:
                    for tgt in resolve_callee_via_defs(cfunc, callee_expr):
                        if is_internal(tgt):
                            found.add(tgt)
            return 0

    _CallVisitor().apply_to(cfunc.body, None)
    return sorted(found)

# --------------------------------------------------------------------------
# -------------------------- 尾调用识别 -------------------------------------

def is_tail_jump(insn_ea: int, tgt_ea: int) -> bool:
    """
    判断是否尾调用:
      - 指令不是 call
      - 跳转目标是有效函数入口
      - 指令可终结基本块
    """
    if idaapi.is_call_insn(insn_ea):
        return False
    f = ida_funcs.get_func(tgt_ea)
    if not f or f.start_ea != tgt_ea:
        return False
    if ida_bytes.is_flow(idaapi.get_full_flags(insn_ea)):
        return False
    return idaapi.is_jmp_insn(insn_ea)

# --------------------------------------------------------------------------
# ------------------------- 调用收集主函数 ---------------------------------

def collect_calls(func_ea: int) -> List[Tuple[str, str, int]]:
    """
    返回 [(callee_name, category, line_no), ...]
      - 允许同一 call_ea 指向多个 callee
      - 最终按照 (line_no, callee_name) 排序
    """
    # 改用 (callsite_ea, callee_ea) 作为字典key，支持一条 call 对多个目标
    callsite_map: Dict[Tuple[int,int], Tuple[str,str,int]] = {}

    # ========== 1) Hex‑Rays：逐 call_expr 提取 ==========
    if ida_hexrays.init_hexrays_plugin():
        cfunc = ida_hexrays.decompile(func_ea)
        if cfunc:
            def line_of(item) -> int:
                coord = cfunc.find_item_coords(item)
                return coord[1] + 1 if coord else -1

            class _CallVis(ida_hexrays.ctree_visitor_t):
                def __init__(self):
                    super().__init__(ida_hexrays.CV_FAST)
                def visit_expr(self, e):
                    if e.op != ida_hexrays.cot_call:
                        return 0
                    call_ea = e.ea
                    call_line = line_of(e)

                    # 解析 callee
                    callee_ea = try_resolve_callee(e.x)
                    if callee_ea:
                        targets = [callee_ea]
                    else:
                        objs = collect_func_objs(e.x)
                        # 若只有一个函数地址就直接用，否则反向切片
                        if len(objs) == 1:
                            targets = list(objs)
                        else:
                            targets = resolve_callee_via_defs(cfunc, e.x)

                    for tgt in targets:
                        if tgt == idaapi.BADADDR:
                            continue
                        key = (call_ea, tgt)
                        if key in callsite_map:
                            continue
                        cat  = ea_category(tgt)
                        raw_name = idc.get_func_name(tgt) or idc.get_name(tgt) or f"{tgt:#x}"
                        name = normalize_api_name(raw_name)
                        callsite_map[key] = (name, cat, call_line)

                    return 0

            _CallVis().apply_to(cfunc.body, None)

    # ========== 2) 汇编补漏：call & tailcall ==========
    for insn in idautils.FuncItems(func_ea):
        if idaapi.is_call_insn(insn):
            # 正常call
            xr = next((xr for xr in idautils.XrefsFrom(insn, ida_xref.XREF_FAR) if xr.iscode), None)
            if xr:
                tgt = xr.to
                if tgt != idaapi.BADADDR:
                    key = (insn, tgt)
                    if key not in callsite_map:
                        cat  = ea_category(tgt)
                        raw_name = idc.get_func_name(tgt) or idc.get_name(tgt) or f"{tgt:#x}"
                        name = normalize_api_name(raw_name)
                        callsite_map[key] = (name, cat, -1)
        else:
            # 尾调用
            xr = next((xr for xr in idautils.XrefsFrom(insn, ida_xref.XREF_FAR) if xr.iscode), None)
            if xr:
                tgt = xr.to
                if is_tail_jump(insn, tgt):
                    key = (insn, tgt)
                    if key not in callsite_map:
                        cat  = ea_category(tgt)
                        raw_name = idc.get_func_name(tgt) or f"{tgt:#x}"
                        name = normalize_api_name(raw_name)
                        callsite_map[key] = (name, cat, -1)

    # ========== 3) thunk 函数处理 ==========
    f = ida_funcs.get_func(func_ea)
    if f and (f.flags & ida_funcs.FUNC_THUNK):
        tgt = ida_funcs.calc_thunk_func_target(f)
        if isinstance(tgt, int):
            key = (f.start_ea, tgt)
            if key not in callsite_map:
                cat  = ea_category(tgt)
                raw_name = idc.get_func_name(tgt) or f"{tgt:#x}"
                name = normalize_api_name(raw_name)
                callsite_map[key] = (name, cat, -1)

    # ========== 4) 二次补充：Hex‑Rays 全局表扫描 (混淆) ==========
    # 这里会把任何可能的 callee 都加进来（行号统一 -1）
    for tgt in collect_callees_from_hexrays(func_ea):
        # 如果已在 map 中就不重复添加
        if any(k[1] == tgt for k in callsite_map):
            continue
        key = (-1, tgt)  # 随意占位
        cat  = ea_category(tgt)
        raw_name = idc.get_func_name(tgt) or f"{tgt:#x}"
        name = normalize_api_name(raw_name)
        callsite_map[key] = (name, cat, -1)

    # ========== 输出：按 (行号, 函数名) 排序 ==========
    entries = list(callsite_map.values())
    return sorted(entries, key=lambda t: (t[2], t[0]))

# --------------------------------------------------------------------------
# ----------------------------- main ---------------------------------------

def main():
    ida_auto.auto_wait()
    funcs = parse_args()
    idc.msg(f"[+] funcs_list = {funcs}\n[+] output     = {OUT_FILE}\n")
    if ida_hexrays.init_hexrays_plugin():
        idc.msg(f"Hex‑Rays {ida_hexrays.get_hexrays_version()} loaded\n")

    callmap: Dict[str, List[List]] = {}
    for fn in funcs:
        ea = idc.get_name_ea_simple(fn)
        f  = ida_funcs.get_func(ea) if ea != idaapi.BADADDR else None
        if not f:
            idc.msg(f"[!] Function '{fn}' not found, skip\n")
            continue

        # 收集结果
        calls = collect_calls(f.start_ea)
        callmap[fn] = [list(t) for t in calls]

        idc.msg(f"    ├─ {fn}: {len(calls)} call‑sites\n")

    # 写入文件
    with open(OUT_FILE, "w", encoding="utf-8") as fp:
        json.dump(callmap, fp, ensure_ascii=False, indent=2)

    idc.msg(f"[+] Call‑map written to {os.path.abspath(OUT_FILE)}\n")
    idaapi.qexit(0)

# --------------------------------------------------------------------------
main()
