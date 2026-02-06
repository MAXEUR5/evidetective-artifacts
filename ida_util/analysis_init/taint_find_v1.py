# -*- coding: utf-8 -*-
"""
ida_taint_trace.py  –  IDA 9.1  (Python 3)

仅追踪【指定 Source 调用 → 指定 Sink 调用】的参数污点传播。
已解决 PLT/EXTRN 地址不一致 & None 传参导致的崩溃。
"""

import idaapi, ida_auto, ida_hexrays, ida_funcs, ida_xref, idautils, idc
from typing import List, Dict, Set, Tuple, Deque, Optional
from collections import defaultdict, deque
from dataclasses import dataclass, field
import os, re, json

# ---------------------------------------------------------------------------
# 0.  导入 / PLT 归一化 + 安全类型检查
# ---------------------------------------------------------------------------
def normalize_ea(ea) -> int:
    """
    把各种形态的地址统一为 Python int。
    允许的输入:
        - int / bool                   -> 直接返回 int(ea)
        - None                         -> BADADDR
        - (a, b, …) 或 [a, b, …]       -> 尝试优先选第 2 个元素作为真实地址
    """
    # list → tuple，便于统一处理
    if isinstance(ea, list):
        ea = tuple(ea)

    # tuple 处理：若第二个元素是整数，看作真实地址；否则取第一个
    if isinstance(ea, tuple):
        if len(ea) >= 2 and isinstance(ea[1], int):
            ea = ea[1]
        else:
            ea = ea[0]

    try:
        return int(ea)
    except Exception:
        return idc.BADADDR
def resolve_import_target(ea) -> int:
    ea = normalize_ea(ea)
    if ea == idc.BADADDR:
        return ea

    seen = set()
    while True:
        if ea in seen:
            return ea
        seen.add(ea)

        f = ida_funcs.get_func(ea)
        if not f:
            return ea

        if f.flags & ida_funcs.FUNC_THUNK:
            ea = normalize_ea(ida_funcs.calc_thunk_func_target(f))
            continue

        seg = idaapi.getseg(ea)
        if seg and idaapi.get_segm_name(seg).startswith(".plt"):
            ins = idaapi.insn_t()
            if idaapi.decode_insn(ins, ea) and ins.itype == idaapi.NN_jmp \
               and ins.ops[0].type == idaapi.o_mem:
                ea = normalize_ea(ins.ops[0].addr)
                continue
        return ea

# ---------------------------------------------------------------------------
# 1.  数据结构
# ---------------------------------------------------------------------------

@dataclass
class CallSite:
    caller_ea: int
    callee_ea: int
    line: int
    tainted_args: Set[int]

@dataclass
class PathResult:
    hops: List[CallSite]

# ---------------------------------------------------------------------------
# 2.  常用辅助
# ---------------------------------------------------------------------------

def func_ea(name: str) -> int:
    ea = idc.get_name_ea_simple(name)
    if ea == idc.BADADDR:
        return ea
    f = ida_funcs.get_func(ea)
    return f.start_ea if f else ea

def func_name(ea: int) -> str:
    return idc.get_func_name(ea) or hex(ea)

# ---------------------------------------------------------------------------
# 3.  Ctree 辅助
# ---------------------------------------------------------------------------

def _collect_var_idxs(expr: ida_hexrays.cexpr_t) -> Set[int]:
    s: Set[int] = set()
    class V(ida_hexrays.ctree_visitor_t):
        def __init__(self): super().__init__(ida_hexrays.CV_FAST)
        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_var:
                s.add(e.v.idx)
            return 0
    V().apply_to(expr, None)
    return s

def _expr_uses(expr: ida_hexrays.cexpr_t, tainted: Set[int]) -> bool:
    return any(idx in tainted for idx in _collect_var_idxs(expr))

# ---------------------------------------------------------------------------
# 4.  单函数局部传播
# ---------------------------------------------------------------------------

@dataclass
class LocalTaint:
    out_edges: List[CallSite]
    sink_hits: List[CallSite]

_local_cache: Dict[Tuple[int, Tuple[int, ...], int, int], LocalTaint] = {}

def analyze_function(func_ea: int,
                     initial_tainted: Set[int],
                     sink_api_ea: int,
                     sink_param: int) -> LocalTaint:
    """
    给定函数首地址和初始 tainted lvar idx 集合，
    - 任何调用若至少 1 个实参与污点相关，则视为该调用“全部参数”带污继续传播；
    - 返回 (1) 出边列表 (2) 若本函数内已命中 sink 调用则记录。
    """
    key = (func_ea, tuple(sorted(initial_tainted)), sink_api_ea, sink_param)
    if key in _local_cache:
        return _local_cache[key]

    out_edges: List[CallSite] = []
    sink_hits: List[CallSite] = []

    try:
        cf = ida_hexrays.decompile(func_ea)
    except ida_hexrays.DecompilationFailure:
        _local_cache[key] = LocalTaint(out_edges, sink_hits)
        return _local_cache[key]

    tainted = set(initial_tainted)
    changed = True
    passes = 0
    while changed and passes < 6:
        changed = False
        passes += 1

        class V(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                super().__init__(ida_hexrays.CV_FAST)

            def visit_expr(self, e):
                nonlocal changed, tainted, out_edges, sink_hits

                # 1) 赋值传播：lhs = rhs
                if e.op == ida_hexrays.cot_asg:
                    lhs, rhs = e.x, e.y
                    if _expr_uses(rhs, tainted) and \
                       lhs.op == ida_hexrays.cot_var and lhs.v.idx not in tainted:
                        tainted.add(lhs.v.idx)
                        changed = True
                    return 0  # 继续遍历

                # 2) 函数调用传播
                if e.op == ida_hexrays.cot_call:
                    # 解析被调函数地址
                    callee_ea = e.x.obj_ea if e.x.op == ida_hexrays.cot_obj else idc.BADADDR
                    callee_ea = resolve_import_target(callee_ea)
                    if callee_ea == idc.BADADDR:
                        return 0

                    # 判断是否有任意实参引用 tainted
                    hit_any = any(_expr_uses(arg, tainted) for arg in e.a)
                    if not hit_any:
                        return 0  # 该调用与当前污点无关

                    # ----- 新规则 -----
                    # a) 所有参数索引都视为 tainted 向下传播
                    all_arg_idxs = set(range(len(e.a)))

                    # b) 更新本函数内部 tainted lvar：凡参与实参的变量全部加入
                    for arg in e.a:
                        for idx in _collect_var_idxs(arg):
                            if idx not in tainted:
                                tainted.add(idx)
                                changed = True
                    # ------------------

                    # 行号
                    ln = 0
                    try:
                        _c, row = cf.find_item_coords(e)
                        ln = row + 1 if row >= 0 else 0
                    except Exception:
                        pass

                    cs = CallSite(caller_ea=func_ea,
                                  callee_ea=callee_ea,
                                  line=ln,
                                  tainted_args=all_arg_idxs)
                    out_edges.append(cs)

                    # Sink 判定
                    if callee_ea == sink_api_ea and sink_param in all_arg_idxs:
                        sink_hits.append(cs)
                return 0  # 继续遍历

        V().apply_to(cf.body, None)

    result = LocalTaint(out_edges, sink_hits)
    _local_cache[key] = result
    return result

# ---------------------------------------------------------------------------
# 5.  BFS 跨函数
# ---------------------------------------------------------------------------

def bfs_paths(src_container_ea: int, first_hops: List[CallSite],
              sink_container_ea: int, sink_api_ea: int, sink_param: int,
              shortest_only=True) -> List[PathResult]:
    idc.msg("BFS\n")
    State = Tuple[int, int]                      # type alias
    pred = {}      # type: Dict[State, Tuple[Optional[State], CallSite]]
    visited = set()  # type: Set[State]
    q = deque()     # type: Deque[State]

    for cs in first_hops:
        for p_idx in cs.tainted_args:
            st = (cs.callee_ea, p_idx)
            if st not in visited:
                visited.add(st); q.append(st)
                pred[st] = (None, cs)

    paths: List[PathResult] = []
    while q:
        func_ea, pidx = q.popleft()
        idc.msg("FUNC_EA: "+str(func_ea)+"\n")

        if func_ea == sink_container_ea:
            seed: Set[int] = set()
            try:
                cf_sink = ida_hexrays.decompile(func_ea)
                for lv in cf_sink.lvars:
                    if lv.is_arg_loc() and lv.argidx == pidx:
                        seed.add(lv.idx)
            except Exception:
                pass
            if seed:
                local_sink = analyze_function(func_ea, seed,
                                              sink_api_ea, sink_param)
                if local_sink.sink_hits:
                    hit_cs = local_sink.sink_hits[0]
                    rev: List[CallSite] = [hit_cs]
                    cur: Optional[State] = (func_ea, pidx)
                    while cur in pred:
                        prv, via = pred[cur]
                        rev.append(via)
                        cur = prv
                    paths.append(PathResult(hops=list(reversed(rev))))
                    if shortest_only:
                        break
                    continue

        # 展开
        lvars: Set[int] = set()
        try:
            cf = ida_hexrays.decompile(func_ea)
            for lv in cf.lvars:
                if lv.is_arg_loc() and lv.argidx == pidx:
                    lvars.add(lv.idx)
        except Exception:
            pass
        if not lvars:
            continue
        local = analyze_function(func_ea, lvars, sink_api_ea, sink_param)
        for cs in local.out_edges:
            for nxt_idx in cs.tainted_args:
                nxt = (cs.callee_ea, nxt_idx)
                if nxt not in visited:
                    visited.add(nxt); q.append(nxt)
                    pred[nxt] = ((func_ea, pidx), cs)
    return paths

# ---------------------------------------------------------------------------
# 6.  CLI 解析
# ---------------------------------------------------------------------------

def parse_cli():
    opts = {k: v for arg in idc.ARGV if "=" in arg for k, v in [arg.split("=", 1)]}
    if "src" not in opts or "sink" not in opts:
        idaapi.msg("Usage: src=<container>:<api>:<idx> sink=<container>:<api>:<idx> "
                   "[mode=all] [json=out.json]\n")
        idaapi.qexit(1)

    # ---------- 这里把 (\\d+) 改成 (\d+) ----------
    def triple(s: str):
        m = re.fullmatch(r"([^:]+):([^:]+):(\d+)", s)
        if not m:
            idaapi.msg(f"[!] 参数格式错误: {s}\n"); idaapi.qexit(1)
        return m.group(1), m.group(2), int(m.group(3))

    src_cont,  src_api,  src_idx  = triple(opts["src"])
    sink_cont, sink_api, sink_idx = triple(opts["sink"])
    mode     = opts.get("mode", "shortest")
    json_out = opts.get("json")
    return src_cont, src_api, src_idx, sink_cont, sink_api, sink_idx, mode, json_out

# ---------------------------------------------------------------------------
# 7.  main
# ---------------------------------------------------------------------------

def main():
    ida_auto.auto_wait(); ida_hexrays.init_hexrays_plugin()

    (src_cont, src_api, src_idx,
     sink_cont, sink_api, sink_idx,
     mode, json_out) = parse_cli()

    src_cont_ea  = func_ea(src_cont)
    sink_cont_ea = func_ea(sink_cont)
    src_api_ea   = resolve_import_target(func_ea(src_api))
    sink_api_ea  = resolve_import_target(func_ea(sink_api))
    if idc.BADADDR in (src_cont_ea, sink_cont_ea, src_api_ea, sink_api_ea):
        idaapi.msg("[!] 无法解析函数名，请检查符号或手工重命名\\n"); idaapi.qexit(1)

    # -------- 查找 Source 调用，提取污点种子 --------
    try:
        cf = ida_hexrays.decompile(src_cont_ea)
    except ida_hexrays.DecompilationFailure:
        idaapi.msg("[!] 反编译源容器失败\\n"); idaapi.qexit(1)

    seed_lvars: Set[int] = set()
    class FindSrc(ida_hexrays.ctree_visitor_t):
        def __init__(self): super().__init__(ida_hexrays.CV_FAST)
        def visit_expr(self, e):
            if e.op != ida_hexrays.cot_call:
                return 0
            callee_ea = e.x.obj_ea if e.x.op == ida_hexrays.cot_obj else idc.BADADDR
            callee_ea = resolve_import_target(callee_ea)
            if callee_ea == src_api_ea and src_idx < len(e.a):
                seed_lvars.update(_collect_var_idxs(e.a[src_idx]))
            return 0
    FindSrc().apply_to(cf.body, None)

    if not seed_lvars:
        idaapi.msg("[!] 未找到满足条件的 Source 调用点\\n"); idaapi.qexit(1)

    first_local = analyze_function(src_cont_ea, seed_lvars,
                                   sink_api_ea, sink_idx)
    first_hops = first_local.out_edges
    if not first_hops:
        idaapi.msg("[!] Source taint 未经函数调用传播，直接结束\\n")
        idaapi.qexit(0)

    idc.msg(str(src_cont_ea)+" "+str(sink_cont_ea)+" "+str(src_api_ea)+" "+str(sink_api_ea)+"\n")
    paths = bfs_paths(src_cont_ea, first_hops,
                      sink_container_ea=sink_cont_ea,
                      sink_api_ea=sink_api_ea,
                      sink_param=sink_idx,
                      shortest_only=(mode != "all"))

    if not paths:
        idaapi.msg(f"[!] 未找到从 {src_cont} → {sink_cont} 的 taint 路径\n")
    else:
        idaapi.msg(f"\n[+] Found {len(paths)} path(s)\n")
        for i, p in enumerate(paths, 1):
            idaapi.msg(f"\n--- Path {i} ---\n")
            for cs in p.hops:
                idaapi.msg(f"{func_name(cs.caller_ea)} --call(line {cs.line}, args {sorted(cs.tainted_args)})--> {func_name(cs.callee_ea)}\n")

    if paths and json_out:
        jpaths = [[{
            "caller": func_name(cs.caller_ea),
            "callee": func_name(cs.callee_ea),
            "line":   cs.line,
            "tainted_args": sorted(cs.tainted_args)
        } for cs in pr.hops] for pr in paths]
        with open(json_out, "w", encoding="utf-8") as fp:
            json.dump({"paths": jpaths}, fp, ensure_ascii=False, indent=2)
        idaapi.msg(f"[+] JSON 路径已写入 {os.path.abspath(json_out)}\n")

    idaapi.qexit(0)

# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()
    pass