# -*- coding: utf-8 -*-
"""
func_stack_dump_v6.py  –  IDA 9.1
批量导出多个函数的局部变量（栈/寄存器）及其伪代码行号使用情况。
#./ida -A -L"output.log" -S"/home/workspace/ida_util/analysis_init/func_stack_dump_v6.py funcs_list=sub_138D,sub_1402" /home/workspace/Testcase/test3/vuln_n

用法示例：
    # 批量
    ida -A -L"output.log" -S"/path/func_stack_dump_v6.py funcs_list=foo,bar,baz" /path/target.bin

    # 兼容旧用法：单个函数
    ida -A -L"output.log" -S"/path/func_stack_dump_v6.py foo" /path/target.bin

输出：
    当前工作目录下生成 func_stack_varmatch.json，结构大致为：
    {
      "foo": {
        "function_name": "foo",
        "__return_address_offset": ...,
        "variables": [ ... ]
      },
      "bar": { ... }
    }
"""

import idc              # type: ignore
import idaapi           # type: ignore
import ida_funcs        # type: ignore
import ida_lines        # type: ignore
import ida_hexrays      # type: ignore
import ida_typeinf      # type: ignore
import ida_frame        # type: ignore
import ida_auto         # type: ignore
import idautils         # type: ignore
import json             # type: ignore


OUT_FILE = "func_stack_varmatch.json"


# -------------------------------------------------------------------------------------
# 1) 判断当前二进制是否 64 位，不使用图形接口
# -------------------------------------------------------------------------------------
def is_64bit():
    """
    优先使用 ida_ida.idainfo_is_64bit()，
    若不存在则尝试 idaapi.cvar.inf.is_64bit()，
    若都失败则抛错。
    """
    try:
        from ida_ida import idainfo_is_64bit
        return idainfo_is_64bit()
    except ImportError:
        pass

    inf = idaapi.cvar.inf
    if inf is not None and hasattr(inf, "is_64bit"):
        return inf.is_64bit()

    raise RuntimeError("无法判断当前二进制是32位还是64位："
                       "idainfo_is_64bit() 和 cvar.inf.is_64bit() 均不可用。")


# -------------------------------------------------------------------------------------
# 2) EA -> 行号映射的构建方式（eamap 优先，失败则 ctree）
# -------------------------------------------------------------------------------------
def build_ea2line_map_via_eamap(cfunc):
    """
    利用 cfunc.get_eamap() 构建从 EA 到伪代码行号的映射
    """
    ea2line = {}
    if not cfunc:
        return ea2line

    # 先触发生成伪代码
    _ = cfunc.get_pseudocode()
    em = cfunc.get_eamap()
    if not em:
        return ea2line

    for ea, items in em.items():
        best_line = None
        for it in items:
            try:
                c, r = cfunc.find_item_coords(it)
                if r >= 0 and (best_line is None or r < best_line):
                    best_line = r
            except Exception:
                pass
        if best_line is not None:
            # +1 让行号更贴近伪代码显示
            ea2line[ea] = best_line + 1
    return ea2line


def build_ea2line_map_via_ctree(cfunc):
    """
    通过遍历 ctree 构建 EA -> 行号映射
    """
    ea2line = {}
    ln = 1
    if not cfunc:
        return ea2line

    class MyCtreeVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_stmt(self, s):
            nonlocal ln
            if s.ea != idc.BADADDR and s.ea not in ea2line:
                ea2line[s.ea] = ln
            ln += 1
            return 0

    visitor = MyCtreeVisitor()
    visitor.apply_to(cfunc.body, None)
    return ea2line


def choose_ea2line_map_builder(cfunc):
    """
    优先尝试 eamap，若为空或失败则回退到 ctree
    """
    try:
        m = build_ea2line_map_via_eamap(cfunc)
        if m:
            return m
    except Exception:
        pass
    return build_ea2line_map_via_ctree(cfunc)


# -------------------------------------------------------------------------------------
# 3) 收集局部变量使用行号，包含对赋值表达式(cot_asg)和函数调用(cot_call)等的处理
# -------------------------------------------------------------------------------------
def find_var_usage_lines(cfunc):
    """
    返回 usage_map: dict( var_idx -> set( 行号 ) )
    其中行号基于 eamap 或 ctree 计算得来。
    """
    lvars = cfunc.get_lvars()
    usage_map = {i: set() for i in range(len(lvars))}
    ea2line = choose_ea2line_map_builder(cfunc)

    # 在表达式级获取“行号”时，如果 e.ea == BADADDR，就用 find_item_coords 兜底
    def add_usage(var_idx, e):
        ea = e.ea
        if ea != idc.BADADDR and ea in ea2line:
            usage_map[var_idx].add(ea2line[ea])
        else:
            # fallback: 直接用 find_item_coords 来获取行坐标
            try:
                c, r = cfunc.find_item_coords(e)
                if r >= 0:
                    usage_map[var_idx].add(r + 1)
            except Exception:
                pass

    def collect_var_indexes(e, out_set):
        """递归：收集当前表达式 e 中出现的所有局部变量 var_idx"""
        if not e:
            return

        # 遇到变量节点
        if e.op == ida_hexrays.cot_var:
            out_set.add(e.v.idx)

        # 继续下探 x, y, z
        if e.x and isinstance(e.x, ida_hexrays.cexpr_t):
            collect_var_indexes(e.x, out_set)
        if e.y and isinstance(e.y, ida_hexrays.cexpr_t):
            collect_var_indexes(e.y, out_set)
        if e.z and isinstance(e.z, ida_hexrays.cexpr_t):
            collect_var_indexes(e.z, out_set)

        # 如果是函数调用，需要遍历参数列表 e.a
        if e.op == ida_hexrays.cot_call and e.a:
            for arg_expr in e.a:
                if arg_expr and isinstance(arg_expr, ida_hexrays.cexpr_t):
                    collect_var_indexes(arg_expr, out_set)

    class VarUsageVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            """
            - 若是一般变量引用 (cot_var)，单独记录其所在表达式的行号
            - 若是赋值表达式 (cot_asg)，把左右子表达式里的所有 var 均视作在同一行出现
            - 若是其他表达式 (含函数调用 cot_call)，也会在递归中搜集 var；行号根据具体需要记录
            """
            if e.op == ida_hexrays.cot_var:
                # 记录单个变量引用
                add_usage(e.v.idx, e)

            elif e.op == ida_hexrays.cot_asg:
                # 对赋值左右两侧收集
                var_idxs = set()
                collect_var_indexes(e.x, var_idxs)
                collect_var_indexes(e.y, var_idxs)
                # 在这条“赋值表达式”本身的行号上，登记所有参与的变量
                for vid in var_idxs:
                    add_usage(vid, e)

            else:
                # 其他表达式可能包含函数调用、数组引用等
                # 默认逻辑：它的子表达式会在 deeper visit_expr 中处理“cot_var”引用
                pass

            return 0

    visitor = VarUsageVisitor()
    visitor.apply_to(cfunc.body, None)
    return usage_map


# -------------------------------------------------------------------------------------
# 4) 参数解析：支持 funcs_list=foo,bar 以及旧用法 ARGV[1]=foo
# -------------------------------------------------------------------------------------
def parse_funcs_from_argv():
    """
    优先从 ARGV 中解析 funcs_list=...，
    如果没有，则回退到旧的单函数用法：ARGV[1] 即函数名。
    返回: [func_name1, func_name2, ...]
    """
    funcs = []

    # 1) 解析 funcs_list=...
    for a in idc.ARGV[1:]:
        if a.startswith("funcs_list="):
            raw = a.split("=", 1)[1].strip()
            if raw.startswith("["):
                # JSON 列表形式
                try:
                    funcs = json.loads(raw)
                except Exception:
                    funcs = []
            else:
                # 逗号分隔形式
                funcs = [x.strip() for x in raw.split(",") if x.strip()]
            break

    # 2) 回退：旧用法，-S"func_stack_dump_v6.py funcA"
    if not funcs and len(idc.ARGV) >= 2:
        funcs = [idc.ARGV[1]]

    if not funcs:
        idc.msg(
            "[!] Usage: -S\"func_stack_dump_v6.py funcs_list=foo,bar\" "
            "or -S\"func_stack_dump_v6.py foo\"\n"
        )
        idaapi.qexit(1)

    return funcs


# -------------------------------------------------------------------------------------
# 5) 单个函数分析逻辑：尽量与 v5 保持一致，只是改为返回数据结构
# -------------------------------------------------------------------------------------
def analyze_one_function(func_name):
    """
    分析单个函数，返回结构:
    {
        "function_name": func_name,
        "__return_address_offset": ...,
        "variables": [ ... ]
    }
    """
    idc.msg(f"[+] Analyzing function: {func_name}\n")

    func_ea = idc.get_name_ea_simple(func_name)
    if func_ea == idc.BADADDR:
        idc.msg(f"[!] Function '{func_name}' not found!\n")
        return None

    f = ida_funcs.get_func(func_ea)
    if not f:
        idc.msg(f"[!] Failed to get function object for '{func_name}'!\n")
        return None

    cfunc = ida_hexrays.decompile(f)
    if not cfunc:
        idc.msg(f"[!] Decompilation of '{func_name}' failed!\n")
        return None

    # ====== 帧信息 & 返回地址偏移（用 ida_frame API）======
    tinfo = ida_typeinf.tinfo_t()
    if not tinfo.get_func_frame(f):  # 推荐写法：面向对象
        idc.msg(f"[!] No function frame recognized for '{func_name}'!\n")
        return None

    # 直接拿帧坐标中的返回地址起始偏移（locals<0, args>0）
    ret_addr_offset = ida_frame.frame_off_retaddr(f)
    idc.msg(f"[+] __return_address offset (frame coord) = {ret_addr_offset:#x}\n")

    # ====== 构造 UDT 映射到“帧坐标” ======
    udt = ida_typeinf.udt_type_data_t()
    if not tinfo.get_udt_details(udt):
        idc.msg(f"[!] Unable to get UDT details for '{func_name}'!\n")
        return None

    udt_map = {}
    for m in udt:
        # m.offset 是 bit，先转字节的“结构偏移”
        soff = m.offset // 8
        # 把结构偏移换成“帧指针相对偏移”（fp-relative, 即 Stack 窗口用的坐标）
        fpoff = ida_frame.soff_to_fpoff(f, soff)
        mem_tinfo = m.type
        udt_map[fpoff] = {
            "name": m.name,
            "type_str": mem_tinfo.dstr(),
            "size": mem_tinfo.get_size()
        }

    # ====== 变量使用行号 ======
    var_usage_map = find_var_usage_lines(cfunc)
    lvars = cfunc.get_lvars()
    results = []

    for idx, lvar in enumerate(lvars):
        if not lvar.name:
            continue

        lvar_tinfo = lvar.type()
        lvar_type_str = lvar_tinfo.dstr()
        lvar_size = lvar.width

        # ---------------- 寄存器变量 ----------------
        if lvar.is_reg_var():
            loc_obj = lvar.location
            if loc_obj.is_reg1():
                reg_id = loc_obj.reg1()
            elif loc_obj.is_reg2():
                # 这里沿用你原来的处理方式：直接抛错
                raise ValueError("[X] Two-register location not handled.")
            else:
                raise ValueError("[X] Unsupported register location type.")

            results.append({
                "lvar_idx": idx,
                "lvar_name": lvar.name,
                "lvar_type": lvar_type_str,
                "lvar_size": lvar_size,
                "usage_lines": sorted(list(var_usage_map[idx])),
                "reg_id": reg_id
            })
            continue

        # ---------------- 栈变量 ----------------
        if lvar.is_stk_var():
            # 修复点：帧偏移换算要“减去” delta，使之与 Stack 窗口坐标对齐
            lvar_off_in_frame = lvar.location.stkoff() - cfunc.get_stkoff_delta()

            rec = {
                "lvar_idx": idx,
                "lvar_name": lvar.name,
                "lvar_offset": lvar_off_in_frame,  # Stack 窗口坐标：locals<0，ret/args>=0
                "lvar_type": lvar_type_str,
                "lvar_size": lvar_size,
                "usage_lines": sorted(list(var_usage_map[idx])),
                "udt_name": None,
                "udt_type": None,
                "udt_size": None,
                # 负数 = 在返回地址之下（更深的栈）
                "dist_from_ret_addr": lvar_off_in_frame - ret_addr_offset
            }

            udt_member = udt_map.get(lvar_off_in_frame, None)
            if udt_member:
                rec["udt_name"] = udt_member["name"]
                rec["udt_type"] = udt_member["type_str"]
                rec["udt_size"] = udt_member["size"]

            results.append(rec)
            continue

        # 其他位置类型（全局、TLS 等），此处直接跳过，仅在 log 中提示
        idc.msg(f"[~] lvar idx={idx} is neither reg_var nor stk_var, skip.\n")

    out_data = {
        "function_name": func_name,
        "__return_address_offset": ret_addr_offset,
        "variables": results
    }
    return out_data


# -------------------------------------------------------------------------------------
# 6) main：批量函数 → 汇总写入一个 JSON
# -------------------------------------------------------------------------------------
def main():
    ida_auto.auto_wait()

    if not ida_hexrays.init_hexrays_plugin():
        idc.msg("[!] Hex-Rays decompiler plugin not available.\n")
        idaapi.qexit(1)

    try:
        arch64 = is_64bit()
        idc.msg(f"[+] is_64bit = {arch64}\n")
    except RuntimeError as e:
        idc.msg(f"[!] {e}\n")
        idaapi.qexit(1)

    funcs = parse_funcs_from_argv()
    idc.msg(f"[+] Total {len(funcs)} functions to analyze.\n")

    all_data = {}
    for func_name in funcs:
        data = analyze_one_function(func_name)
        if data is not None:
            all_data[func_name] = data

    with open(OUT_FILE, "w", encoding="utf-8", errors="replace") as outf:
        json.dump(all_data, outf, indent=2, ensure_ascii=False)

    idaapi.msg(f"[+] JSON result saved to: {OUT_FILE}\n")
    idaapi.qexit(0)


if __name__ == "__main__":
    main()
