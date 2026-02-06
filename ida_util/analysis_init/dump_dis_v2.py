
import json
import os

import idaapi
import idc
import idautils

import ida_funcs
import ida_lines
import ida_auto
import ida_bytes
import ida_name

# ---------- 0. 等待自动分析完成 ----------
if callable(getattr(idaapi, "auto_wait", None)):
    idaapi.auto_wait()
ida_auto.auto_wait()

# ---------- 1. 解析 funcs_list ----------
def parse_funcs_from_argv() -> list[str]:
    """
    从 idc.ARGV 中提取 'funcs_list=' 参数，并返回函数名列表。
    完全不依赖正则表达式，仅做简单字符串处理。
    """
    for arg in idc.ARGV[1:]:                 # ARGV[0] 是脚本路径
        if arg.startswith("funcs_list="):
            value = arg.partition("=")[2].strip()
            # 列表形式: [main,func1] 或 [  main , func1 ]
            if value.startswith("[") and value.endswith("]"):
                raw_items = value[1:-1].split(",")
                return [item.strip() for item in raw_items if item.strip()]
            # 单个函数
            return [value]
    # 未找到参数, 直接退出
    idc.warning("未检测到参数 funcs_list=...，脚本退出")
    idaapi.qexit(1)

FUNC_NAMES: list[str] = parse_funcs_from_argv()
idc.msg(f"[*] 解析到函数列表: {FUNC_NAMES}\n")

# ---------- 2. 确保 Hex-Rays 反编译器可用 ----------
try:
    import ida_hexrays
    if not ida_hexrays.init_hexrays_plugin():
        idc.warning("Hex-Rays 反编译器未激活，无法导出增强汇编（需要 eamap）")
        idaapi.qexit(1)
except Exception as e:
    idc.warning(f"加载 Hex-Rays 失败: {e}")
    idaapi.qexit(1)

# ---------- 3. 实用工具 ----------
def is_code(ea: int) -> bool:
    """判断 EA 处是否为代码指令。"""
    return ida_bytes.is_code(ida_bytes.get_full_flags(ea))

def get_disasm_text(ea: int) -> str:
    """
    生成一行反汇编文本（去色），优先使用 ida_lines.generate_disasm_line，
    失败则回退到 idc.GetDisasm。
    """
    try:
        s = ida_lines.generate_disasm_line(ea, 0)  # 0: 按 IDA 分析显示
        if s:
            return ida_lines.tag_remove(s)
    except Exception:
        pass
    return idc.GetDisasm(ea) or ""

def get_label_at(ea: int, func_start_ea: int) -> str | None:
    """
    若 EA 具有可见名字（如 loc_.../case_.../sub_...），则返回形如 'label:' 的行文本。
    出于贴近 GUI 效果，函数入口也允许输出（即 'sub_xxxx:'），
    如不想要可注释掉 ea == func_start_ea 的分支。
    """
    try:
        name = ida_name.get_name(ea)
    except Exception:
        name = None
    if not name:
        return None
    # 若不希望在函数首地址打印函数名标签，可取消注释下面两行：
    # if ea == func_start_ea:
    #     return None
    return f"{name}:"

def is_meaningful_pseudoline(text: str) -> bool:
    """
    依据 Hex-Rays 文档中 “Copy to assembly 仅复制有意义行（省略 {}, else/do）” 的描述做过滤：
    https://docs.hex-rays.com/9.0/user-guide/decompiler/interactive/cmd_copy
    """
    s = text.strip()
    if not s:
        return False
    if s in ("{", "}"):
        return False
    # 仅 'else' 或 'do' 关键字行剔除；"else if (...)" 仍保留
    if s == "else" or s == "do":
        return False
    return True

def build_ea_to_pseudorows(cfunc) -> dict[int, list[int]]:
    """
    使用 cfunc.get_eamap() 与 cfunc.find_item_coords() 建立:
        EA -> [伪代码行号row(y)] 的映射。
    - get_eamap(): EA -> cinsn_t* 向量
    - find_item_coords(citem): 返回 (x, y)，其中 y 即 pseudocode 中的行号
    参考 API ：
      * cfunc_t.get_eamap() / eamap_t.at(ea) / cinsnptrvec_t
      * cfunc_t.find_item_coords()
    """
    ea2rows: dict[int, list[int]] = {}
    eamap = cfunc.get_eamap()  # ea -> cinsn_t*[]
    for ea in idautils.FuncItems(cfunc.entry_ea):
        if not is_code(ea):
            continue
        rows = set()
        try:
            cvec = eamap.at(ea)  # cinsnptrvec_t
        except Exception:
            cvec = None
        if cvec:
            for i in range(len(cvec)):
                ci = cvec[i]
                try:
                    xy = cfunc.find_item_coords(ci)  # (x, y)
                    if isinstance(xy, tuple) and len(xy) == 2:
                        rows.add(int(xy[1]))
                except Exception:
                    # 某些节点可能找不到坐标，忽略
                    pass
        if rows:
            ea2rows[ea] = sorted(rows)
    return ea2rows

def make_enhanced_disasm_for_func(f: ida_funcs.func_t, cfunc) -> str:
    """
    生成“增强汇编”文本：
      - 插入 label 行（与 GUI 反汇编一致的 'xxx:'）
      - 在首个对应指令前插入伪代码注释行（尽量模拟 GUI 的 Copy to assembly）
      - 输出指令行
    """
    sv = cfunc.get_pseudocode()  # strvec_t
    ea2rows = build_ea_to_pseudorows(cfunc)
    printed_rows = set()  # 已输出的伪代码行号，避免重复

    lines: list[str] = []

    # 按函数地址顺序遍历
    for ea in idautils.FuncItems(f.start_ea):
        if not is_code(ea):
            continue

        # 1) label 行（若有）
        lbl = get_label_at(ea, f.start_ea)
        if lbl:
            lines.append(lbl)

        # 2) 伪代码注释行（仅在尚未输出过该行时插入）
        rows = ea2rows.get(ea, [])
        for y in rows:
            if y in printed_rows:
                continue
            try:
                raw = sv[y].line  # 含色标
                text = ida_lines.tag_remove(raw)
            except Exception:
                continue
            if is_meaningful_pseudoline(text):
                # 用 '; ' 作为注释前缀，尽量贴近 IDA 列表视图样式
                lines.append(f"; {text}")
            printed_rows.add(y)

        # 3) 指令行
        lines.append(get_disasm_text(ea))

    return "\n".join(lines)

# ---------- 4. 主流程 ----------
result: dict[str, dict[str, str]] = {}

for func_name in FUNC_NAMES:
    func_ea = idc.get_name_ea_simple(func_name)
    if func_ea == idc.BADADDR:
        idc.msg(f"[!] 未找到函数 '{func_name}'，跳过\n")
        continue

    f = ida_funcs.get_func(func_ea)
    if not f:
        idc.msg(f"[!] 获取函数对象 '{func_name}' 失败，跳过\n")
        continue

    # 4-1. 导出“原始反汇编”（维持你原有的行为：仅指令，不含 label）
    dis_lines: list[str] = [
        idc.GetDisasm(ea) for ea in idautils.Heads(f.start_ea, f.end_ea) if is_code(ea)
    ]
    disasm_text = "\n".join(dis_lines)

    # 4-2. 导出伪代码
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        pcode_lines = [
            ida_lines.tag_remove(sline.line) for sline in cfunc.get_pseudocode()
        ]
        pcode_text = "\n".join(pcode_lines)
    except ida_hexrays.DecompilationFailure as e:
        idc.msg(f"[!] 反编译 '{func_name}' 失败: {e}\n")
        cfunc = None
        pcode_text = ""

    # 4-3. 生成“增强汇编”（需要成功拿到 cfunc）
    if cfunc:
        try:
            disasm_enhanced = make_enhanced_disasm_for_func(f, cfunc)
        except Exception as ee:
            idc.msg(f"[!] 生成增强汇编 '{func_name}' 失败: {ee}\n")
            disasm_enhanced = ""
    else:
        disasm_enhanced = ""

    # 4-4. 收集结果
    result[func_name] = {
        "pcode": pcode_text,
        "disasm": disasm_text,
        "disasm_enhanced": disasm_enhanced,
    }

# ---------- 5. 写入 JSON ----------
out_path = "func_dis.json"
try:
    with open(out_path, "w", encoding="utf-8") as fp:
        json.dump(result, fp, ensure_ascii=False, indent=2)
    idc.msg(f"[*] 结果已保存至 {out_path}\n")
except Exception as err:
    fallback = os.path.join(os.getcwd(), "func_dis.json")
    with open(fallback, "w", encoding="utf-8") as fp:
        json.dump(result, fp, ensure_ascii=False, indent=2)
    idc.msg(f"[!] 写入 {out_path} 失败({err})，已改存 {fallback}\n")

# ---------- 6. 结束 ----------
idaapi.qexit(0)
#./ida -A -L"output.log" -S"/home/workspace/ida_util/analysis_init/dump_dis_v2.py funcs_list=goodG2B" /home/workspace/jc/juliet-test-suite-c/test/CWE121_Stack_Based_Buffer_Overflow__dest_char_alloca_cat_12-good