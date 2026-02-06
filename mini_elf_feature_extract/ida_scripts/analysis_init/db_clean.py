"""
Clean IDA artifacts for a target binary (Linux/Ubuntu, pure Python).

Usage:
  python3 clean_ida_artifacts.py /path/to/target.bin               # 直接删除
  python3 clean_ida_artifacts.py /path/to/target.bin --dry-run     # 仅预演
  python3 clean_ida_artifacts.py /path/to/target.bin \
      --extra-dir /work/idas --extra-dir /tmp                      # 额外目录
  python3 clean_ida_artifacts.py /path/to/target.bin -v            # 输出更详细

Options:
  --dry-run            仅展示将删除的对象，不实际删除
  --extra-dir DIR      额外扫描目录（可多次指定），只在这些目录的顶层匹配
  -v, --verbose        详细日志
  --patterns PATS      追加自定义 glob（逗号分隔，支持 {base} 占位，例如: "{base}*.til,{base}*.tilib"）
  --no-base-strip      不进行“逐层去扩展名”的基名回退（默认会把 libc.so.6 -> libc.so -> libc）
  --no-realpath        不使用 realpath 目录；仅用传入路径所在目录
  --keep-empty-dirs    删除后保留空目录（默认不会创建/删除目录；仅删除文件或既有的 *.files 目录）
"""

import argparse
import glob
import os
import shutil
import stat
from typing import Iterable, List, Set


# ---------- 默认匹配模式 ----------
DEFAULT_GLOBS = [
    "{base}.i64",
    "{base}.i64.*",
    "{base}.i64.files",      # 目录
    "{base}.idb",
    "{base}.idb.*",
    "{base}.idb.files",      # 目录（少见）
    "{base}.id0",
    "{base}.id1",
    "{base}.id2",
    "{base}.nam",
    # 类型库及其变体（更宽松，覆盖你遇到的 .til 反复生成问题）
    "{base}.til",
    "{base}*.til",
    "{base}.til.*",
    "{base}.tilib",
    "{base}*.tilib",
    "{base}.tilib.*",
    # 备份/临时
    "{base}.i64.bak",
    "{base}.idb.bak",
]


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("target", help="目标二进制文件路径")
    ap.add_argument("--dry-run", action="store_true", default=False)
    ap.add_argument("--extra-dir", action="append", default=[],
                    help="额外扫描目录（可多次指定）")
    ap.add_argument("--patterns", default="", help="追加自定义模式，逗号分隔")
    ap.add_argument("--no-base-strip", action="store_true", default=False,
                    help="不做逐层去扩展名（libc.so.6 -> libc.so -> libc）")
    ap.add_argument("--no-realpath", action="store_true", default=False,
                    help="不使用 realpath(目标) 所在目录")
    ap.add_argument("-v", "--verbose", action="store_true", default=False)
    ap.add_argument("--keep-empty-dirs", action="store_true", default=False)
    return ap.parse_args()


# ---------- 工具函数 ----------
def iter_bases(path: str, strip: bool = True) -> Iterable[str]:
    """依次返回可能的基名（完整名优先），用于构造 {base}。"""
    yield path
    if not strip:
        return
    p = path
    while True:
        b, ext = os.path.splitext(p)
        if not ext:
            break
        p = b
        yield p


def expand_patterns(bases: Iterable[str], patterns: List[str]) -> List[str]:
    globs = []
    for base in bases:
        for pat in patterns:
            globs.append(pat.format(base=base))
    return globs


def uniqued(seq: Iterable[str]) -> List[str]:
    out, seen = [], set()
    for s in seq:
        if s not in seen:
            out.append(s)
            seen.add(s)
    return out


def chmod_writable(path: str):
    try:
        mode = os.lstat(path).st_mode
        # 确保用户可写，目录可执行位（进入目录）
        add = stat.S_IWUSR | stat.S_IRUSR | (stat.S_IXUSR if stat.S_ISDIR(mode) else 0)
        os.chmod(path, mode | add)
    except Exception:
        pass


def onerror_rmtree(func, path, exc_info):
    try:
        chmod_writable(path)
        func(path)
    except Exception:
        raise


def force_remove(path: str, verbose: bool = False):
    if os.path.isdir(path) and not os.path.islink(path):
        if verbose:
            print(f"[DEL-DIR] {path}")
        shutil.rmtree(path, onerror=onerror_rmtree)
    else:
        if verbose:
            print(f"[DEL]     {path}")
        chmod_writable(path)
        os.remove(path)


# ---------- 主流程 ----------
def main():
    args = parse_args()

    target = os.path.abspath(os.path.expanduser(args.target))
    if not os.path.exists(target):
        print(f"[!] 目标不存在：{target}")
        raise SystemExit(1)

    # 构造候选目录：传入目录、realpath 目录（可选）、用户额外目录
    dirs: List[str] = [os.path.dirname(target)]
    if not args.no_realpath:
        rp = os.path.realpath(target)
        rp_dir = os.path.dirname(rp)
        if rp_dir not in dirs:
            dirs.append(rp_dir)
    for d in args.extra_dir:
        d = os.path.abspath(os.path.expanduser(d))
        if d not in dirs:
            dirs.append(d)

    # 组合模式
    patterns = list(DEFAULT_GLOBS)
    if args.patterns.strip():
        patterns.extend([p.strip() for p in args.patterns.split(",") if p.strip()])

    bases = list(iter_bases(os.path.join(dirs[0], os.path.basename(target)),
                            strip=(not args.no_base_strip)))
    # 为 realpath/extra-dir 构造匹配时，基名只替换目录，不改变基名字符串
    base_names = [os.path.basename(b) for b in bases]

    # 收集候选（不递归；只在各目录顶层 glob）
    candidates: List[str] = []
    seen: Set[str] = set()
    for d in dirs:
        for base in base_names:
            # 在当前目录下的“基名”路径
            full_base = os.path.join(d, base)
            globs = expand_patterns([full_base], patterns)
            for g in globs:
                for p in glob.glob(g):
                    ap = os.path.abspath(p)
                    if ap not in seen and os.path.exists(ap):
                        candidates.append(ap)
                        seen.add(ap)

    if not candidates:
        print("[SUMMARY] 未发现可清理的 IDA 数据库/派生文件。")
        raise SystemExit(0)

    # 稳定排序：先文件、后目录，长路径后删；避免目录先删导致报错
    candidates.sort(key=lambda p: (os.path.isdir(p) and not os.path.islink(p), len(p)))

    #print("[i] 目标二进制 :", target)
    #print("[i] 扫描目录   :", ", ".join(dirs))
    #print("[i] 匹配数量   :", len(candidates))
    for p in candidates:
        kind = "DIR " if os.path.isdir(p) and not os.path.islink(p) else "FILE"
        #print(f"   - ({kind}) {p}")

    if args.dry_run:
        #print(f"[SUMMARY] 计划删除 {len(candidates)} 个对象（DRY-RUN 未实际删除）。")
        raise SystemExit(0)

    deleted, failed = 0, 0
    for p in candidates:
        try:
            force_remove(p, verbose=args.verbose)
            deleted += 1
        except Exception as e:
            print(f"[WARN] 删除失败: {p} :: {e}")
            failed += 1

    #print(f"[SUMMARY] deleted={deleted}, failed={failed}")

    # 可选：清空空的 *.files 目录的父目录？默认不动（保持安全）
    if not args.keep_empty_dirs:
        pass


if __name__ == "__main__":
    main()