#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Representative sampling script for Juliet-C binaries with stripped symbols.
Input: features_xxx.json (contains meta + items).
Output includes only:
  - selected: chosen sample list (id + path + file_name)
  - coverage: coverage metrics (mean/max distance/similarity, etc.)
Also renders a 3D embedding visualization where red = selected samples and blue = unselected samples.

Production-ready approach:
1) Use only the entry-reachable call subgraph view: call_subgraph.internal_funcs / internal_edges / import_edges.
    Skip import_api_list (the import table may contain dead APIs).
2) Fuse structural features (call graph topology, counts of paths / min/max/avg path length, function size stats)
    with semantic features (actual API call counts, disassembly token n-grams) to form feature vectors.
3) Apply rooted WL (Weisfeiler-Lehman) graph hashing to perform deduplicating clustering on templated samples
    so near-equivalent templates fall into the same cluster.
4) Run weighted farthest-point greedy selection at the cluster level to balance representativeness (large clusters)
    and diversity (cluster-to-cluster distance).
5) Within each chosen cluster, pick the medoid (cluster-center sample) as the final representative to avoid outliers.
6) Use PCA to compress all sample features to 3D and plot a scatter: representatives in red, others in blue.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import re
import sys
from typing import Dict, List, Tuple, Any, Optional

import numpy as np
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D  # noqa: F401 register the 3D projection


REG_RE = re.compile(
    r'^(r(1[0-5]|[0-9])|e?(ax|bx|cx|dx|si|di|bp|sp)|[abcd][lh]|[sd]il|[sb]pl|r(ip)|xmm\d+|ymm\d+|zmm\d+|mm\d+|st\(\d+\))$',
    re.IGNORECASE,
)

RET_MNEMS = {"ret", "retn", "retf"}
CALL_MNEMS = {"call"}
CMP_MNEMS = {"cmp"}
TEST_MNEMS = {"test"}
NOP_MNEMS = {"nop"}
SETCC_PREFIX = "set"
CMOV_PREFIX = "cmov"

# Juliet-C / libc / POSIX / runtime API role categories (extend as needed)
API_CATS = {
    # memory copy/move/cmp/set
    "memcpy": "mem_copy",
    "memmove": "mem_copy",
    "bcopy": "mem_copy",
    "wmemcpy": "mem_copy",
    "memcmp": "mem_cmp",
    "bcmp": "mem_cmp",
    "memset": "mem_set",
    "bzero": "mem_set",

    # string copy/concat
    "strcpy": "str_copy",
    "strncpy": "str_copy",
    "wcscpy": "str_copy",
    "wcsncpy": "str_copy",
    "strcpy_s": "str_copy",
    "strcat": "str_cat",
    "strncat": "str_cat",
    "wcscat": "str_cat",
    "wcsncat": "str_cat",
    "strcat_s": "str_cat",

    # string length
    "strlen": "str_len",
    "strnlen": "str_len",
    "wcslen": "str_len",

    # string compare
    "strcmp": "str_cmp",
    "strncmp": "str_cmp",
    "strcasecmp": "str_cmp",
    "strncasecmp": "str_cmp",
    "wcscmp": "str_cmp",
    "wcsncmp": "str_cmp",

    # string search
    "strchr": "str_search",
    "strrchr": "str_search",
    "strstr": "str_search",
    "strpbrk": "str_search",
    "wcschr": "str_search",
    "wcsrchr": "str_search",
    "wcsstr": "str_search",

    # formatted output (writes into strings)
    "sprintf": "fmt_write",
    "snprintf": "fmt_write",
    "vsprintf": "fmt_write",
    "vsnprintf": "fmt_write",
    "swprintf": "fmt_write",
    "vswprintf": "fmt_write",

    # console/file output
    "printf": "output",
    "wprintf": "output",
    "vprintf": "output",
    "vwprintf": "output",
    "fprintf": "output",
    "fwprintf": "output",
    "vfprintf": "output",
    "vfwprintf": "output",
    "puts": "output",
    "fputs": "output",
    "putchar": "output",
    "fputc": "output",
    "perror": "output",

    # input (console / stdin / file / network, etc.)
    "fgets": "input",
    "gets": "input",
    "getline": "input",
    "getdelim": "input",
    "scanf": "input",
    "wscanf": "input",
    "sscanf": "input",
    "swscanf": "input",
    "fscanf": "input",
    "fwscanf": "input",
    "__isoc99_sscanf": "input",
    "__isoc99_swscanf": "input",
    "fread": "input",
    "read": "input",
    "recv": "net_input",
    "recvfrom": "net_input",

    # file write
    "fwrite": "file_write",
    "write": "file_write",

    # file operations
    "fopen": "file_open",
    "freopen": "file_open",
    "fdopen": "file_open",
    "fclose": "file_close",
    "open": "file_open",
    "close": "file_close",
    "fseek": "file_seek",
    "ftell": "file_seek",
    "rewind": "file_seek",
    "remove": "file_remove",
    "unlink": "file_remove",
    "rename": "file_rename",
    "tmpnam": "tmp_file",
    "tmpfile": "tmp_file",
    "mktemp": "tmp_file",

    # path / directory / permission helpers
    "chdir": "path",
    "mkdir": "path",
    "rmdir": "path",
    "access": "path",
    "stat": "path",
    "lstat": "path",
    "fstat": "path",

    # networking APIs (Linux / POSIX)
    "socket": "net",
    "bind": "net",
    "listen": "net",
    "accept": "net",
    "connect": "net",
    "send": "net",
    "sendto": "net",
    "shutdown": "net",
    "htons": "net_conv",
    "htonl": "net_conv",
    "ntohs": "net_conv",
    "ntohl": "net_conv",
    "inet_addr": "net_conv",
    "inet_pton": "net_conv",
    "gethostbyname": "net_dns",
    "gethostbyaddr": "net_dns",
    "getaddrinfo": "net_dns",
    "freeaddrinfo": "net_dns",

    # process / command execution
    "system": "process",
    "execl": "process",
    "execlp": "process",
    "execle": "process",
    "execv": "process",
    "execvp": "process",
    "execve": "process",
    "popen": "process",
    "fork": "process",
    "exit": "exit",
    "_exit": "exit",
    "abort": "exit",

    # environment variables
    "getenv": "env",
    "putenv": "env",
    "setenv": "env",
    "unsetenv": "env",

    # memory allocation
    "malloc": "alloc",
    "calloc": "alloc",
    "realloc": "alloc",
    "free": "free",
    "_Znwm": "alloc",   # operator new(unsigned long)
    "_Znam": "alloc",   # operator new[](unsigned long)
    "_ZdlPv": "free",   # operator delete(void*)
    "_ZdaPv": "free",   # operator delete[](void*)
    "_ZdlPvm": "free",  # operator delete(void*, unsigned long)

    # time / randomness
    "time": "time",
    "localtime": "time",
    "gmtime": "time",
    "mktime": "time",
    "ctime": "time",
    "clock": "time",
    "srand": "rand",
    "rand": "rand",
    "random": "rand",
    "srandom": "rand",

    # numeric conversion
    "atoi": "convert",
    "atol": "convert",
    "atoll": "convert",
    "strtol": "convert",
    "strtoul": "convert",
    "strtoll": "convert",
    "strtoull": "convert",
    "wcstol": "convert",
    "wcstoul": "convert",

    # cryptography / hashing (Juliet crypto CWEs)
    "MD5_Init": "crypto_hash",
    "MD5_Update": "crypto_hash",
    "MD5_Final": "crypto_hash",
    "SHA1_Init": "crypto_hash",
    "SHA1_Update": "crypto_hash",
    "SHA1_Final": "crypto_hash",
    "SHA256_Init": "crypto_hash",
    "SHA256_Update": "crypto_hash",
    "SHA256_Final": "crypto_hash",

    # stack protection / exception handling
    "__stack_chk_fail": "stack_protect",
    "_Unwind_Resume": "except",
}


def norm_api(name: str) -> str:
    """
    Normalize API names (align with func_call_dict / call_subgraph.used_imports):
    - Collapse multiple leading '_' that may appear in IDA/objdump (e.g., ___stack_chk_fail -> __stack_chk_fail).
    - Preserve C++ Itanium ABI mangled names (_Z...).
    - Preserve double-underscore runtime symbols (__xxx).
    - Remove a single leading '_' in other cases (common in IDA/objdump output).
    """
    if not name:
        return ""
    if name.startswith("___") and not name.startswith("_Z"):
        while name.startswith("___"):
            name = name[1:]

    if name.startswith("_Z"):
        return name
    if name.startswith("__"):
        return name
    if name.startswith("_") and not name.startswith("_Z"):
        return name[1:]
    return name


def api_cat(name: str) -> str:
    return API_CATS.get(norm_api(name), "other")


def bucket_log2(x: float) -> int:
    """
    log2 bucketing: 0->0, 1->1, [2,3]->2, [4,7]->3 ...
    """
    if x <= 0:
        return 0
    return int(math.floor(math.log2(x))) + 1


def hash_feature(feat: str, dim: int) -> Tuple[int, float]:
    """
    Hashing trick: map any string feature into [0, dim).
    Use one hash bit to pick the sign to reduce collision bias.
    """
    h = hashlib.md5(feat.encode("utf-8")).digest()
    idx = int.from_bytes(h[:4], "little", signed=False) % dim
    sign = 1.0 if (h[4] & 1) == 0 else -1.0
    return idx, sign


def operand_type(op: str) -> str:
    op = op.strip()
    if not op:
        return "NONE"
    if "[" in op or "]" in op:
        return "MEM"
    if ":" in op and re.match(r"^[a-z]{1,3}:", op, re.IGNORECASE):
        return "MEM"
    if re.match(r"^-?(0x[0-9a-fA-F]+|\d+)$", op):
        return "IMM"
    if REG_RE.match(op):
        return "REG"
    if re.match(r"^(loc_|sub_|off_|a[A-Za-z]|dword_|qword_|byte_|word_)", op):
        return "SYM"
    return "OTHER"


def parse_insn_tokens(disasm: str, used_imports: Optional[set] = None, internal_funcs: Optional[set] = None) -> List[str]:
    """
    Parse a disassembly string into a token sequence (avoid relying on addresses/function names):
    - Strip comments, labels, and pseudo instructions
    - Normalize instructions as "mnemonic + operand types" (REG/MEM/IMM/SYM/OTHER)
    - For call instructions differentiate CALL_API:xxx / CALL_INT / CALL_IND / CALL_EXT
    - For jxx instructions normalize to JCC/JMP/JX
    """
    if used_imports is None:
        used_imports = set()
    if internal_funcs is None:
        internal_funcs = set()

    tokens: List[str] = []
    for raw_line in disasm.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if ";" in line:
            line = line.split(";", 1)[0].strip()
        if not line:
            continue
        if line.endswith(":"):
            continue
        if line.startswith("."):
            continue

        parts = line.split()
        if not parts:
            continue
        mnem = parts[0].lower()

        if mnem.startswith(("loc_", "sub_", "off_")):
            continue

        if mnem in NOP_MNEMS:
            continue

        if mnem in RET_MNEMS:
            tokens.append("RET")
            continue

        if mnem in CALL_MNEMS:
            operand = " ".join(parts[1:]).strip()
            if not operand:
                tokens.append("CALL")
                continue
            op0 = operand.split(",")[0].strip()
            op0 = op0.replace("short", "").strip()
            op0 = op0.replace("near ptr", "").replace("far ptr", "").strip()

            if operand_type(op0) in ("REG", "MEM"):
                tokens.append("CALL_IND")
                continue

            callee = op0
            callee_norm = norm_api(callee)

            if callee_norm in used_imports or callee in used_imports:
                tokens.append(f"CALL_API:{callee_norm}")
            elif callee in internal_funcs:
                tokens.append("CALL_INT")
            elif callee.startswith("sub_") or callee == "main":
                tokens.append("CALL_INT")
            else:
                tokens.append("CALL_EXT")
            continue

        if mnem.startswith("j"):
            if mnem in ("jmp", "jmpq", "jmpl"):
                tokens.append("JMP")
            elif mnem in ("jrcxz", "jecxz", "jcxz"):
                tokens.append("JX")
            else:
                tokens.append("JCC")
            continue

        if mnem.startswith(SETCC_PREFIX):
            tokens.append("SETCC")
            continue

        if mnem.startswith(CMOV_PREFIX):
            tokens.append("CMOVCC")
            continue

        if mnem in CMP_MNEMS:
            ops = " ".join(parts[1:]).split(",")
            if len(ops) >= 2:
                tokens.append(f"CMP_{operand_type(ops[0])}_{operand_type(ops[1])}")
            else:
                tokens.append("CMP")
            continue

        if mnem in TEST_MNEMS:
            ops = " ".join(parts[1:]).split(",")
            if len(ops) >= 2:
                tokens.append(f"TEST_{operand_type(ops[0])}_{operand_type(ops[1])}")
            else:
                tokens.append("TEST")
            continue

        if mnem in (
            "mov", "movzx", "movsx", "lea",
            "add", "sub", "imul", "mul", "idiv", "div",
            "and", "or", "xor", "shl", "shr", "sar", "sal",
            "inc", "dec", "neg", "not", "cmpxchg", "xchg",
        ):
            ops = " ".join(parts[1:]).split(",")
            if len(ops) >= 2:
                tokens.append(f"{mnem.upper()}_{operand_type(ops[0])}_{operand_type(ops[1])}")
            else:
                tokens.append(mnem.upper())
            continue

        if mnem in ("syscall", "int", "int3", "cpuid", "rdtsc", "hlt"):
            tokens.append(mnem.upper())
            continue

        tokens.append(mnem.upper())

    return tokens


def build_internal_adj(item: Dict[str, Any]) -> Dict[str, List[str]]:
    cs = item.get("call_subgraph", {}) or {}
    internal_funcs = set(cs.get("internal_funcs") or [])
    if internal_funcs:
        adj = {f: [] for f in internal_funcs}
        internal_edges = cs.get("internal_edges", {}) or {}
        for src, lst in internal_edges.items():
            if src not in adj:
                continue
            for e in lst or []:
                dst = e.get("dst")
                if dst in internal_funcs:
                    adj[src].append(dst)
        return adj

    rc = item.get("reachable_callgraph", {}) or {}
    funcs = set(rc.get("reachable_funcs") or [])
    edges = rc.get("edges", {}) or {}
    adj = {f: [] for f in funcs}
    for src, dsts in edges.items():
        if src not in adj:
            continue
        for dst in dsts or []:
            if dst in funcs:
                adj[src].append(dst)
    return adj


def tarjan_scc(adj: Dict[str, List[str]]) -> List[List[str]]:
    sys.setrecursionlimit(1000000)

    index = 0
    stack: List[str] = []
    onstack = set()
    indices: Dict[str, int] = {}
    lowlink: Dict[str, int] = {}
    sccs: List[List[str]] = []

    def strongconnect(v: str) -> None:
        nonlocal index
        indices[v] = index
        lowlink[v] = index
        index += 1
        stack.append(v)
        onstack.add(v)

        for w in adj.get(v, []):
            if w not in indices:
                strongconnect(w)
                lowlink[v] = min(lowlink[v], lowlink[w])
            elif w in onstack:
                lowlink[v] = min(lowlink[v], indices[w])

        if lowlink[v] == indices[v]:
            comp: List[str] = []
            while True:
                w = stack.pop()
                onstack.remove(w)
                comp.append(w)
                if w == v:
                    break
            sccs.append(comp)

    for v in adj.keys():
        if v not in indices:
            strongconnect(v)

    return sccs


def condense_graph(adj: Dict[str, List[str]]) -> Tuple[List[List[str]], Dict[str, int], Dict[int, List[int]]]:
    sccs = tarjan_scc(adj)
    comp_id: Dict[str, int] = {}
    for i, comp in enumerate(sccs):
        for v in comp:
            comp_id[v] = i

    cadj: Dict[int, set] = {i: set() for i in range(len(sccs))}
    for v, outs in adj.items():
        for w in outs:
            ci = comp_id[v]
            cj = comp_id[w]
            if ci != cj:
                cadj[ci].add(cj)

    cadj_list: Dict[int, List[int]] = {k: sorted(list(v)) for k, v in cadj.items()}
    return sccs, comp_id, cadj_list


def dag_metrics(adj: Dict[str, List[str]], entry: str) -> Dict[str, float]:
    n_nodes = len(adj)
    n_edges = sum(len(v) for v in adj.values())
    if n_nodes == 0:
        return {
            "n_nodes": 0, "n_edges": 0,
            "path_count": 0, "min_len": 0, "max_len": 0, "avg_len": 0.0,
            "n_leaves": 0, "max_outdeg": 0, "avg_outdeg": 0.0,
        }

    if entry not in adj:
        entry = next(iter(adj.keys()))

    sccs, comp_id, cadj = condense_graph(adj)
    entry_c = comp_id.get(entry, 0)

    stack = [entry_c]
    reachable = {entry_c}
    while stack:
        c = stack.pop()
        for nxt in cadj.get(c, []):
            if nxt not in reachable:
                reachable.add(nxt)
                stack.append(nxt)

    radj: Dict[int, List[int]] = {c: [n for n in cadj.get(c, []) if n in reachable] for c in reachable}

    indeg = {c: 0 for c in reachable}
    for c, outs in radj.items():
        for o in outs:
            indeg[o] += 1
    q = sorted([c for c, d in indeg.items() if d == 0])
    topo: List[int] = []
    while q:
        c = q.pop(0)
        topo.append(c)
        for o in radj.get(c, []):
            indeg[o] -= 1
            if indeg[o] == 0:
                q.append(o)
                q.sort()

    dp_count: Dict[int, int] = {}
    dp_min: Dict[int, int] = {}
    dp_max: Dict[int, int] = {}
    dp_sum: Dict[int, int] = {}
    for c in reversed(topo):
        outs = radj.get(c, [])
        if not outs:
            dp_count[c] = 1
            dp_min[c] = 1
            dp_max[c] = 1
            dp_sum[c] = 1
        else:
            dp_count[c] = sum(dp_count[o] for o in outs)
            dp_min[c] = 1 + min(dp_min[o] for o in outs)
            dp_max[c] = 1 + max(dp_max[o] for o in outs)
            dp_sum[c] = sum(dp_sum[o] + dp_count[o] for o in outs)

    path_count = float(dp_count.get(entry_c, 1))
    min_len = float(dp_min.get(entry_c, 1))
    max_len = float(dp_max.get(entry_c, 1))
    avg_len = float(dp_sum.get(entry_c, 1)) / path_count if path_count else 0.0

    n_leaves = sum(1 for c in reachable if len(radj.get(c, [])) == 0)
    outdeg_vals = [len(adj.get(v, [])) for v in adj]
    max_outdeg = max(outdeg_vals) if outdeg_vals else 0
    avg_outdeg = float(sum(outdeg_vals)) / float(len(outdeg_vals)) if outdeg_vals else 0.0

    return {
        "n_nodes": float(n_nodes),
        "n_edges": float(n_edges),
        "path_count": path_count,
        "min_len": min_len,
        "max_len": max_len,
        "avg_len": avg_len,
        "n_leaves": float(n_leaves),
        "max_outdeg": float(max_outdeg),
        "avg_outdeg": avg_outdeg,
    }


def get_func_sizes(item: Dict[str, Any]) -> Dict[str, int]:
    size_map: Dict[str, int] = {}
    for f in item.get("internal_func_list", []) or []:
        name = f.get("name")
        sz = f.get("size")
        if not name or sz is None:
            continue
        try:
            if isinstance(sz, str) and sz.startswith("0x"):
                size_map[name] = int(sz, 16)
            else:
                size_map[name] = int(sz)
        except Exception:
            continue
    return size_map


def get_import_call_counts(item: Dict[str, Any]) -> collections.Counter:
    counts = collections.Counter()
    fcd = item.get("func_call_dict", {}) or {}
    for _func, calls in fcd.items():
        for c in calls or []:
            if c.get("cat") == "IMPORT_API":
                name = norm_api(c.get("name", ""))
                if name:
                    counts[name] += 1

    if not counts:
        cs = item.get("call_subgraph", {}) or {}
        imp_edges = cs.get("import_edges", {}) or {}
        for _func, lst in imp_edges.items():
            for e in lst or []:
                name = norm_api(e.get("dst", ""))
                if name:
                    counts[name] += 1
    return counts


def get_used_imports_set(item: Dict[str, Any]) -> set:
    cs = item.get("call_subgraph", {}) or {}
    used = cs.get("used_imports", []) or []
    return set(norm_api(x) for x in used if x)


def wl_graph_signature(
    adj: Dict[str, List[str]],
    entry: str,
    node_labels: Dict[str, str],
    h: int = 2,
) -> str:
    labels = {v: node_labels.get(v, "") for v in adj}
    if entry in labels:
        labels[entry] = "ROOT|" + labels[entry]

    in_nei = {v: [] for v in adj}
    for u, outs in adj.items():
        for v in outs:
            if v in in_nei:
                in_nei[v].append(u)

    for _ in range(h):
        new_labels: Dict[str, str] = {}
        for v in adj:
            out_lbls = sorted(labels.get(n, "") for n in adj.get(v, []))
            in_lbls = sorted(labels.get(n, "") for n in in_nei.get(v, []))
            s = labels.get(v, "") + "|OUT:" + ",".join(out_lbls) + "|IN:" + ",".join(in_lbls)
            hv = hashlib.md5(s.encode("utf-8")).hexdigest()[:12]
            new_labels[v] = hv
        labels = new_labels

    multiset = sorted(labels.values())
    gsig = hashlib.md5(("|".join(multiset)).encode("utf-8")).hexdigest()[:16]
    return gsig


def extract_feature_counter(
    item: Dict[str, Any],
    dim: int,
    wl_iter: int,
) -> Tuple[collections.Counter, str, Dict[str, float]]:
    meta = item.get("meta", {}) or {}
    bits = meta.get("elf_bits", 0)
    if isinstance(bits, str) and bits.isdigit():
        bits = int(bits)
    bits = int(bits) if bits in (32, 64) else 0

    entry = (item.get("entry", {}) or {}).get("entry_func") \
            or (item.get("reachable_callgraph", {}) or {}).get("entry") \
            or "main"

    adj = build_internal_adj(item)

    if entry in adj:
        stack = [entry]
        reachable = {entry}
        while stack:
            v = stack.pop()
            for w in adj.get(v, []):
                if w not in reachable:
                    reachable.add(w)
                    stack.append(w)
        adj = {v: [w for w in outs if w in reachable] for v, outs in adj.items() if v in reachable}

    metrics = dag_metrics(adj, entry)
    size_map = get_func_sizes(item)
    internal_funcs = list(adj.keys())
    internal_set = set(internal_funcs)

    sizes = [size_map.get(f) for f in internal_funcs if size_map.get(f) is not None]
    sizes = [s for s in sizes if isinstance(s, int) and s > 0]
    func_count = len(internal_funcs)
    avg_size = float(sum(sizes)) / float(len(sizes)) if sizes else 0.0
    max_size = float(max(sizes)) if sizes else 0.0
    min_size = float(min(sizes)) if sizes else 0.0

    import_counts = get_import_call_counts(item)
    used_imports = set(import_counts.keys()) if import_counts else get_used_imports_set(item)

    disasm_dict = item.get("disasm_dict", {}) or {}
    all_tokens: List[str] = []
    per_func_sig: Dict[str, str] = {}
    for f in internal_funcs:
        dis_entry = disasm_dict.get(f, {}) if isinstance(disasm_dict.get(f, {}), dict) else {}
        dis = dis_entry.get("disasm", "") or ""
        toks = parse_insn_tokens(dis, used_imports, internal_funcs=internal_set)
        all_tokens.extend(toks + ["FUNC_END"])

        hist = collections.Counter(t.split(":", 1)[0] for t in toks)
        sig_str = ";".join(f"{k}:{hist[k]}" for k in sorted(hist.keys()))
        per_func_sig[f] = hashlib.md5(sig_str.encode("utf-8")).hexdigest()[:8]

    cs = item.get("call_subgraph", {}) or {}
    imp_edges = cs.get("import_edges", {}) or {}
    node_labels: Dict[str, str] = {}
    for f in internal_funcs:
        size_bin = bucket_log2(float(size_map.get(f, 0)))
        out_deg = float(len(adj.get(f, [])))
        api_deg = float(len(imp_edges.get(f, []) or []))
        node_labels[f] = f"S{size_bin}|O{bucket_log2(out_deg)}|A{bucket_log2(api_deg)}|I{per_func_sig.get(f,'0')}"
    wl_sig = wl_graph_signature(adj, entry, node_labels, h=wl_iter)
    cluster_key = f"B{bits}|WL{wl_sig}"

    fc: collections.Counter = collections.Counter()

    fc[f"BITS:{bits}"] += 1
    fc[f"WL:{wl_sig}"] += 1

    fc[f"CG_NODES_L2:{bucket_log2(metrics['n_nodes'])}"] += 1
    fc[f"CG_EDGES_L2:{bucket_log2(metrics['n_edges'])}"] += 1
    fc[f"CG_LEAVES_L2:{bucket_log2(metrics['n_leaves'])}"] += 1
    fc[f"CG_MAX_OUT_L2:{bucket_log2(metrics['max_outdeg'])}"] += 1
    fc[f"CG_AVG_OUT_L2:{bucket_log2(metrics['avg_outdeg'] + 1e-9)}"] += 1

    fc[f"PATH_COUNT_L2:{bucket_log2(metrics['path_count'])}"] += 1
    fc[f"PATH_MIN_LEN:{int(round(metrics['min_len']))}"] += 1
    fc[f"PATH_MAX_LEN:{int(round(metrics['max_len']))}"] += 1
    fc[f"PATH_AVG_LEN_L2:{bucket_log2(metrics['avg_len'] + 1e-9)}"] += 1

    fc[f"FUNC_CNT_L2:{bucket_log2(float(func_count))}"] += 1
    fc[f"FUNC_AVG_SZ_L2:{bucket_log2(avg_size)}"] += 1
    fc[f"FUNC_MAX_SZ_L2:{bucket_log2(max_size)}"] += 1
    fc[f"FUNC_MIN_SZ_L2:{bucket_log2(min_size)}"] += 1
    for s in sizes:
        fc[f"FS_BIN:{bucket_log2(float(s))}"] += 1

    total_import_calls = float(sum(import_counts.values()))
    fc[f"API_TOTAL_CALLS_L2:{bucket_log2(total_import_calls)}"] += 1
    fc[f"API_UNIQUE_L2:{bucket_log2(float(len(import_counts)))}"] += 1
    for api, cnt in import_counts.items():
        fc[f"API:{api}"] += float(cnt) * 2.0
        fc[f"API_CAT:{api_cat(api)}"] += float(cnt)

    for t in all_tokens:
        if t == "FUNC_END":
            continue
        base = t.split(":", 1)[0]
        fc[f"INSN1:{base}"] += 1.0

    for i in range(len(all_tokens) - 1):
        a, b = all_tokens[i], all_tokens[i + 1]
        if a == "FUNC_END" or b == "FUNC_END":
            continue
        fc[f"INSN2:{a}|{b}"] += 1.0

    return fc, cluster_key, metrics


def counters_to_matrix(counters: List[collections.Counter], dim: int) -> Tuple[np.ndarray, np.ndarray]:
    n = len(counters)
    X = np.zeros((n, dim), dtype=np.float32)
    df = np.zeros(dim, dtype=np.int32)

    for i, fc in enumerate(counters):
        used_idx = set()
        for feat, val in fc.items():
            idx, sign = hash_feature(feat, dim)
            X[i, idx] += sign * float(val)
            used_idx.add(idx)
        for idx in used_idx:
            df[idx] += 1
    return X, df


def apply_idf_and_normalize(X: np.ndarray, df: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    n = X.shape[0]
    idf = np.log((1.0 + n) / (1.0 + df.astype(np.float32))) + 1.0
    X = X * idf.astype(np.float32)
    norms = np.linalg.norm(X, axis=1)
    norms[norms == 0] = 1.0
    Xn = X / norms[:, None]
    return Xn, idf.astype(np.float32)


def weighted_farthest_first(cluster_vecs: np.ndarray, weights: np.ndarray, k: int, beta: float = 0.5) -> List[int]:
    m = cluster_vecs.shape[0]
    if k >= m:
        return list(range(m))

    start = int(np.argmax(weights))
    selected = [start]

    best_sim = cluster_vecs @ cluster_vecs[start].T
    best_sim[start] = 1.0

    for _ in range(1, k):
        dist = 1.0 - best_sim
        score = dist * (np.log1p(weights).astype(np.float32) ** beta)
        score[selected] = -1e9
        j = int(np.argmax(score))
        selected.append(j)
        sim_new = cluster_vecs @ cluster_vecs[j].T
        best_sim = np.maximum(best_sim, sim_new)

    return selected


def choose_representative_in_cluster(member_indices: List[int], Xn: np.ndarray) -> int:
    sub = Xn[member_indices]
    centroid = sub.mean(axis=0)
    norm = np.linalg.norm(centroid)
    if norm == 0:
        return member_indices[0]
    centroid = centroid / norm
    sims = sub @ centroid
    return member_indices[int(np.argmax(sims))]


def allocate_k_by_bits(bits_list: List[int], k: int) -> Dict[int, int]:
    counts = collections.Counter(bits_list)
    groups = [b for b in (32, 64) if counts.get(b, 0) > 0]
    if not groups:
        return {0: k}

    total = sum(counts[b] for b in groups)
    alloc = {}
    for b in groups:
        alloc[b] = int(round(k * counts[b] / total))
    for b in groups:
        if alloc[b] == 0:
            alloc[b] = 1
    s = sum(alloc.values())
    while s > k:
        b = max(groups, key=lambda x: alloc[x])
        if alloc[b] > 1:
            alloc[b] -= 1
            s -= 1
        else:
            break
    while s < k:
        b = max(groups, key=lambda x: counts[x] / (alloc[x] + 1e-9))
        alloc[b] += 1
        s += 1
    return alloc


def select_for_group(
    group_indices: List[int],
    cluster_keys: List[str],
    Xn: np.ndarray,
    k: int,
) -> List[int]:
    if k <= 0 or not group_indices:
        return []
    if k >= len(group_indices):
        return list(group_indices)

    clusters: Dict[str, List[int]] = collections.defaultdict(list)
    for i in group_indices:
        clusters[cluster_keys[i]].append(i)

    cluster_ids = sorted(clusters.keys())
    weights = np.array([len(clusters[c]) for c in cluster_ids], dtype=np.float32)

    cvecs = []
    for cid in cluster_ids:
        v = Xn[clusters[cid]].mean(axis=0)
        n = np.linalg.norm(v)
        cvecs.append(v if n == 0 else v / n)
    cvecs = np.vstack(cvecs).astype(np.float32)

    m = len(cluster_ids)
    selected_indices: List[int] = []

    if m <= k:
        for cid in cluster_ids:
            rep = choose_representative_in_cluster(clusters[cid], Xn)
            selected_indices.append(rep)
        remaining = k - len(selected_indices)
        if remaining > 0:
            big_clusters = sorted(cluster_ids, key=lambda c: len(clusters[c]), reverse=True)
            ptr = 0
            while remaining > 0 and ptr < len(big_clusters):
                cid = big_clusters[ptr]
                members = clusters[cid]
                chosen_in_cluster = [i for i in selected_indices if i in set(members)]
                if len(members) > len(chosen_in_cluster):
                    cand = [i for i in members if i not in set(chosen_in_cluster)]
                    if not chosen_in_cluster:
                        pick = cand[0]
                    else:
                        chosen_vecs = Xn[chosen_in_cluster]
                        sims = Xn[cand] @ chosen_vecs.T
                        best_sim = sims.max(axis=1)
                        pick = cand[int(np.argmin(best_sim))]
                    selected_indices.append(pick)
                    remaining -= 1
                ptr = (ptr + 1) % len(big_clusters)
        return selected_indices[:k]

    sel_cidx = weighted_farthest_first(cvecs, weights, k)
    sel_cluster_ids = [cluster_ids[i] for i in sel_cidx]
    for cid in sel_cluster_ids:
        rep = choose_representative_in_cluster(clusters[cid], Xn)
        selected_indices.append(rep)

    return selected_indices


def compute_pca_3d(Xn: np.ndarray) -> np.ndarray:
    """
    Use PCA to obtain a 3D embedding for visualization: input Xn (N x D), output (N x 3).
    """
    Xc = Xn - Xn.mean(axis=0, keepdims=True)
    U, S, Vt = np.linalg.svd(Xc, full_matrices=False)
    W = Vt[:3].T  # D x 3
    X3 = Xc @ W    # N x 3
    return X3.astype(np.float32)


def plot_embedding_3d(X3: np.ndarray, selected_indices: List[int], out_path: str) -> None:
    """
    Draw a 3D scatter plot:
    - red: selected samples
    - blue: unselected samples
    """
    N = X3.shape[0]
    mask = np.zeros(N, dtype=bool)
    for idx in selected_indices:
        if 0 <= idx < N:
            mask[idx] = True

    X_sel = X3[mask]
    X_rest = X3[~mask]

    fig = plt.figure(figsize=(8, 6))
    ax = fig.add_subplot(111, projection="3d")

    if len(X_rest) > 0:
        ax.scatter(
            X_rest[:, 0],
            X_rest[:, 1],
            X_rest[:, 2],
            c="blue",
            s=10,
            alpha=0.35,
            label="not selected",
        )
    if len(X_sel) > 0:
        ax.scatter(
            X_sel[:, 0],
            X_sel[:, 1],
            X_sel[:, 2],
            c="red",
            s=25,
            alpha=0.9,
            label="selected",
        )

    ax.set_xlabel("PC1")
    ax.set_ylabel("PC2")
    ax.set_zlabel("PC3")
    ax.legend(loc="best")
    ax.set_title("3D PCA embedding of samples")

    fig.tight_layout()
    fig.savefig(out_path, dpi=200, bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("input_json", help="Input feature JSON (same format as provided previously)")
    ap.add_argument("output_json", help="Sampling result JSON (contains selected + coverage)")
    ap.add_argument("-k", "--k", type=int, default=100, help="Sample size (default=100)")
    ap.add_argument("--dim", type=int, default=4096, help="Hashing vector dimension (default=4096)")
    ap.add_argument("--wl-iter", type=int, default=2, help="WL iteration count (default=2)")
    ap.add_argument("--seed", type=int, default=0, help="Random seed (pipeline is mostly deterministic)")
    ap.add_argument("--no-bits-stratify", action="store_true", help="Skip elf_bits stratification and select k samples globally")
    ap.add_argument(
        "--plot-path",
        type=str,
        default=None,
        help="3D embedding image output path (default=output_json basename + .png)",
    )
    args = ap.parse_args()

    if args.k <= 0:
        raise SystemExit("k must be a positive integer")

    with open(args.input_json, "r") as f:
        data = json.load(f)

    items_dict = data.get("items", {}) or {}

    item_keys = sorted(items_dict.keys(), key=lambda x: (len(str(x)), str(x)))
    items = [items_dict[k] for k in item_keys]

    counters: List[collections.Counter] = []
    cluster_keys: List[str] = []
    bits_list: List[int] = []

    for it in items:
        fc, ck, _met = extract_feature_counter(it, dim=args.dim, wl_iter=args.wl_iter)
        counters.append(fc)
        cluster_keys.append(ck)
        b = (it.get("meta", {}) or {}).get("elf_bits", 0)
        if isinstance(b, str) and b.isdigit():
            b = int(b)
        b = int(b) if b in (32, 64) else 0
        bits_list.append(b)

    X, df = counters_to_matrix(counters, dim=args.dim)
    Xn, _idf = apply_idf_and_normalize(X, df)

    N = len(items)
    k = min(args.k, N)
    selected_indices: List[int] = []

    if args.no_bits_stratify:
        all_idx = list(range(N))
        selected_indices = select_for_group(all_idx, cluster_keys, Xn, k)
    else:
        alloc = allocate_k_by_bits(bits_list, k)
        for b, kb in sorted(alloc.items()):
            grp_idx = [i for i in range(N) if bits_list[i] == b] if b in (32, 64) else list(range(N))
            selected_indices.extend(select_for_group(grp_idx, cluster_keys, Xn, kb))

        selected_indices = list(dict.fromkeys(selected_indices))[:k]
        if len(selected_indices) < k:
            remaining = [i for i in range(N) if i not in set(selected_indices)]
            if remaining:
                sel_vecs = Xn[selected_indices]
                sims = Xn[remaining] @ sel_vecs.T
                best_sim = sims.max(axis=1)
                order = np.argsort(best_sim)  # smaller value -> farther from current set
                for idx in order:
                    selected_indices.append(remaining[int(idx)])
                    if len(selected_indices) >= k:
                        break

    # Coverage statistics (values go to JSON, visual overview uses 3D projection)
    sel_vecs = Xn[selected_indices]
    sims = Xn @ sel_vecs.T
    best_sim = sims.max(axis=1)
    dists = 1.0 - best_sim
    cov = {
        "mean_dist": float(np.mean(dists)),
        "p50_dist": float(np.percentile(dists, 50)),
        "p90_dist": float(np.percentile(dists, 90)),
        "max_dist": float(np.max(dists)),
        "mean_sim": float(np.mean(best_sim)),
        "p10_sim": float(np.percentile(best_sim, 10)),
    }

    # Selected list contains id + path + file_name
    selected = []
    for idx in selected_indices:
        key = item_keys[idx]
        it = items_dict[key]
        m = it.get("meta", {}) or {}
        selected.append({
            "id": key,
            "path": m.get("path", ""),
            "file_name": m.get("file_name", ""),
        })

    out = {
        "selected": selected,
        "coverage": cov,
    }

    with open(args.output_json, "w") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    print(f"[+] done. selected={len(selected)}/{N} -> {args.output_json}")
    print("[+] coverage:", json.dumps(cov, indent=2))

    # 3D visualization
    if args.plot_path is not None:
        plot_path = args.plot_path
    else:
        if "." in args.output_json:
            plot_path = args.output_json.rsplit(".", 1)[0] + ".png"
        else:
            plot_path = args.output_json + ".png"

    X3 = compute_pca_3d(Xn)
    plot_embedding_3d(X3, selected_indices, plot_path)
    print(f"[+] 3D embedding plot saved to {plot_path}")


if __name__ == "__main__":
    main()
