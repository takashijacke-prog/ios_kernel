#!/usr/bin/env python3
# 结构体成员偏移提取: 对每个 xnu 源码树用 clang -fdump-record-layouts 计算 arm64 内核结构体布局
# - 机器头符号链接: bsd/machine->arm, osfmk/machine->arm, libkern/libkern/machine->arm, osfmk/mach/machine->arm
# - config options: 从 bsd/conf/MASTER* 等提取 options XXX -> -DCONFIG_XXX=1
# - 每个 probe 独立编译，失败不影响其它；解析 dump 输出为 {struct: {member: byte_offset}}
import json, os, re, subprocess, sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(BASE, "xnu_src")
OUT = os.path.join(BASE, "offsets", "structs")

# 每个 probe: (include 列表, 需要声明变量的类型)
PROBES = {
    "proc":     (["sys/proc_internal.h"], ["proc", "pgrp", "session"]),
    "task":     (["kern/task.h"], ["task"]),
    "thread":   (["kern/thread.h", "sys/user.h"], ["thread", "uthread"]),
    "ucred":    (["sys/ucred.h"], ["ucred"]),
    "filedesc": (["sys/filedesc.h"], ["filedesc"]),
    "fileproc": (["sys/file_internal.h"], ["fileproc", "fileglob"]),
    "vnode":    (["sys/vnode_internal.h"], ["vnode"]),
    "pmap":     (["arm/pmap.h"], ["pmap"]),
    "vm_map":   (["vm/vm_map.h"], ["vm_map", "vm_map_entry"]),
    "ipc_port": (["ipc/ipc_port.h"], ["ipc_port"]),
}

DEFINES = ["XNU_KERNEL_PRIVATE", "KERNEL_PRIVATE", "BSD_KERNEL_PRIVATE",
           "MACH_KERNEL_PRIVATE", "KERNEL", "PRIVATE", "__APPLE_API_PRIVATE",
           "__APPLE_API_UNSTABLE",
           "_CLOCK_T"]   # 规避 _clock_t.h 与 kern_types.h 的 clock_t 冲突(同为8字节)

# 某些头仅在函数原型里用到未自带定义的类型(ast_t/u_int 等)，预声明避免报错
PRELUDE = ("typedef unsigned int ast_t;\n"
           "typedef unsigned int u_int;\n"
           "typedef unsigned long u_long;\n"
           "typedef unsigned short u_short;\n"
           "typedef unsigned char u_char;\n")

def cpu_define(tree):
    """proc_reg.h 需要具体 Apple CPU 宏（cache line 定义，全平台 64B 相同）。
    排除 APPLE_ARM64_ARCH_FAMILY 这类家族宏，取 #if/#elif 链中第一个具体 CPU。"""
    for rel in ("osfmk/arm64/proc_reg.h", "osfmk/arm/proc_reg.h"):
        p = os.path.join(tree, rel)
        try:
            txt = open(p, errors="replace").read()
            for m in re.finditer(r"defined\s*\(\s*(\w+)\s*\)", txt):
                name = m.group(1)
                if name.startswith(("APPLE", "VMAPPLE", "BCM")) and name != "APPLE_ARM64_ARCH_FAMILY":
                    return name
        except OSError:
            pass
    return "APPLEFIRESTORM"

def res_include():
    p = subprocess.run(["clang", "-print-resource-dir"], capture_output=True, text=True)
    return os.path.join(p.stdout.strip(), "include")

RES_INC = res_include()

def make_links(tree):
    links = [("bsd/machine", "arm"), ("osfmk/machine", "arm"),
             ("osfmk/mach/machine", "arm"), ("libkern/libkern/machine", "arm"),
             ("pexpert/machine", "arm")]
    for lnk, tgt in links:
        p = os.path.join(tree, lnk)
        if os.path.islink(p) or os.path.exists(p):
            continue
        try:
            os.symlink(tgt, p)
        except OSError:
            pass

# 非生产 profile 选项（debug/sanitizer/coverage 等会改变结构体布局，排除）
NON_PROD = re.compile(r"DEBUG|KASAN|KCOV|UBSAN|TRASH|ASSERT|COUNT_SYSCALLS|ALTERNATE_DEBUGGER|"
                      r"KTRACE|MACH_KDP|GZIP|NONFATAL|IOCOUNT_TRACE|_TRACE|KERNEL_TICKLE|TRAP|"
                      r"DEVELOPMENT|DIAGNOSTIC", re.I)

GROUP_RE = re.compile(r"^#\s+(\w+)\s*=\s*\[([^\]]*)\]")

def _parse_groups(path):
    """解析 MASTER 注释块里的 profile 组: #  NAME = [ items ]
    遇到 #if SOC_IS_* 取 #else 分支（物理设备非虚拟化）"""
    groups, skip = {}, False
    for line in open(path, errors="replace"):
        s = line.strip()
        if re.match(r"#\s*if\s+SOC_IS", s):
            skip = True
            continue
        if re.match(r"#\s*else", s) and skip:
            skip = False
            continue
        if re.match(r"#\s*endif", s):
            skip = False
            continue
        if skip:
            continue
        m = GROUP_RE.match(s)
        if m:
            groups.setdefault(m.group(1), m.group(2).split())
    return groups

def _resolve(groups, start="RELEASE"):
    """从 RELEASE 组展开成叶子 tag 集合"""
    tags, stack, seen = set(), [start], set()
    while stack:
        g = stack.pop()
        if g in seen:
            continue
        seen.add(g)
        for item in groups.get(g, [g]):
            if item in groups:
                stack.append(item)
            else:
                tags.add(item)
    return tags

# 无 arm64/iPhoneOS 组合块的老树(如3789)需补的 iOS 生产 tag
EMBEDDED_EXTRA = {"arm64", "config_embedded", "config_sched_multiq",
                  "config_sched_traditional", "config_sched_deferred_ast", "xsmall"}

def config_options(tree):
    """提取生产内核 arm64 iPhoneOS 的 CONFIG_* 选项集合。
    优先解析 config/MASTER*.iPhoneOS 的 RELEASE profile 组合；无组合块时退化为并集。"""
    cfg = os.path.join(tree, "config")
    cands = [os.path.join(cfg, f) for f in
             ("MASTER.arm64.iPhoneOS", "MASTER.arm64", "MASTER", "MASTER.x86_64")]
    cands = [p for p in cands if os.path.isfile(p)]
    groups, arm64_specific, master_file = {}, False, None
    for p in cands:
        g = _parse_groups(p)
        if "RELEASE" in g:
            groups, master_file = g, p
            arm64_specific = "arm64" in os.path.basename(p)
            break
    if master_file:
        tags = _resolve(groups)
        if not arm64_specific:
            tags |= EMBEDDED_EXTRA
        # 收集 MASTER 系列所有文件里的 options 行（选项分散在 MASTER/MASTER.arm64）
        opt_lines = []
        for p in cands:
            opt_lines += list(open(p, errors="replace"))
        opts = {}
        for line in opt_lines:
            body, _, comment = line.partition("#")
            m = re.match(r"\s*options\s+([A-Za-z0-9_]+)(?:\s*=\s*([0-9]+))?", body)
            if not m or not body.strip().startswith("options"):
                continue
            name, val = m.group(1), m.group(2)
            tagm = re.search(r"<([^>]*)>", comment)
            if tagm:
                otags = {t.strip() for t in tagm.group(1).split(",")}
                if not (otags & tags):
                    continue
            # 无 tag = 总是启用
            if not name.startswith("CONFIG_"):
                name = "CONFIG_" + name.upper()
            if val is not None:
                if name not in opts:
                    opts[name] = val      # 数值档: 首个匹配 profile 的值
            else:
                opts[name] = "1"
        return sorted(f"{k}={v}" if v != "1" else k for k, v in opts.items())
    # ---- 退化路径: 老式 conf/MASTER 并集 ----
    opts = set()
    for sub in ("bsd/conf", "osfmk/conf", "pexpert/conf", "security/conf",
                "libkern/conf", "libsa/conf", "iokit/conf"):
        d = os.path.join(tree, sub)
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            if f in ("MASTER", "MASTER.arm64"):
                for line in open(os.path.join(d, f), errors="replace"):
                    line = line.split("#")[0].strip()
                    m = re.match(r"options\s+([A-Za-z0-9_]+)", line)
                    if m and not NON_PROD.search(m.group(1)):
                        name = m.group(1)
                        opts.add(name if name.startswith("CONFIG_") else "CONFIG_" + name.upper())
    return sorted(opts)

PROBE_C = """\
{defines}
{includes}
{decls}
"""

def build_probe(tree, incs, types, extra_defs, prelude=PRELUDE):
    defines = "\n".join(f"#define {d.replace('=', ' ')} 1" if "=" not in d else
                        f"#define {d.replace('=', ' ')}" for d in DEFINES + extra_defs)
    includes = "\n".join(f"#include <{i}>" for i in incs)
    decls = "\n".join(f"__attribute__((used)) static struct {t} _probe_{t};\n_Static_assert(sizeof(struct {t}) > 0, \"force layout {t}\");" for t in types)
    return PROBE_C.format(defines=defines, includes=prelude + includes, decls=decls)

DUMP_RE = re.compile(r"^\s*(\d+) \| (.*)$")

def parse_layouts(text):
    """解析 -fdump-record-layouts 输出 -> {struct_name: {dotted_member: byte_off}}"""
    out = {}
    cur, stack = None, []   # stack: (indent, name, base_bit)
    for line in text.splitlines():
        m = DUMP_RE.match(line)
        if not m:
            continue
        bit = int(m.group(1))
        rest = m.group(2)
        indent = len(rest) - len(rest.lstrip())
        item = rest.strip()
        hm = re.match(r"(?:struct|union) (\w+)$", item)
        if hm and indent == 0:
            cur = hm.group(1)
            out.setdefault(cur, {})
            stack = []
            continue
        if cur is None:
            continue
        # 层级: indent/2
        lvl = indent // 2
        while stack and stack[-1][0] >= lvl:
            stack.pop()
        hm = re.match(r"(?:struct|union)(?: (\w+))?(?: (\w+))?$", item)
        if hm:
            tag, name = hm.group(1), hm.group(2)
            path = name or ""
            full = ".".join([s[1] for s in stack if s[1]] + [path]).strip(".")
            base = bit
            stack.append((lvl, path, base))
            if full:
                out[cur][full] = base // 8
            continue
        if "sizeof=" in item or item.startswith("*** "):
            continue
        # 成员行: "type name" 或位域 "name : bits"
        mm = re.match(r"(.+?) (\w+)(?: : \d+)?$", item)
        if mm:
            name = mm.group(2)
            full = ".".join([s[1] for s in stack if s[1]] + [name]).strip(".")
            out[cur][full] = bit // 8
    return out

def probe_tree(tree, tag):
    # arm64 支持检测: 3789 等 macOS-only 树无 arm 代码 -> x86_64 目标(同为 LP64,
    # 机器无关结构体布局一致; arm 特有结构体如 pmap 跳过)
    has_arm64 = os.path.isdir(os.path.join(tree, "osfmk", "arm64")) or \
                os.path.isdir(os.path.join(tree, "bsd", "arm"))
    if has_arm64:
        make_links(tree)
    target = "arm64-apple-ios12.0" if has_arm64 else "x86_64-apple-macosx10.12"
    extra = config_options(tree) + ([cpu_define(tree), "MAX_CPU_CLUSTERS=2", "MAX_CPUS=64", "MAX_PSETS=2"] if has_arm64 else [])
    prelude = PRELUDE + '#include <sys/types.h>\n'
    incs = [os.path.join(BASE, "shim"), tree] + [os.path.join(tree, d) for d in
            ("bsd", "osfmk", "osfmk/kern", "libkern", "pexpert", "iokit", "EXTERNAL_HEADERS",
             "EXTERNAL_HEADERS/corecrypto", "libsa", "security", "libsyscall")
            if os.path.isdir(os.path.join(tree, d))]
    result, errors = {}, {}
    for name, (headers, types) in PROBES.items():
        if not has_arm64 and name == "pmap":
            errors[name] = {"missing": types, "err": "no arm64 sources in tree"}
            continue
        src = build_probe(tree, headers, types, extra, prelude)
        cfile = os.path.join(tree, f".probe_{name}.c")
        with open(cfile, "w") as f:
            f.write(src)
        cmd = (["clang", "-fsyntax-only", "-Xclang", "-fdump-record-layouts",
                f"--target={target}", "-nostdinc", "-ffreestanding",
                "-isystem", RES_INC, "-Wno-everything", "-fno-color-diagnostics"]
               + sum((["-I", d] for d in incs), []) + [cfile])
        p = subprocess.run(cmd, capture_output=True, text=True)
        layouts = parse_layouts(p.stderr + p.stdout)
        got = {t: layouts.get(t) for t in types if layouts.get(t)}
        if got:
            result.update(got)
        missing = [t for t in types if t not in got]
        if missing:
            # 记录首个错误方便诊断
            first_err = next((l for l in (p.stderr + p.stdout).splitlines()
                              if "error:" in l), "no layout dumped")
            errors[name] = {"missing": missing, "err": first_err.strip()[:200]}
        os.remove(cfile)
    return result, errors, ("arm64" if has_arm64 else "x86_64")

def main():
    os.makedirs(OUT, exist_ok=True)
    tags = sys.argv[1:] or sorted(
        (d for d in os.listdir(SRC) if d.startswith("xnu-") and os.path.isdir(os.path.join(SRC, d))),
        key=lambda d: [int(x) for x in d[4:].split('.')])
    for d in tags:
        tag = d[4:] if d.startswith("xnu-") else d
        tree = os.path.join(SRC, d)
        dst = os.path.join(OUT, f"{tag}.json")
        if os.path.exists(dst):
            print(f"= {tag} 已有结果, 跳过")
            continue
        res, errs, arch = probe_tree(tree, tag)
        n = sum(len(v) for v in res.values())
        with open(dst, "w") as f:
            json.dump({"xnu_tag": tag, "probe_arch": arch, "structs": res, "errors": errs}, f, indent=1, sort_keys=True)
        print(f"{'✓' if res else '✗'} {tag}: {len(res)} structs, {n} members"
              + (f" | 失败 probe: {list(errs)}" if errs else ""), flush=True)

if __name__ == "__main__":
    main()
