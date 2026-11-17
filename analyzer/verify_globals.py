#!/usr/bin/env python3
# 批量验证: 遍历 offsets/globals/*.json, 用 Mach-O 段/section 信息校验每个候选的合理性
import json, os, sys, re, glob
from collections import Counter

BASE = "/Users/guangbodadi/ios_kernel"
sys.path.insert(0, os.path.join(BASE, "analyzer"))
from find_globals import MachO

def check(jp):
    d = json.load(open(jp))
    path = os.path.join(BASE, "kernels", d["relpath"])
    m = MachO(path)
    issues = []
    info = {}
    xnu = d.get("xnu_version", "?")
    ver = tuple(int(p) for p in re.split(r"\.", xnu.split("-")[0])[:2] or ["0"])

    # kernproc 迁移: xnu-7195 (iOS 14) 起 SECURITY_READ_ONLY_LATE -> __DATA_CONST
    # 例外: xnu-8019 (iOS 15.0) 分支未合入迁移, 仍为 __DATA (二进制确认)
    is_new = ver >= (7195,) and not (ver[0] == 8019)

    if d.get("allproc"):
        ap = int(d["allproc"], 16)
        sec = next((s for s in m.sections if s["addr"] <= ap < s["addr"]+s["size"]), None)
        seg = m.seg_of(ap)
        info["allproc_seg"] = seg
        info["allproc_sec"] = sec["name"] if sec else None
        if not (seg == "__DATA" and sec and sec["name"] in ("__common", "__bss", "__data")):
            issues.append(f"allproc 位置异常: {seg}/{sec['name'] if sec else '?'}")
    else:
        issues.append("allproc=None")

    if d.get("kernproc"):
        kp = int(d["kernproc"], 16)
        seg = m.seg_of(kp)
        sec = next((s for s in m.sections if s["addr"] <= kp < s["addr"]+s["size"]), None)
        info["kernproc_seg"] = seg
        info["kernproc_sec"] = sec["name"] if sec else None
        # iOS 16+: kernproc 必须在 __DATA_CONST; iOS 15-: 在 __DATA
        if is_new and seg != "__DATA_CONST":
            issues.append(f"kernproc 应在 __DATA_CONST, 实际 {seg}")
        if not is_new and seg != "__DATA":
            issues.append(f"kernproc 应在 __DATA, 实际 {seg}")
    else:
        issues.append("kernproc=None")

    return d, info, issues

def main():
    files = sorted(glob.glob(os.path.join(BASE, "offsets", "globals", "*.json")))
    print(f"共 {len(files)} 个结果")
    n_ok = n_issue = 0
    issues_list = []
    seg_stats = Counter()
    for jp in files:
        d, info, issues = check(jp)
        seg_stats[info.get("allproc_sec", "?") + "/" + info.get("kernproc_sec", "?")] += 1
        if issues:
            n_issue += 1
            issues_list.append((d.get("relpath", "?"), d.get("xnu_version"), issues))
        else:
            n_ok += 1
    print(f"通过: {n_ok}  有问题: {n_issue}")
    print(f"section 组合: {dict(seg_stats)}")
    for rel, xnu, issues in issues_list[:25]:
        print(f"  ! {rel} [{xnu}]: {issues}")

if __name__ == "__main__":
    main()
