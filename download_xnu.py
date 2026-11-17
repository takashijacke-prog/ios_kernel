#!/usr/bin/env python3
# 为每个 xnu 版本挑选 GitHub tag（精确优先，否则同大版本最近），下载 tarball 到 xnu_src/
import json, os, subprocess, sys

BASE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(BASE, "xnu_src")
os.makedirs(SRC, exist_ok=True)

tags = json.load(open(os.path.join(BASE, "xnu_available_tags.json")))   # ["xnu-..."]
avail = sorted((t[4:] for t in tags), key=lambda v: [int(x) for x in v.split('.')])
need = [k for k in json.load(open(os.path.join(BASE, "xnu_versions.json"))) if not k.startswith('PARSE')]

def pick(n):
    if n in avail:
        return n, True
    major = n.split('.')[0]
    same = [t for t in avail if t.split('.')[0] == major]
    if not same:
        return None, False
    # 版本元组距离最小
    nk = [int(x) for x in n.split('.')]
    def dist(t):
        tk = [int(x) for x in t.split('.')]
        L = max(len(nk), len(tk))
        a = nk + [0] * (L - len(nk)); b = tk + [0] * (L - len(tk))
        return sum(abs(x - y) * (10 ** (6 * (L - i))) for i, (x, y) in enumerate(zip(a, b)))
    best = min(same, key=dist)
    return best, False

mapping, tags_needed = {}, set()
for n in need:
    t, exact = pick(n)
    mapping[n] = {"tag": t, "exact": exact}
    if t:
        tags_needed.add(t)
        print(f"{'✓' if exact else '≈'} {n} -> {t}")
    else:
        print(f"✗ {n} -> NO TAG")

json.dump(mapping, open(os.path.join(BASE, "xnu_tag_map.json"), "w"), indent=1)
print(f"\n需下载 {len(tags_needed)} 个 tarball")

fail = []
for t in sorted(tags_needed, key=lambda v: [int(x) for x in v.split('.')]):
    d = os.path.join(SRC, f"xnu-{t}")
    if os.path.isdir(d):
        print(f"= xnu-{t} 已存在")
        continue
    url = f"https://github.com/apple-oss-distributions/xnu/archive/refs/tags/xnu-{t}.tar.gz"
    tgz = os.path.join(SRC, f"xnu-{t}.tar.gz")
    p = subprocess.run(["curl", "-sL", "--fail", "-o", tgz, url])
    if p.returncode != 0 or not os.path.exists(tgz) or os.path.getsize(tgz) < 100000:
        print(f"✗ xnu-{t} 下载失败")
        fail.append(t)
        continue
    subprocess.run(["tar", "-xzf", tgz, "-C", SRC], check=True)
    os.remove(tgz)
    print(f"✓ xnu-{t}")
print(f"===== 失败 {len(fail)}: {fail}")
