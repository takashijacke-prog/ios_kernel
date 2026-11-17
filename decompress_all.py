#!/usr/bin/env python3
# 批量解压 kernelcache -> .macho
# - 已是裸 Mach-O (cffa edfe) 的直接复制
# - IMG4/压缩封装走 ipsw kernel dec
import os, subprocess

BASE = os.path.dirname(os.path.abspath(__file__))
IPSW = os.path.join(BASE, "tools", "ipsw")
KDIR = os.path.join(BASE, "kernels")

def is_macho64(path):
    with open(path, "rb") as f:
        return f.read(4) == b"\xcf\xfa\xed\xfe"

ok, copied, fail = 0, 0, 0
for root, _, files in os.walk(KDIR):
    for f in sorted(files):
        if not f.startswith("kernelcache_") or f.endswith(".macho"):
            continue
        src = os.path.join(root, f)
        dst = src + ".macho"
        if os.path.exists(dst):
            continue
        if is_macho64(src):
            with open(src, "rb") as a, open(dst, "wb") as b:
                b.write(a.read())
            copied += 1
            print(f"= {f} (裸Mach-O直拷)", flush=True)
            continue
        p = subprocess.run([IPSW, "kernel", "dec", src, "--output", root],
                           capture_output=True, text=True)
        produced = None
        for cand in (src + ".dec", os.path.join(root, os.path.splitext(f)[0] + ".dec")):
            if os.path.exists(cand):
                produced = cand
                break
        if p.returncode == 0 and produced and is_macho64(produced):
            os.replace(produced, dst)
            ok += 1
            print(f"✓ {f}", flush=True)
        else:
            if produced and not is_macho64(produced):
                os.remove(produced)
            fail += 1
            print(f"✗ {f}: {(p.stdout + p.stderr)[-200:]}", flush=True)

print(f"===== 解压 {ok} / 直拷 {copied} / 失败 {fail} =====")
