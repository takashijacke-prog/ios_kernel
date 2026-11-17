#!/usr/bin/env python3
# 关键版本 kernelcache 远程抽取 (正确解析CSV, 断点续传)
import csv, os, subprocess, sys, time

BASE = os.path.dirname(os.path.abspath(__file__))
IPSW = os.path.join(BASE, "tools", "ipsw")
DONE = os.path.join(BASE, "logs", "done.txt")
FAIL = os.path.join(BASE, "logs", "failed.txt")
DETAIL = os.path.join(BASE, "logs", "detail.log")
os.makedirs(os.path.join(BASE, "logs"), exist_ok=True)

done = set(open(DONE).read().split()) if os.path.exists(DONE) else set()
failed = set(open(FAIL).read().split()) if os.path.exists(FAIL) else set()

rows = list(csv.DictReader(open(os.path.join(BASE, "key_targets.csv"))))
only = sys.argv[1] if len(sys.argv) > 1 else None   # 可选: 只跑某一行 platform_version_buildid

for r in rows:
    key = f"{r['platform']}_{r['version']}_{r['buildid']}"
    if only and key != only:
        continue
    if key in done:
        continue
    outdir = os.path.join(BASE, "kernels", r["platform"], f"iOS_{r['version']}_{r['buildid']}")
    os.makedirs(outdir, exist_ok=True)
    print(f"[{time.strftime('%H:%M:%S')}] 抽取 {r['platform']} iOS {r['version']} ({r['buildid']}) ...", flush=True)
    with open(DETAIL, "a") as log:
        p = subprocess.run([IPSW, "extract", "--remote", r["url"], "--kernel", "--output", outdir],
                           stdout=log, stderr=subprocess.STDOUT)
    if p.returncode == 0:
        # ipsw 会建子目录且可能出多个变体(同SoC内容相同) — 取第一个拍平到 outdir
        target = os.path.join(outdir, f"kernelcache_{r['platform']}_{r['version']}_{r['buildid']}")
        picked = None
        for root, _, files in os.walk(outdir):
            for f in sorted(files):
                if f.startswith("kernelcache."):
                    picked = os.path.join(root, f)
                    break
            if picked:
                break
        if picked and os.path.abspath(picked) != target:
            os.replace(picked, target)
        # 清掉多余变体和子目录
        for root, dirs, files in os.walk(outdir, topdown=False):
            for f in files:
                if os.path.join(root, f) != target:
                    os.remove(os.path.join(root, f))
            for d in dirs:
                os.rmdir(os.path.join(root, d))
        open(DONE, "a").write(key + "\n")
        print(f"[{time.strftime('%H:%M:%S')}] ✓ {key}", flush=True)
    else:
        open(FAIL, "a").write(key + "\n")
        print(f"[{time.strftime('%H:%M:%S')}] ✗ {key} (见 logs/detail.log)", flush=True)
    if only:
        break

print(f"===== 成功 {len(done)} / 失败 {len(failed)} =====")
