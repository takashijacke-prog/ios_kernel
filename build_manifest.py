#!/usr/bin/env python3
# 生成内核抽取清单: 按 (buildid, platform) 去重, 每个 iOS 版本 x 每个 SoC 只抽一次内核
import json, csv

plat = json.load(open("device_platforms.json"))
rows = list(csv.DictReader(open("ipsw_all_urls.csv")))

# identifier -> platform
ident2plat = {k: v["platform"] for k, v in plat.items()}

manifest = {}
for r in rows:
    p = ident2plat.get(r["identifier"], "")
    if not p:
        continue
    key = (r["buildid"], p)
    if key not in manifest:
        manifest[key] = {
            "version": r["version"],
            "buildid": r["buildid"],
            "platform": p,
            "example_device": r["device"],
            "identifier": r["identifier"],
            "url": r["url"],
        }

out = sorted(manifest.values(), key=lambda r: (
    [int(x) if x.isdigit() else 0 for x in r["version"].split(".")], r["platform"]))

with open("kernel_manifest.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["version","buildid","platform","example_device","identifier","url"])
    w.writeheader()
    w.writerows(out)

vers = sorted({r["version"] for r in out}, key=lambda v: [int(x) if x.isdigit() else 0 for x in v.split(".")])
print(f"去重后需抽取的内核: {len(out)} 个 (覆盖 {len(vers)} 个 iOS 版本)")
print(f"版本范围: {vers[0]} ~ {vers[-1]}")
print("输出: kernel_manifest.csv")
