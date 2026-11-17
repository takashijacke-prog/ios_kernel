#!/usr/bin/env python3
# 关键版本筛选: 每个 SoC 平台 x 每个 iOS 大版本, 取首发(min)+最终(max)
import csv, collections

PLATS = ["t8010","t8015","t8020","t8030","t8101","t8110","t8120","t8130","t8140"]

def vkey(v):
    return [int(x) if x.isdigit() else 0 for x in v.split(".")]

rows = [r for r in csv.DictReader(open("kernel_manifest.csv")) if r["platform"] in PLATS]

# platform -> major -> [(version, buildid, url)]
g = collections.defaultdict(lambda: collections.defaultdict(list))
for r in rows:
    major = r["version"].split(".")[0]
    g[r["platform"]][major].append(r)

out = []
for p in PLATS:
    for major in sorted(g[p], key=int):
        vers = g[p][major]
        seen, dedup = set(), []
        for r in sorted(vers, key=lambda r: vkey(r["version"])):
            if r["buildid"] not in seen:
                seen.add(r["buildid"])
                dedup.append(r)
        picks = [dedup[0]] if len(dedup) == 1 else [dedup[0], dedup[-1]]
        out.extend(picks)

out.sort(key=lambda r: (r["platform"], vkey(r["version"])))
with open("key_targets.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["platform","version","buildid","example_device","identifier","url"])
    w.writeheader()
    w.writerows([{k: r[k] for k in w.fieldnames} for r in out])

for r in out:
    print(f'{r["platform"]}  iOS {r["version"]:<7} {r["buildid"]:<9} {r["example_device"]}')
print(f"\n共 {len(out)} 个 kernelcache 待抽取")
