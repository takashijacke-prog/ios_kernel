#!/usr/bin/env python3
# 并行驱动: 对全部 .macho 跑 find_globals.analyze, 结果写 offsets/globals/*.json
import json, os, sys
from multiprocessing import Pool

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "offsets", "globals")

def one(path):
    try:
        import find_globals
        r = find_globals.analyze(path)
        rel = os.path.relpath(path, os.path.join(BASE, "kernels"))
        plat = rel.split(os.sep)[0]
        r["platform"] = plat
        r["relpath"] = rel
        name = os.path.basename(path).replace(".macho", "") + ".json"
        with open(os.path.join(OUT, name), "w") as f:
            json.dump(r, f, indent=1)
        ok = bool(r.get("allproc"))
        return f"{'✓' if ok else '△'} {name} allproc={r.get('allproc')} kernproc={r.get('kernproc')}"
    except Exception as e:
        return f"✗ {os.path.basename(path)}: {type(e).__name__} {e}"

def main():
    os.makedirs(OUT, exist_ok=True)
    targets = []
    for root, _, files in os.walk(os.path.join(BASE, "kernels")):
        for f in sorted(files):
            if f.endswith(".macho"):
                name = f.replace(".macho", "") + ".json"
                if not os.path.exists(os.path.join(OUT, name)):
                    targets.append(os.path.join(root, f))
    print(f"待分析 {len(targets)} 个内核", flush=True)
    with Pool(6) as p:
        for line in p.imap_unordered(one, targets):
            print(line, flush=True)

if __name__ == "__main__":
    main()
