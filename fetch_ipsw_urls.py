#!/usr/bin/env python3
# 拉取 iPhone 6 ~ iPhone 16 全机型全版本(含小版本)的真实 IPSW 直链
# 数据源: ipsw.me API -> 苹果官方 CDN (updates.cdn-apple.com / appldnld.apple.com)
import json, csv, sys, ssl, urllib.request, concurrent.futures

try:
    import certifi
    SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    SSL_CTX = ssl.create_default_context()
    SSL_CTX.check_hostname = False
    SSL_CTX.verify_mode = ssl.CERT_NONE

# iPhone 6 ~ iPhone 16 全系 identifier (含 Plus/Pro/Max/mini/SE/e)
DEVICES = [
    "iPhone7,1", "iPhone7,2",                          # 6 Plus / 6
    "iPhone8,1", "iPhone8,2", "iPhone8,4",             # 6s / 6s+ / SE1
    "iPhone9,1", "iPhone9,2", "iPhone9,3", "iPhone9,4",# 7 / 7+
    "iPhone10,1","iPhone10,2","iPhone10,3",            # 8 / 8+ / X
    "iPhone10,4","iPhone10,5","iPhone10,6",            # 8/8+/X (高通基带版)
    "iPhone11,2","iPhone11,4","iPhone11,6","iPhone11,8",# XS / XS Max / XR
    "iPhone12,1","iPhone12,3","iPhone12,5","iPhone12,8",# 11 / 11Pro / 11ProMax / SE2
    "iPhone13,1","iPhone13,2","iPhone13,3","iPhone13,4",# 12mini / 12 / 12Pro / 12ProMax
    "iPhone14,2","iPhone14,3","iPhone14,4","iPhone14,5","iPhone14,6",# 13Pro / 13ProMax / 13mini / 13 / SE3
    "iPhone14,7","iPhone14,8","iPhone15,2","iPhone15,3",# 14 / 14+ / 14Pro / 14ProMax
    "iPhone15,4","iPhone15,5","iPhone16,1","iPhone16,2",# 15 / 15+ / 15Pro / 15ProMax
    "iPhone17,1","iPhone17,2","iPhone17,3","iPhone17,4","iPhone17,5",# 16Pro / 16ProMax / 16 / 16+ / 16e
]

def fetch(ident):
    url = f"https://api.ipsw.me/v4/device/{ident}?type=ipsw"
    with urllib.request.urlopen(url, timeout=30, context=SSL_CTX) as r:
        d = json.loads(r.read())
    rows = []
    for fw in d.get("firmwares", []):
        if not fw.get("signed"):   # 只要还能下的(验证开的) — 老版本验证关了苹果CDN也删链, 先全留着再说
            pass
        rows.append({
            "device": d.get("name", ident),
            "identifier": ident,
            "version": fw.get("version"),
            "buildid": fw.get("buildid"),
            "signed": fw.get("signed"),
            "size_GB": round(fw.get("size", 0) / 1e9, 2),
            "url": fw.get("url", ""),
        })
    return rows

def main():
    all_rows = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        for rows in ex.map(fetch, DEVICES):
            all_rows.extend(rows)

    # 去重(同一 version+buildid+url)
    seen, out = set(), []
    for r in all_rows:
        k = (r["identifier"], r["version"], r["buildid"])
        if k not in seen and r["url"]:
            seen.add(k)
            out.append(r)

    out.sort(key=lambda r: (r["identifier"], [int(x) if x.isdigit() else 0 for x in (r["version"] or "0").split(".")]))

    with open("ipsw_all_urls.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["device","identifier","version","buildid","signed","size_GB","url"])
        w.writeheader()
        w.writerows(out)

    with open("ipsw_all_urls.txt", "w") as f:
        for r in out:
            f.write(r["url"] + "\n")

    total_size = sum(r["size_GB"] for r in out)
    signed_cnt = sum(1 for r in out if r["signed"])
    print(f"共 {len(out)} 个 IPSW 直链 | 当前可签名下载 {signed_cnt} 个 | 全量体积约 {total_size:.0f} GB")
    print("输出: ipsw_all_urls.csv (完整表) / ipsw_all_urls.txt (纯链接)")

if __name__ == "__main__":
    main()
