#!/bin/bash
# 关键版本 kernelcache 远程抽取: 只下 IPSW 里 kernelcache 那几十MB
# 输入: key_targets.csv (platform,version,buildid,example_device,identifier,url)
cd "$(dirname "$0")"
mkdir -p kernels logs
IPSW=./tools/ipsw
DONE_LOG=logs/done.txt
FAIL_LOG=logs/failed.txt
touch "$DONE_LOG" "$FAIL_LOG"

tail -n +2 key_targets.csv | while IFS=, read -r platform version buildid device ident url; do
    url=$(echo "$url" | tr -d '"')
    key="${platform}_${version}_${buildid}"
    outdir="kernels/${platform}/iOS_${version}_${buildid}"

    grep -qF "$key" "$DONE_LOG" && continue   # 断点续传

    mkdir -p "$outdir"
    echo "[$(date +%H:%M:%S)] 抽取 $platform iOS $version ($buildid) ..."

    if "$IPSW" extract --remote "$url" --kernel --output "$outdir" >>logs/detail.log 2>&1; then
        # 统一命名 kernelcache_<platform>_<version>_<buildid>
        for f in "$outdir"/kernelcache.release.* "$outdir"/kernelcache.*; do
            [ -f "$f" ] || continue
            case "$(basename "$f" | grep -c "$buildid" || true)" in
                0) mv "$f" "$outdir/kernelcache_${platform}_${version}_${buildid}" ;;
            esac
        done
        echo "$key" >> "$DONE_LOG"
        echo "[$(date +%H:%M:%S)] ✓ $platform iOS $version"
    else
        echo "$key" >> "$FAIL_LOG"
        echo "[$(date +%H:%M:%S)] ✗ $platform iOS $version (见 logs/detail.log)"
    fi
done

echo "===== 结束: 成功 $(wc -l < $DONE_LOG | tr -d ' ') / 失败 $(wc -l < $FAIL_LOG | tr -d ' ') ====="
