#!/bin/bash
# 批量远程抽取内核: 只下 IPSW 里 kernelcache 那几十MB, 不下整个固件
# 用法: ./download_kernels.sh [起始行] [结束行]   (默认全量)
cd "$(dirname "$0")"
mkdir -p kernels logs

START=${1:-2}          # 跳过CSV表头
END=${2:-99999}
DONE_LOG=logs/done.txt
FAIL_LOG=logs/failed.txt
touch "$DONE_LOG" "$FAIL_LOG"

i=1
tail -n +2 kernel_manifest.csv | while IFS=, read -r version buildid platform device ident url; do
    i=$((i+1))
    [ $i -lt $START ] && continue
    [ $i -gt $END ] && break

    url=$(echo "$url" | tr -d '"')
    key="${version}_${buildid}_${platform}"
    outdir="kernels/iOS_${version}/${platform}"

    # 已完成的跳过 (断点续传)
    grep -qF "$key" "$DONE_LOG" && continue

    mkdir -p "$outdir"
    echo "[$(date +%H:%M:%S)] $i 抽取 iOS $version ($buildid) $platform ..."

    if ipsw extract --remote "$url" --kernel --output "$outdir" >>logs/detail.log 2>&1; then
        # 改名规范一下
        for f in "$outdir"/kernelcache.release.*; do
            [ -f "$f" ] || continue
            base=$(basename "$f")
            case "$base" in
                *"${buildid}"*) : ;;  # 已带buildid
                *) mv "$f" "$outdir/kernelcache_${platform}_${version}_${buildid}" ;;
            esac
        done
        echo "$key" >> "$DONE_LOG"
        echo "[$(date +%H:%M:%S)] ✓ iOS $version $platform 完成"
    else
        echo "$key" >> "$FAIL_LOG"
        echo "[$(date +%H:%M:%S)] ✗ iOS $version $platform 失败 (见 logs/detail.log)"
    fi
done

echo "===== 全部结束: 成功 $(wc -l < $DONE_LOG) / 失败 $(wc -l < $FAIL_LOG) ====="
