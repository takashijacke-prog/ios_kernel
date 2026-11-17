#!/usr/bin/env python3
# 诊断探针: 对比成功/失败内核在 find_globals.py 各检测链路上的差异
import struct, sys
from collections import Counter

sys.path.insert(0, "/Users/guangbodadi/ios_kernel/analyzer")
from find_globals import MachO, text_words, find_xrefs_to, RegTrack, dec_ls_uoff, is_ret, is_adrp, dec_adrp, aval

def probe(path):
    m = MachO(path)
    words = text_words(m)
    idx = {pc: i for i, (pc, _) in enumerate(words)}
    print(f"=== {path}")
    print(f"  text_insns={len(words)} kernel_base={hex(m.kernel_base)}")
    print(f"  segments: {[(s['name'], hex(s['vmaddr']), hex(s['vmsize'])) for s in m.segments]}")

    # 1. shutdownwait 链路
    sw = [va for _, va in m.find_bytes(b"shutdownwait")]
    print(f"  [allproc] shutdownwait strings: {[hex(v) for v in sw]}")
    if sw:
        xrefs = [(x, sva) for sva in sw for x in find_xrefs_to(words, idx, sva)]
        print(f"    xrefs: {len(xrefs)}")
        for x, sva in xrefs[:5]:
            i = idx[x]
            # 函数窗口内的 DATA load
            tr = RegTrack()
            cands = []
            for pc, w in words[i:i + 400]:
                if is_ret(w):
                    break
                tr.do(pc, w)
                ls = dec_ls_uoff(w)
                if ls and ls[0]:
                    v = tr.reg.get(ls[2])
                    if v and v[0] == "load" and m.is_data(v[1]):
                        cands.append(hex(v[1]))
            print(f"    xref@{hex(x)} (str@{hex(sva)}): {Counter(cands).most_common(3)}")

    # 2. kernel_task 链路
    kt = [va for _, va in m.find_bytes(b"kernel_task")]
    print(f"  [kernproc] kernel_task strings: {[hex(v) for v in kt]}")
    for sva in kt:
        xrefs = [x for x in find_xrefs_to(words, idx, sva)]
        print(f"    str@{hex(sva)} xrefs: {len(xrefs)}")
        for x in xrefs[:3]:
            i = idx[x]
            tr = RegTrack()
            args = []
            for pc, w in words[max(0, i - 40):i + 20]:
                tr.do(pc, w)
                for argno in (0, 1):
                    v = tr.reg.get(argno)
                    if v and (v[0] == "load" or (v[0] == "addr" and m.is_data(v[1]))):
                        args.append((argno, v))
            print(f"      xref@{hex(x)}: {[(a, ('load',hex(v[1])) if v[0]=='load' else ('addr',hex(v[1]))) for a,v in args]}")

    # 3. shutdownwait 是否被别的字符串替代: 找 shutdownwait 相关字符串家族
    for s in (b"shutdown", b"halt", b"reboot", b"allproc", b"proc0"):
        hits = [va for _, va in m.find_bytes(s)]
        if hits:
            print(f"  [str] {s.decode()}: {[hex(v) for v in hits[:4]]}")

if __name__ == "__main__":
    for p in sys.argv[1:]:
        probe(p)
