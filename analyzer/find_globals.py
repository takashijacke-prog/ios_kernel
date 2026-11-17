#!/usr/bin/env python3
# 全局符号偏移分析器: kernel_base / version / allproc / kernproc
# 方法: Mach-O 解析 + 手工解码 adrp/add/ldr/str/mov 轻量符号执行 (经典 patchfinder 思路)
# 寄存器值语义: ("addr", base, off) = 编译期绝对地址 base+off; ("load", va) = 从 va 载入
import struct, sys, os, re, json
from collections import Counter

MH_MAGIC_64 = b"\xcf\xfa\xed\xfe"
LC_SEGMENT_64 = 0x19

class MachO:
    def __init__(self, path):
        self.path = path
        self.data = open(path, "rb").read()
        d = self.data
        assert d[:4] == MH_MAGIC_64, "not macho64"
        self.filetype = struct.unpack_from("<I", d, 12)[0]
        self.segments = []
        self.sections = []
        self._parse_segments(0)
        kbase = [s for s in self.segments if s["name"] == "__TEXT"]
        self.kernel_base = kbase[0]["vmaddr"] if kbase else self.segments[0]["vmaddr"]
        # MH_FILESET kernelcache: 外层仅壳, 真正的内核 Mach-O 在 com.apple.kernel 条目里
        if self.filetype == 0xC:
            koff = self._fileset_kernel_off()
            if koff:
                self.segments, self.sections = [], []
                self._parse_segments(koff)

    def _parse_segments(self, base):
        d = self.data
        ncmds = struct.unpack_from("<I", d, base + 16)[0]
        off = base + 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", d, off)
            if cmd == LC_SEGMENT_64:
                name = d[off+8:off+24].split(b"\0")[0].decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", d, off+24)
                nsects = struct.unpack_from("<I", d, off+64)[0]
                self.segments.append(dict(name=name, vmaddr=vmaddr, vmsize=vmsize,
                                          fileoff=fileoff, filesize=filesize))
                soff = off + 72
                for _ in range(nsects):
                    sn = d[soff:soff+16].split(b"\0")[0].decode()
                    sg = d[soff+16:soff+32].split(b"\0")[0].decode()
                    addr, size = struct.unpack_from("<QQ", d, soff+32)
                    foff = struct.unpack_from("<I", d, soff+48)[0]
                    self.sections.append(dict(seg=sg, name=sn, addr=addr, size=size, offset=foff))
                    soff += 80
            off += cmdsize

    def _fileset_kernel_off(self):
        d = self.data
        ncmds = struct.unpack_from("<I", d, 16)[0]
        off = 32
        first = None
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", d, off)
            if cmd == 0x80000035:  # LC_FILESET_ENTRY
                _, fileoff = struct.unpack_from("<QQ", d, off+8)
                eid_off = struct.unpack_from("<I", d, off+24)[0]
                eid = d[off+eid_off:d.find(b"\0", off+eid_off)].decode(errors="replace")
                if first is None:
                    first = fileoff
                if eid == "com.apple.kernel":
                    return fileoff
            off += cmdsize
        return first
        kbase = [s for s in self.segments if s["name"] == "__TEXT"]
        self.kernel_base = kbase[0]["vmaddr"] if kbase else self.segments[0]["vmaddr"]

    def va2off(self, va):
        for s in self.segments:
            if s["vmaddr"] <= va < s["vmaddr"] + s["vmsize"] and (va - s["vmaddr"]) < s["filesize"]:
                return s["fileoff"] + (va - s["vmaddr"])
        return None

    def off2va(self, o):
        for s in self.segments:
            if s["fileoff"] <= o < s["fileoff"] + s["filesize"]:
                return s["vmaddr"] + (o - s["fileoff"])
        return None

    def seg_of(self, va):
        for s in self.segments:
            if s["vmaddr"] <= va < s["vmaddr"] + s["vmsize"]:
                return s["name"]
        return None

    def is_data(self, va):
        s = self.seg_of(va)
        return bool(s) and s.startswith("__DATA")

    def find_bytes(self, needle):
        out, start = [], 0
        while True:
            i = self.data.find(needle, start)
            if i < 0:
                return out
            va = self.off2va(i)
            if va:
                out.append((i, va))
            start = i + 1

# ---------- ARM64 手工解码 ----------
def dec_adrp(w, pc):
    imm = (((w >> 5) & 0x7ffff) << 2) | ((w >> 29) & 3)
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xfff) + (imm << 12), w & 0x1f            # target, rd

def dec_add_imm(w):
    imm = (w >> 10) & 0xfff
    if ((w >> 22) & 3) == 1:
        imm <<= 12
    return (w >> 5) & 0x1f, w & 0x1f, imm                   # rn, rd, imm

def dec_ls_uoff(w):
    """无符号立即数 LDR/STR -> (is_load, rn, rt, imm) 或 None"""
    if (w & 0x3B000000) != 0x39000000:
        return None
    opc = (w >> 22) & 3
    if opc == 3:
        return None
    size = (w >> 30) & 3
    if opc == 2 and size == 3:
        return None
    shift = size if opc != 2 else min(size, 2)
    return (opc != 0, (w >> 5) & 0x1f, w & 0x1f, ((w >> 10) & 0xfff) << shift)

def dec_mov_reg(w):
    if (w & 0xFFE0FFE0) == 0xAA0003E0 or (w & 0x7FE0FFE0) == 0x2A0003E0:
        return (w >> 16) & 0x1f, w & 0x1f                   # rm, rd
    return None

def is_adrp(w):      return (w & 0x9F000000) == 0x90000000
def is_add_imm64(w): return (w & 0xFF000000) == 0x91000000
def is_bl(w):        return (w & 0xFC000000) == 0x94000000
def is_ret(w):       return (w & 0xFFFFFC1F) == 0xD65F0000

def text_words(m):
    out = []
    for s in m.sections:
        if s["name"] == "__text" and s["seg"] in ("__TEXT", "__TEXT_EXEC"):
            base_va, size, foff = s["addr"], s["size"], s["offset"]
            for i in range(0, size & ~3, 4):
                out.append((base_va + i, struct.unpack_from("<I", m.data, foff + i)[0]))
    out.sort()
    return out

def aval(v):
    """("addr", base, off) -> 扁平 va"""
    return v[1] + v[2] if v and v[0] == "addr" else None

class RegTrack:
    def __init__(self):
        self.reg = {}
    def do(self, pc, w):
        if is_adrp(w):
            tgt, rd = dec_adrp(w, pc)
            self.reg[rd] = ("addr", tgt, 0)
            return None
        if is_add_imm64(w):
            rn, rd, imm = dec_add_imm(w)
            v = self.reg.get(rn)
            if v and v[0] == "addr":
                self.reg[rd] = ("addr", v[1], v[2] + imm)
            elif v and v[0] == "load":
                # load 后的指针 + 偏移 (iOS10 风格: ldr x, [slot]; add x0, x, #off)
                # 用独立类型 loadptr 保留"源自槽位"语义, 避免与 adrp 直算地址混淆
                self.reg[rd] = ("loadptr", v[1], imm)
            else:
                self.reg.pop(rd, None)
            return None
        mv = dec_mov_reg(w)
        if mv:
            rm, rd = mv
            v = self.reg.get(rm)
            if v:
                self.reg[rd] = v
            else:
                self.reg.pop(rd, None)
            return None
        ls = dec_ls_uoff(w)
        if ls:
            is_load, rn, rt, imm = ls
            v = self.reg.get(rn)
            base = aval(v)
            if is_load:
                if base is not None:
                    self.reg[rt] = ("load", base + imm)
                else:
                    self.reg.pop(rt, None)
                return None
            src = self.reg.get(rt)
            return ("str", (base + imm) if base is not None else None, src)
        if is_bl(w):
            self.reg.clear()
        return None

def find_xrefs_to(words, idx, target_va):
    page, lo = target_va & ~0xfff, target_va & 0xfff
    hits = []
    for i, (pc, w) in enumerate(words):
        if not is_adrp(w):
            continue
        tgt, rd = dec_adrp(w, pc)
        if tgt != page:
            continue
        for j in range(i + 1, min(i + 6, len(words))):
            pc2, w2 = words[j]
            if is_add_imm64(w2):
                rn, rd2, imm = dec_add_imm(w2)
                if rn == rd and imm == lo:
                    hits.append(pc)
                break
            if is_adrp(w2) or is_bl(w2) or is_ret(w2):
                break
    return hits

def find_allproc(m, words, idx):
    """shutdownwait xref -> 同函数内向 __DATA 的 ldr (allproc.lh_first)"""
    xrefs = []
    for _, sva in m.find_bytes(b"shutdownwait"):
        xrefs += [(sva, x) for x in find_xrefs_to(words, idx, sva)]
    if not xrefs:
        return None, "no shutdownwait xref"
    cands = []
    for sva, xref in xrefs:
        tr = RegTrack()
        for pc, w in words[idx[xref]:idx[xref] + 400]:
            if is_ret(w):
                break
            tr.do(pc, w)
            ls = dec_ls_uoff(w)
            if ls and ls[0]:
                v = tr.reg.get(ls[2])
                if v and v[0] == "load" and m.is_data(v[1]):
                    cands.append(v[1])
    if not cands:
        return None, "xref found, no DATA load nearby"
    best, n = Counter(cands).most_common(1)[0]
    return best, f"votes {n}/{len(cands)}"

def find_kernproc_via_ktask(m, words, idx):
    """bsd_init: process_name("kernel_task", kernproc)
    - 调用形式: x1 = ldr [kernproc] 或 x1/x0 = ("addr", proc0)
    - iOS10 风格: x0 = ldr [kernproc槽位] + p_comm偏移 -> addr(槽位, off)
    - 内联 bcopy 形式: x0 = proc0 + p_comm 偏移
    找到 proc0 后再反查 str &proc0 -> __DATA 全局 = kernproc"""
    kts = [va for _, va in m.find_bytes(b"kernel_task")]
    if not kts:
        return None, "no kernel_task string", None
    load_votes, proc0_votes, base_votes, str_votes = [], [], [], []
    for sva in kts:
        for xref in find_xrefs_to(words, idx, sva):
            i = idx[xref]
            tr = RegTrack()
            for pc, w in words[max(0, i - 60):i + 40]:
                r = tr.do(pc, w)
                if r and r[0] == "str" and r[1] is not None and m.is_data(r[1]):
                    str_votes.append(r[1])   # 初始化写入点 (bsd_init 早期 str [槽位])
                for argno in (0, 1):
                    v = tr.reg.get(argno)
                    if not v:
                        continue
                    if v[0] == "load" and m.is_data(v[1]):
                        load_votes.append(v[1])
                    elif v[0] == "loadptr" and m.is_data(v[1]):
                        base_votes.append(v[1])   # ldr 槽位 + 偏移 -> 槽位是 kernproc
                    elif v[0] == "addr" and m.is_data(v[1]):
                        proc0_votes.append(aval(v))   # 完整地址 (结构基址或内部字段)
    if load_votes:
        best, n = Counter(load_votes).most_common(1)[0]
        return best, f"ktask x1 load votes {n}", None
    if base_votes:
        best, n = Counter(base_votes).most_common(1)[0]
        return best, f"ktask addr+off base votes {n}", None
    if not proc0_votes:
        if str_votes:
            best, n = Counter(str_votes).most_common(1)[0]
            return best, f"ktask xref str-slot votes {n}", None
        return None, "ktask xref but args untracked", None
    proc0, n = Counter(proc0_votes).most_common(1)[0]
    votes = []
    p0page = proc0 & ~0xfff
    for i, (pc, w) in enumerate(words):
        if not (is_adrp(w) and dec_adrp(w, pc)[0] == p0page):
            continue
        tr = RegTrack()
        for pc2, w2 in words[max(0, i - 64):i + 200]:
            if is_ret(w2):
                break
            r = tr.do(pc2, w2)
            if r and r[0] == "str" and r[1] is not None:
                src = r[2]
                if src and src[0] == "addr" and m.is_data(r[1]):
                    sv = aval(src)
                    if sv is not None and (sv & ~0xfff) == p0page:
                        votes.append(r[1])
    if votes:
        best, n2 = Counter(votes).most_common(1)[0]
        return best, f"via proc0 {hex(proc0)} votes {n2}", proc0
    return None, f"proc0 {hex(proc0)} found, no store", proc0

def find_kernproc(m, words, idx, allproc):
    """LIST_INSERT_HEAD(&allproc, kernproc, p_list): 窗口内同时 ldr allproc + str allproc,
    存入值为 ("load", G) -> G=kernproc; 为 ("addr", P) -> P=proc0 再反查"""
    if allproc is None:
        return None, "need allproc"
    proc0_cands, kern_votes = [], []
    for i, (pc, w) in enumerate(words):
        if not (is_adrp(w) and dec_adrp(w, pc)[0] == (allproc & ~0xfff)):
            continue
        tr = RegTrack()
        loads, stores = [], []
        for pc2, w2 in words[i:i + 120]:
            if is_ret(w2):
                break
            r = tr.do(pc2, w2)
            if r and r[0] == "str" and r[1] is not None:
                stores.append((r[1], r[2]))
            else:
                ls = dec_ls_uoff(w2)
                if ls and ls[0]:
                    v = tr.reg.get(ls[2])
                    if v and v[0] == "load" and v[1] == allproc:
                        loads.append(v[1])
        if not loads:
            continue
        for dst, src in stores:
            if dst != allproc or not src:
                continue
            if src[0] == "load" and m.is_data(src[1]):
                kern_votes.append(src[1])
            elif src[0] == "addr":
                proc0_cands.append(aval(src))
    if kern_votes:
        best, n = Counter(kern_votes).most_common(1)[0]
        return best, f"list load votes {n}"
    if proc0_cands:
        proc0, _ = Counter(proc0_cands).most_common(1)[0]
        votes = []
        p0page = proc0 & ~0xfff
        for i, (pc, w) in enumerate(words):
            if not (is_adrp(w) and dec_adrp(w, pc)[0] == p0page):
                continue
            tr = RegTrack()
            for pc2, w2 in words[max(0, i - 64):i + 200]:
                if is_ret(w2):
                    break
                r = tr.do(pc2, w2)
                if r and r[0] == "str" and r[1] is not None:
                    src = r[2]
                    if src and src[0] == "addr" and aval(src) == proc0 and m.is_data(r[1]) and r[1] != allproc:
                        votes.append(r[1])
        if votes:
            best, n = Counter(votes).most_common(1)[0]
            return best, f"via proc0 {hex(proc0)} votes {n}"
        return None, f"proc0 {hex(proc0)} found, no kernproc store"
    return None, "LIST_INSERT_HEAD pattern not found"

def find_version(m):
    for off, va in m.find_bytes(b"Darwin Kernel Version"):
        s = m.data[off:off + 256].split(b"\0")[0]
        mm = re.match(rb"Darwin Kernel Version (\d+\.\d+\.\d+): .+root:xnu-([0-9.]+)~(\d+)/(\S+)", s)
        if mm:
            return va, mm.group(1).decode(), mm.group(2).decode(), mm.group(4).decode()
    return None, None, None, None

def analyze(path):
    m = MachO(path)
    words = text_words(m)
    idx = {pc: i for i, (pc, _) in enumerate(words)}
    ver_va, darwin, xnu, variant = find_version(m)
    allproc, amsg = find_allproc(m, words, idx)
    kernproc, kmsg, proc0 = find_kernproc_via_ktask(m, words, idx)
    if kernproc is None and allproc is not None:
        kernproc, kmsg2 = find_kernproc(m, words, idx, allproc)
        kmsg += " | list: " + kmsg2
    kb = m.kernel_base
    return {
        "file": os.path.basename(path),
        "kernel_base": hex(kb),
        "version_string": hex(ver_va) if ver_va else None,
        "version_off": hex(ver_va - kb) if ver_va else None,
        "darwin_version": darwin,
        "xnu_version": xnu,
        "build_variant": variant,
        "allproc": hex(allproc) if allproc else None,
        "allproc_off": hex(allproc - kb) if allproc else None,
        "allproc_seg": m.seg_of(allproc) if allproc else None,
        "kernproc": hex(kernproc) if kernproc else None,
        "kernproc_off": hex(kernproc - kb) if kernproc else None,
        "kernproc_seg": m.seg_of(kernproc) if kernproc else None,
        "proc0": hex(proc0) if proc0 else None,
        "notes": {"allproc": amsg, "kernproc": kmsg, "text_instructions": len(words)},
    }

if __name__ == "__main__":
    for p in sys.argv[1:]:
        print(json.dumps(analyze(p), indent=1, ensure_ascii=False))
