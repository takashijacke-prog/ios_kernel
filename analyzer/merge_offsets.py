#!/usr/bin/env python3
# 合并: key_targets + globals/*.json + structs/*.json -> offsets.csv / offsets.json / verify_report.md
import csv, json, os, sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "offsets")

# CSV 列: (列名, struct, [成员 fallback 链])
COLUMNS = [
    ("proc.p_list_next", "proc", ["p_list.le_next", "le_next"]),
    ("proc.p_pid",       "proc", ["p_pid"]),
    ("proc.p_task",      "proc", ["p_task"]),
    ("proc.p_ucred",     "proc", ["p_ucred", "p_ucred_ro"]),
    ("proc.p_fd",        "proc", ["p_fd"]),
    ("proc.p_comm",      "proc", ["p_comm"]),
    ("proc.p_flag",      "proc", ["p_flag"]),
    ("proc.p_stat",      "proc", ["p_stat"]),
    ("proc.p_textvp",    "proc", ["p_textvp"]),
    ("task.map",         "task", ["map"]),
    ("task.bsd_info",    "task", ["bsd_info"]),
    ("task.itk_space",   "task", ["itk_space"]),
    ("ucred.uid",        "ucred", ["cr_posix.cr_uid", "cr_uid"]),
    ("ucred.ruid",       "ucred", ["cr_posix.cr_ruid", "cr_ruid"]),
    ("ucred.svuid",      "ucred", ["cr_posix.cr_svuid", "cr_svuid"]),
    ("ucred.groups",     "ucred", ["cr_posix.cr_groups", "cr_groups"]),
    ("ucred.label",      "ucred", ["cr_label"]),
    ("filedesc.fd_ofiles",  "filedesc", ["fd_ofiles", "fd_ofiles_start"]),
    ("filedesc.fd_lastfile","filedesc", ["fd_lastfile"]),
    ("filedesc.fd_nfiles",  "filedesc", ["fd_nfiles"]),
    ("fileproc.fglob",   "fileproc", ["fp_glob", "f_fglob"]),
    ("fileproc.flags",   "fileproc", ["fp_flags", "f_flags"]),
    ("fileglob.fg_ops",  "fileglob", ["fg_ops"]),
    ("fileglob.fg_data", "fileglob", ["fg_data"]),
    ("fileglob.fg_flag", "fileglob", ["fg_flag"]),
    ("fileglob.fg_count","fileglob", ["fg_count"]),
    ("pmap.tte",         "pmap", ["tte"]),
    ("vnode.v_usecount", "vnode", ["v_usecount"]),
    ("vnode.v_data",     "vnode", ["v_data"]),
    ("ipc_port.ip_kobject", "ipc_port", ["ip_kobject"]),
]

def load_globals():
    out = {}
    gdir = os.path.join(OUT, "globals")
    for f in os.listdir(gdir):
        if f.endswith(".json"):
            d = json.load(open(os.path.join(gdir, f)))
            key = f[:-5].replace("kernelcache_", "")   # t8010_10.3.3_14G60
            out[key] = d
    return out

def main():
    tag_map = json.load(open(os.path.join(BASE, "xnu_tag_map.json")))
    structs_cache = {}
    def structs_for(xnu_ver):
        ent = tag_map.get(xnu_ver)
        if not ent or not ent["tag"]:
            return None, None, None
        tag = ent["tag"]
        if tag not in structs_cache:
            p = os.path.join(OUT, "structs", f"{tag}.json")
            structs_cache[tag] = json.load(open(p)) if os.path.exists(p) else None
        d = structs_cache[tag]
        return (d["structs"], ent["exact"], d.get("probe_arch")) if d else (None, ent["exact"], None)

    globals_ = load_globals()
    rows, full, problems = [], {}, []
    with open(os.path.join(BASE, "key_targets.csv")) as f:
        for t in csv.DictReader(f):
            plat, ver, bid = t["platform"], t["version"], t["buildid"]
            key = f"{plat}_{ver}_{bid}"
            g = globals_.get(key)
            row = {"platform": plat, "ios_version": ver, "buildid": bid,
                   "device": t.get("example_device", ""), "identifier": t.get("identifier", "")}
            entry = {"device": t.get("example_device",""), "identifier": t.get("identifier",""),
                     "globals": None, "structs": None, "xnu_tag": None, "tag_exact": None}
            xnu_ver = None
            if g:
                xnu_ver = g.get("xnu_version")
                kb = int(g["kernel_base"], 16)
                def off(name):
                    v = g.get(name)
                    return hex(v - kb) if isinstance(v, int) else (
                        hex(int(g[name.replace('_off','')], 16) - kb) if g.get(name.replace('_off','')) else None)
                row.update({
                    "kernel_base": g["kernel_base"],
                    "xnu_version": xnu_ver,
                    "version_string_off": g.get("version_off"),
                    "allproc_off": g.get("allproc_off"),
                    "kernproc_off": g.get("kernproc_off"),
                })
                entry["globals"] = g
            else:
                problems.append(f"{key}: 缺 globals 分析结果")
            structs, exact, arch = structs_for(xnu_ver) if xnu_ver else (None, None, None)
            entry["xnu_tag"] = tag_map.get(xnu_ver, {}).get("tag") if xnu_ver else None
            entry["tag_exact"] = exact
            if structs:
                entry["structs"] = structs
                entry["probe_arch"] = arch
                for col, sname, chain in COLUMNS:
                    members = structs.get(sname, {})
                    val = None
                    for mname in chain:
                        if mname in members:
                            val = members[mname]
                            break
                    row[col] = hex(val) if val is not None else ""
                if arch == "x86_64":
                    row["note"] = "结构体来自 x86_64 探针(该版 arm 源未发布, LP64 布局一致)"
            else:
                for col, _, _ in COLUMNS:
                    row[col] = ""
                if xnu_ver:
                    problems.append(f"{key}: xnu-{xnu_ver} 无结构体数据")
            full[key] = entry
            rows.append(row)

    fields = ["platform", "ios_version", "buildid", "device", "identifier",
              "kernel_base", "xnu_version", "version_string_off", "allproc_off", "kernproc_off"] \
             + [c for c, _, _ in COLUMNS] + ["note"]
    for r in rows:
        r.setdefault("note", "")
    with open(os.path.join(OUT, "offsets.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(OUT, "offsets.json"), "w") as f:
        json.dump(full, f, indent=1, sort_keys=True)

    # ---- 验证 ----
    n_allproc = sum(1 for r in rows if r.get("allproc_off"))
    n_kernproc = sum(1 for r in rows if r.get("kernproc_off"))
    n_pid = sum(1 for r in rows if r.get("proc.p_pid"))
    report = ["# 偏移表验证报告", "",
              f"- 内核总数: {len(rows)}",
              f"- allproc 找到: {n_allproc}/{len(rows)}",
              f"- kernproc 找到: {n_kernproc}/{len(rows)}",
              f"- proc.p_pid: {n_pid}/{len(rows)}", ""]
    # p_pid 合理性: 应 < 0x100
    bad = [r for r in rows if r.get("proc.p_pid") and int(r["proc.p_pid"], 16) >= 0x100]
    if bad:
        report.append(f"⚠ p_pid >= 0x100 可疑: {[r['platform']+'_'+r['ios_version'] for r in bad]}")
    # 同 xnu 版本跨平台结构体一致性(同源必同)
    report.append("")
    report.append("## 缺失/异常明细")
    report += [f"- {p}" for p in problems] or ["- 无"]
    with open(os.path.join(OUT, "verify_report.md"), "w") as f:
        f.write("\n".join(report) + "\n")
    print(f"rows={len(rows)} allproc={n_allproc} kernproc={n_kernproc} p_pid={n_pid}")
    print(f"问题 {len(problems)} 条" + (": " + "; ".join(problems[:8]) if problems else ""))

if __name__ == "__main__":
    main()
