#!/usr/bin/env python3
"""Revision scan driver. Produces every number the revised paper reports from
the external corpus, in ropkit-compatible CSVs, from yara CLI output.

Arms:
  orig    - rules as printed in paper-v3 (verification of the old Table VIII)
  v4      - corrected rule set (the rules the revised paper ships)
  pattern - v4 minus the entropy-gated tracks (two-track ablation arm)
"""
import csv, hashlib, os, subprocess, sys

ROOT = "/home/dogsploit/Cyber/Malwares/stealers/SRIDE"
REV = os.path.join(ROOT, "research/validation/revision")
OLDCSV = os.path.join(ROOT, "research/validation/corpus_results.csv")
RULES = {
    "orig": os.path.join(ROOT, "research/rules/sride_paper_rules.yar"),
    "v4": os.path.join(REV, "rules_v4.yar"),
    "pattern": os.path.join(REV, "rules_v4_pattern_only.yar"),
}
GENERIC_V4 = "ROP_Structural_Dispatch_Generic"
GENERIC_ORIG = "ROP_Shellcode_Dropper_Generic"

def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(65536), b""):
            h.update(c)
    return h.hexdigest()

# file set: everything under corpus/samples and corpus/clean
files = []
for sub in ("samples", "clean"):
    d = os.path.join(ROOT, "research/corpus", sub)
    for fn in sorted(os.listdir(d)):
        p = os.path.join(d, fn)
        if os.path.isfile(p):
            files.append(p)

# family + packed from the recorded CSV, keyed by basename
meta = {}
with open(OLDCSV, newline="") as f:
    for r in csv.DictReader(f):
        meta[r["file"]] = r

def scan(rulefile, targets):
    """returns {path: [rules matched]}"""
    out = {}
    for t in targets:
        r = subprocess.run(["yara", "-f", rulefile, t],
                           capture_output=True, text=True, timeout=300)
        hits = [ln.split()[0] for ln in r.stdout.splitlines() if ln.strip()]
        out[t] = hits
    return out

results = {arm: scan(rf, files) for arm, rf in RULES.items()}

# ---- arm comparison CSV in audit_arms format (external corpus) ----
with open(os.path.join(REV, "external_ablation.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["sha256", "family", "file", "packed", "hit_nofilter", "hit_withfilter"])
    for p in files:
        base = os.path.basename(p)
        m = meta.get(base, {})
        nofilt = bool(results["pattern"][p])
        withfilt = bool(results["v4"][p])
        w.writerow([sha256(p), m.get("family", "clean" if "/clean/" in p else "?"),
                    base, m.get("packed", "0"), int(nofilt), int(withfilt)])

# ---- per-rule detail for the revised external table ----
with open(os.path.join(REV, "external_rules_v4.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["sha256", "family", "file", "packed", "gen_v4", "fam_v4",
                "gen_orig", "fam_orig"])
    fam_rules_orig = {"AsyncRAT_ROP_ProcessHollow", "NjRAT_ROP_ShellcodeStage",
                      "Custom_C2_ROP_Syscall_64", "BankTrojan_BR_UPX_Packed",
                      "BankTrojan_BR_Payload_ROPHook"}
    for p in files:
        base = os.path.basename(p)
        m = meta.get(base, {})
        o, v = results["orig"][p], results["v4"][p]
        w.writerow([sha256(p), m.get("family", "clean" if "/clean/" in p else "?"),
                    base, m.get("packed", "0"),
                    int(GENERIC_V4 in v),
                    ",".join(sorted(set(v) - {GENERIC_V4})),
                    int(GENERIC_ORIG in o),
                    ",".join(sorted(set(o) & fam_rules_orig))])

# ---- verification: orig arm vs recorded A_paper column ----
mismatch = 0
for p in files:
    base = os.path.basename(p)
    if base not in meta:
        continue
    recorded = set(filter(None, meta[base]["A_paper"].split(",")))
    got = set(results["orig"][p])
    if recorded != got:
        mismatch += 1
        print(f"DIFF {base}: recorded={sorted(recorded)} got={sorted(got)}")
print(f"\nfiles scanned: {len(files)}; orig-arm mismatches vs corpus_results.csv: {mismatch}")

# quick tallies for the v4 arm
def tally(arm):
    gen = fam = 0
    for p in files:
        if "/clean/" in p:
            continue
        hits = results[arm][p]
        g = GENERIC_V4 in hits if arm != "orig" else GENERIC_ORIG in hits
        if g: gen += 1
        if set(hits) - {GENERIC_V4, GENERIC_ORIG}: fam += 1
    return gen, fam

for arm in RULES:
    g, fm = tally(arm)
    print(f"{arm:8} malware files: generic-rule hits={g}, family-rule hits={fm}")
for p in files:
    if "/clean/" in p:
        print(f"clean {os.path.basename(p):20} v4={results['v4'][p]} orig={results['orig'][p]}")
