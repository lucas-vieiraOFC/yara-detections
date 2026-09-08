#!/usr/bin/env python3
"""v5 scan driver. Produces every number the v5 rule set reports from the
external corpus, from yara CLI output, and checks YARA/YARA-X agreement.

Sets scanned:
  corpus   - corpus/samples + corpus/clean (59 files; the paper's Table V set)
  nulls    - revision/null/{shuffled,random,entropy} (9 files)
  controls - revision/controls/chain{3,4,5,8,orig}.exe (5 synthetic chains)

Outputs:
  external_rules_v5.csv  per-file rule hits for the corpus set
  stdout                 tallies used in the paper text
"""
import csv, hashlib, os, subprocess, sys

ROOT = "/home/dogsploit/Cyber/Malwares/stealers/SRIDE"
REV = os.path.join(ROOT, "research/validation/revision")
OLDCSV = os.path.join(ROOT, "research/validation/corpus_results.csv")
RULES_V5 = os.path.join(ROOT, "research/rules/sride_rules_v5.yar")
YR = os.path.join(REV, "yr")
GENERIC = "ROP_Structural_Dispatch_Generic"

def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(65536), b""):
            h.update(c)
    return h.hexdigest()

def collect(subdirs):
    files = []
    for sub in subdirs:
        d = os.path.join(ROOT, "research", sub)
        for fn in sorted(os.listdir(d)):
            p = os.path.join(d, fn)
            if os.path.isfile(p):
                files.append(p)
    return files

corpus = collect(["corpus/samples", "corpus/clean"])
nulls = collect(["validation/revision/null/shuffled",
                 "validation/revision/null/random",
                 "validation/revision/null/entropy"])
controls = [os.path.join(REV, "controls", n) for n in
            ("chain3.exe", "chain4.exe", "chain5.exe", "chain8.exe", "chain_orig.exe")]

# family + packed from the recorded CSV, keyed by basename
meta = {}
with open(OLDCSV, newline="") as f:
    for r in csv.DictReader(f):
        meta[r["file"]] = r

def scan_yara(rulefile, targets):
    out = {}
    for t in targets:
        r = subprocess.run(["yara", "-f", rulefile, t],
                           capture_output=True, text=True, timeout=300)
        out[t] = sorted(ln.split()[0] for ln in r.stdout.splitlines() if ln.strip())
    return out

def scan_yarax(rulefile, targets):
    out = {}
    for t in targets:
        r = subprocess.run([YR, "scan", rulefile, t],
                           capture_output=True, text=True, timeout=300)
        hits = []
        for ln in r.stdout.splitlines():
            ln = ln.strip()
            if ln and not ln.startswith("warning") and not ln.startswith(" "):
                hits.append(ln.split()[0])
        out[t] = sorted(hits)
    return out

v5 = scan_yara(RULES_V5, corpus + nulls + controls)
v5x = scan_yarax(RULES_V5, corpus + nulls + controls)

# ---- per-rule detail CSV for the v5 external table ----
with open(os.path.join(REV, "external_rules_v5.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["sha256", "family", "file", "packed", "gen_v5", "fam_v5"])
    for p in corpus:
        base = os.path.basename(p)
        m = meta.get(base, {})
        hits = v5[p]
        w.writerow([sha256(p), m.get("family", "clean" if "/clean/" in p else "?"),
                    base, m.get("packed", "0"),
                    int(GENERIC in hits),
                    ",".join(h for h in hits if h != GENERIC)])

# ---- tallies ----
def tally(files, label):
    gen = fam = 0
    rows = []
    for p in files:
        hits = v5[p]
        g = GENERIC in hits
        fh = [h for h in hits if h != GENERIC]
        gen += g
        fam += bool(fh)
        if hits:
            rows.append(f"    {os.path.basename(p):45} -> {', '.join(hits)}")
    print(f"{label}: {len(files)} files, generic={gen}, family-rule hits={fam}")
    for r in rows:
        print(r)

mal = [p for p in corpus if "/samples/" in p]
cln = [p for p in corpus if "/clean/" in p]
tally(mal, "corpus malware")
tally(cln, "corpus clean")
tally(nulls, "null model")
tally(controls, "synthetic controls")

# per-family-set fam tallies for the table annotations
print("\nper-set fam_v5 detail (malware):")
from collections import defaultdict
byset = defaultdict(lambda: [0, 0, 0])  # n, gen, fam
for p in mal:
    m = meta.get(os.path.basename(p), {})
    s = byset[m.get("family", "?")]
    s[0] += 1
    s[1] += GENERIC in v5[p]
    s[2] += any(h != GENERIC for h in v5[p])
for k in sorted(byset):
    n, g, fm = byset[k]
    print(f"  {k:28} n={n:2} gen={g:2} fam={fm:2}")

# ---- dual-engine agreement ----
mism = 0
for p in corpus + nulls + controls:
    if v5[p] != v5x[p]:
        mism += 1
        print(f"ENGINE-DIFF {os.path.basename(p)}: yara={v5[p]} yr={v5x[p]}")
print(f"\ndual-engine: {len(corpus) + len(nulls) + len(controls)} files, "
      f"mismatches={mism}")
