#!/usr/bin/env python3
"""run_corpus_scan.py — corpus evaluation driver for the SRIDE study.

Scans every corpus file with each rule set, computes per-section entropy
(packed flag), and writes:
  - corpus_results.csv  (file, family, size, packed, matches per ruleset)
  - prints a per-family summary matrix to stdout.

Rule sets (paths relative to research/):
  A: rules/sride_paper_rules_corrected.yar   (the six rules printed in the paper)
  B: rules/sride_stealer.yar                 (expanded in-house rule set)
"""
import csv, math, os, subprocess, sys

import pefile

ROOT = os.path.dirname(os.path.abspath(__file__))          # research/validation
R = os.path.dirname(ROOT)                                  # research/
RULESETS = {
    "A_paper": os.path.join(R, "rules", "sride_paper_rules_corrected.yar"),
    "B_expanded": os.path.join(R, "rules", "sride_stealer.yar"),
}

# (family_label, path) — paths relative to research/
TARGETS = []
S = os.path.join(R, "corpus", "samples")
for f in sorted(os.listdir(S)):
    TARGETS.append((f.split("__")[0], os.path.join(S, f)))
C = os.path.join(R, "corpus", "clean")
for f in sorted(os.listdir(C)):
    TARGETS.append(("CLEAN", os.path.join(C, f)))
# the four in-repo stealer families (controls with known ground truth)
REPO = os.path.dirname(os.path.dirname(R))                 # stealers/
for label, rel in [
    ("Myth",      "mythstealer/55a418f8562684607ee0acd745595e297ab7e586d0a5d3f8328643b29c72dfa2.exe"),
    ("Myth",      "mythstealer/decrypted_payload.dll"),
    ("Prysmax",   "prysmaxstealer/rustystealer.exe"),
    ("Snowflake", "snowflakestealer/stealer.exe"),
    ("Snowflake", "snowflakestealer/payload_v2.bin"),
    ("Snowflake", "snowflakestealer/stage3_decompressed.bin"),
    ("CLEAN",     None),  # placeholder for /bin/ls added below
]:
    if rel is None:
        TARGETS.append(("CLEAN", "/bin/ls"))
    else:
        TARGETS.append((label, os.path.join(REPO, rel)))


def max_section_entropy(path):
    try:
        pe = pefile.PE(path, fast_load=True)
    except Exception:
        return None
    best = 0.0
    for sec in pe.sections:
        data = sec.get_data()
        if not data:
            continue
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        h = -sum((c / len(data)) * math.log2(c / len(data)) for c in freq if c)
        best = max(best, h)
    return best


def scan(rules, path):
    try:
        out = subprocess.run(
            ["yara", "--no-warnings", rules, path],
            capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    if out.returncode != 0:
        return "ERROR"
    return ",".join(sorted({ln.split()[0] for ln in out.stdout.splitlines() if ln.strip()}))


def main():
    rows = []
    for fam, path in TARGETS:
        ent = max_section_entropy(path)
        row = {
            "family": fam,
            "file": os.path.basename(path),
            "size": os.path.getsize(path),
            "max_section_entropy": f"{ent:.2f}" if ent is not None else "n/a",
            "packed": ("1" if (ent is not None and ent > 7.0) else "0"),
        }
        for key, rules in RULESETS.items():
            row[key] = scan(rules, path)
        rows.append(row)
        print(f"[{len(rows):3d}/{len(TARGETS)}] {fam:24s} {row['file'][:44]:44s} "
              f"H={row['max_section_entropy']:>5s} A={row['A_paper'] or '-'} B={row['B_expanded'] or '-'}")
    csv_path = os.path.join(ROOT, "corpus_results.csv")
    with open(csv_path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print("\nwrote", csv_path)

    # per-family summary
    fams = {}
    for r in rows:
        d = fams.setdefault(r["family"], {"n": 0, "packed": 0, "A": 0, "B": 0})
        d["n"] += 1
        d["packed"] += int(r["packed"])
        d["A"] += bool(r["A_paper"] and r["A_paper"] not in ("ERROR", "TIMEOUT"))
        d["B"] += bool(r["B_expanded"] and r["B_expanded"] not in ("ERROR", "TIMEOUT"))
    print(f"\n{'family':26s}{'n':>4s}{'packed':>7s}{'A_hits':>7s}{'B_hits':>7s}")
    for fam, d in sorted(fams.items()):
        print(f"{fam:26s}{d['n']:>4d}{d['packed']:>7d}{d['A']:>7d}{d['B']:>7d}")


if __name__ == "__main__":
    sys.exit(main())
