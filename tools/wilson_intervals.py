#!/usr/bin/env python3
"""Wilson score interval code used for every confidence interval in the paper
"Structural ROP Invariants for Static Malware Triage" (Freitas Vieira &
Olivera, Computers & Security submission).

Self-test (run: python3 tools/wilson_intervals.py --test) recomputes every
interval printed in the paper and in supplementary section S.4 and asserts the
rounded values match, so a reader can confirm the printed intervals come from
this formula with z = 1.96.
"""

import math
import sys


def wilson(k, n, z=1.96):
    """Two-sided Wilson score interval, returned as (low, high) in percent,
    rounded to one decimal."""
    if not 0 <= k <= n or n == 0:
        raise ValueError("require 0 <= k <= n and n > 0")
    p = k / n
    z2 = z * z
    denom = 1 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / denom
    low = max(0.0, round(100 * (center - half), 1))
    high = min(100.0, round(100 * (center + half), 1))
    return (low, high)


def wilson_upper(k, n, z=1.96):
    """One-sided 95% upper bound in percent, rounded to one decimal.
    Equal to the upper end of the two-sided Wilson interval for the
    '95% upper bound' statements used in the paper."""
    return wilson(k, n, z)[1]


# Every Wilson interval printed in the paper, its supplementary material, and
# the repository's run record (RESULTS.md). Tuple: (k, n, point, low, high);
# `point` is a printed point estimate (S.4 table format "point [low, high]")
# or None where only the interval is printed. Percentages as printed.
PRINTED_INTERVALS = [
    # Supplementary S.4 development fitting table
    (44, 50, 88.0, 76.2, 94.4),
    (48, 50, 96.0, 86.5, 98.9),
    (30, 30, 100.0, 88.6, 100.0),
    (9, 10, 90.0, 59.6, 98.2),
    (20, 20, 100.0, 83.9, 100.0),
    (18, 20, 90.0, 69.9, 97.2),
    (169, 180, 93.9, 89.4, 96.6),
    # Section 7.4 external held-out evaluation
    (44, 70, None, 51.1, 73.2),
    (46, 70, None, 54.0, 75.8),
    # Section 7.5 null model
    (32, 33, None, 84.7, 99.5),
    (33, 33, None, 89.6, 100.0),
    (98, 99, None, 94.5, 99.8),
    # Section 7.6 entropy ablation
    (0, 16, None, 0.0, 19.4),      # RESULTS.md run record (v4-era arm)
    (0, 20, None, 0.0, 16.1),
    # Section 7.7 indicator baseline and decay (Table 2 era bins)
    (8, 70, None, 5.9, 21.0),
    (5, 5, None, 56.6, 100.0),
    (1, 5, None, 3.6, 62.4),
    (24, 45, None, 39.1, 67.1),
    (6, 45, None, 6.3, 26.2),
    (9, 11, None, 52.3, 94.9),
    (1, 11, None, 1.6, 37.7),
    (6, 9, None, 35.4, 87.9),
    (0, 9, None, 0.0, 29.9),
    # v4-era corpus figures retained in RESULTS.md
    (34, 56, None, 47.6, 72.4),
    (7, 56, None, 6.2, 23.6),
    # Section 7.8 verifier results
    (0, 73, None, 0.0, 5.0),
    (0, 59, None, 0.0, 6.1),       # RESULTS.md run record (v4-era corpus)
]


def self_test():
    failures = 0
    for k, n, point, low, high in PRINTED_INTERVALS:
        comp_low, comp_high = wilson(k, n)
        ok = (comp_low == low) and (comp_high == high)
        if point is not None:
            comp_point = round(100 * k / n, 1)
            ok = ok and (comp_point == point)
        label = f"{k}/{n}"
        printed = ("{:.1f} ".format(point) if point is not None else "") + \
                  "[{:.1f}, {:.1f}]".format(low, high)
        if not ok:
            failures += 1
        print(f"{'PASS' if ok else 'FAIL'}  {label:>8}  printed {printed}  "
              f"recomputed [{comp_low}, {comp_high}]")
    print()
    if failures:
        print(f"SELF-TEST FAILED: {failures} interval(s) do not reproduce.")
        return 1
    print(f"SELF-TEST PASSED: all {len(PRINTED_INTERVALS)} printed intervals "
          "reproduce exactly at one-decimal rounding.")
    return 0


if __name__ == "__main__":
    if "--test" in sys.argv:
        sys.exit(self_test())
    print(__doc__)
