"""Compare a Bloom filter with a Python set (hash table) on real breached-password hashes.

Usage:
    python src/benchmark.py
Writes results/results.csv
"""

import csv
import hashlib
import math
import sys
import time
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from bloom_filter import BloomFilter, sha1_hex

SIZES = [10_000, 100_000, 1_000_000]
RATES = [0.01, 0.001]
FP_CHECKS = 1_000_000      # hashes NOT in the list, used to measure false positives
TIMING_CHECKS = 100_000    # lookups used to measure speed


def load(n):
    return Path(f"data/hibp_{n}.txt").read_text().split()


def build_set(n):
    return set(load(n))


def build_bloom(n, rate):
    bloom = BloomFilter(n, rate)
    for h in load(n):
        bloom.add(h)
    return bloom


def measure_memory(build):
    """Build a structure while tracemalloc counts every byte it keeps."""
    tracemalloc.start()
    structure = build()
    used, _peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return structure, used


def microseconds_per_check(structure, items):
    start = time.perf_counter()
    for item in items:
        item in structure
    return (time.perf_counter() - start) / len(items) * 1_000_000


def theory_rate(bloom):
    """Expected false-positive rate: (1 - e^(-k*n/m))^k"""
    k, n, m = bloom.num_hashes, bloom.count, bloom.num_bits
    return (1 - math.exp(-k * n / m)) ** k


def main():
    rows = []
    for n in SIZES:
        print(f"\n=== {n:,} breached hashes ===")
        stored = load(n)

        # Python set (hash table)
        table, set_bytes = measure_memory(lambda: build_set(n))
        not_stored = [sha1_hex(f"not-breached-{i}") for i in range(FP_CHECKS)]
        not_stored = [h for h in not_stored if h not in table]   # make sure none are really in the list
        speed = microseconds_per_check(table, stored[:TIMING_CHECKS])
        rows.append([n, "Python set", "", "", set_bytes, 0, 0, 0, round(speed, 3)])
        print(f"  Python set:        {set_bytes / 1e6:8.2f} MB   {speed:.2f} µs per check")

        # Bloom filters
        for rate in RATES:
            bloom, bloom_bytes = measure_memory(lambda: build_bloom(n, rate))
            false_negatives = sum(1 for h in stored if h not in bloom)
            false_positives = sum(1 for h in not_stored if h in bloom)
            measured = false_positives / len(not_stored)
            speed = microseconds_per_check(bloom, stored[:TIMING_CHECKS])
            rows.append([n, f"Bloom filter {rate:.1%}", rate, bloom.num_hashes, bloom_bytes,
                         false_negatives, measured, theory_rate(bloom), round(speed, 3)])
            print(f"  Bloom filter {rate:.1%}: {bloom_bytes / 1e6:8.2f} MB   {speed:.2f} µs per check   "
                  f"k={bloom.num_hashes}   false positives {measured:.3%} (theory {theory_rate(bloom):.3%})   "
                  f"false negatives {false_negatives}")

    Path("results").mkdir(exist_ok=True)
    with open("results/results.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["n", "structure", "target_rate", "hash_functions", "memory_bytes",
                         "false_negatives", "measured_fp_rate", "theory_fp_rate", "microseconds_per_check"])
        writer.writerows(rows)
    print("\nSaved results/results.csv")


if __name__ == "__main__":
    main()