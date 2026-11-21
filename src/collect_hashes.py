"""Download a random sample of breached password hashes from Have I Been Pwned.

Usage:
    python src/collect_hashes.py
Writes data/hibp_10000.txt, data/hibp_100000.txt, data/hibp_1000000.txt
"""

import random
import time
import urllib.request
from pathlib import Path

URL = "https://api.pwnedpasswords.com/range/"
TARGET = 1_000_000
SUBSETS = [10_000, 100_000, 1_000_000]


def fetch_range(prefix):
    """Get every breached hash that starts with this 5-character prefix."""
    request = urllib.request.Request(URL + prefix, headers={"User-Agent": "cs469-bloom-filter-demo"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                text = response.read().decode("utf-8")
            break
        except Exception as error:
            print(f"  retrying {prefix} after error: {error}")
            time.sleep(2)
    else:
        return []  # gave up on this prefix after 3 tries

    hashes = []
    for line in text.splitlines():
        suffix, count = line.strip().split(":")
        if int(count) > 0:              # count 0 lines are padding, not real hashes
            hashes.append(prefix + suffix)
    return hashes


def main():
    rng = random.Random(469)            # fixed seed, so the sample can be repeated
    all_prefixes = [f"{n:05X}" for n in range(16 ** 5)]   # 00000 to FFFFF
    rng.shuffle(all_prefixes)           # random order spreads the sample across the whole list

    collected = []
    started = time.time()
    for i, prefix in enumerate(all_prefixes, start=1):
        collected.extend(fetch_range(prefix))
        if i % 50 == 0:
            print(f"  {len(collected):,} hashes from {i} requests")
        if len(collected) >= TARGET:
            break

    rng.shuffle(collected)
    Path("data").mkdir(exist_ok=True)
    for n in SUBSETS:
        path = Path("data") / f"hibp_{n}.txt"
        path.write_text("\n".join(collected[:n]) + "\n")
        print(f"Wrote {n:,} hashes to {path}")
    print(f"Done in {time.time() - started:.0f} seconds after {i} requests")


if __name__ == "__main__":
    main()