"""Interactive demo: check a password against the breached-password Bloom filter.

The benchmark sample is 1 million hashes picked at random from about 2 billion, so a
famous password like "password" is probably not in it. For the demo, the full Have I
Been Pwned ranges for a few well-known passwords are added on top of the sample, so
the filter catches them the way a real checker would.

Usage:
    python src/check_password.py
The password you type is hashed on this computer. It is never sent anywhere or saved.
"""

import getpass
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from bloom_filter import BloomFilter, sha1_hex
from collect_hashes import fetch_range

DATA_FILE = "data/hibp_1000000.txt"
TARGET_RATE = 0.001
COMMON_PASSWORDS = ["password", "123456", "qwerty", "letmein", "iloveyou",
                    "admin", "welcome", "monkey", "dragon", "football"]


def main():
    start = time.perf_counter()
    hashes = Path(DATA_FILE).read_text().split()

    # Only the first 5 characters of each hash are sent, so the service never learns the password
    for password in COMMON_PASSWORDS:
        hashes.extend(fetch_range(sha1_hex(password)[:5]))

    bloom = BloomFilter(len(hashes), TARGET_RATE)
    for h in hashes:
        bloom.add(h)
    seconds = time.perf_counter() - start
    print(f"Loaded {bloom.count:,} breached password hashes into a {len(bloom.bits) / 1e6:.2f} MB "
          f"Bloom filter (k={bloom.num_hashes}, {TARGET_RATE:.1%} target) in {seconds:.1f} seconds.")
    print("Type a password to check it. Your typing stays hidden. Press Enter on a blank line to quit.\n")

    while True:
        password = getpass.getpass("Password: ")
        if not password:
            break
        start = time.perf_counter()
        found = sha1_hex(password) in bloom
        micros = (time.perf_counter() - start) * 1_000_000
        if found:
            print(f"  BREACHED: this password is on the breach list. Pick a different one. ({micros:.0f} µs)")
        else:
            print(f"  Not found on the breach list. ({micros:.0f} µs)")


if __name__ == "__main__":
    main()