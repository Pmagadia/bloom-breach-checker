import sys
import unittest
from pathlib import Path

# Let the tests find bloom_filter.py in the src folder
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from bloom_filter import BloomFilter, sha1_hex


class BloomFilterTests(unittest.TestCase):

    def test_size_matches_formula(self):
        # Claim 1: 1 million items at 1% needs 9,585,059 bits and 7 hash functions
        b = BloomFilter(1_000_000, 0.01)
        self.assertEqual(b.num_bits, 9_585_059)
        self.assertEqual(b.num_hashes, 7)

    def test_no_false_negatives(self):
        # Claim 2: every password that was added must be found
        b = BloomFilter(5_000, 0.01)
        passwords = [sha1_hex(f"password{i}") for i in range(5_000)]
        for h in passwords:
            b.add(h)
        for h in passwords:
            self.assertIn(h, b)

    def test_false_positive_rate_near_target(self):
        # Claim 3: add 20,000 passwords, check 100,000 that were never added,
        # and about 1% should wrongly come back as "found"
        b = BloomFilter(20_000, 0.01)
        for i in range(20_000):
            b.add(sha1_hex(f"stored{i}"))
        wrong = sum(sha1_hex(f"never-added{i}") in b for i in range(100_000))
        rate = wrong / 100_000
        print(f"\n  measured false-positive rate: {rate:.3%}")
        self.assertGreater(rate, 0.005)   # at least 0.5%
        self.assertLess(rate, 0.015)      # at most 1.5%

    def test_sha1_matches_have_i_been_pwned(self):
        # Our hashes must match the format Have I Been Pwned uses
        self.assertEqual(sha1_hex("password"), "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8")


if __name__ == "__main__":
    unittest.main()