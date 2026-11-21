import hashlib
import math


class BloomFilter:
    def __init__(self, expected_items, false_positive_rate):
        n = expected_items
        p = false_positive_rate

        # m: how many bits the filter needs
        self.num_bits = math.ceil(-n * math.log(p) / (math.log(2) ** 2))

        # k: how many hash functions to use
        self.num_hashes = max(1, round(self.num_bits / n * math.log(2)))

        # The bits themselves. A bytearray stores 8 bits per byte, so divide by 8 and round up.
        self.bits = bytearray((self.num_bits + 7) // 8)

        # How many items have been added
        self.count = 0

    def _positions(self, item):
        # One hash, split into two numbers (Kirsch & Mitzenmacher, 2008)
        digest = hashlib.blake2b(item.encode("utf-8"), digest_size=16).digest()
        h1 = int.from_bytes(digest[:8], "little")
        h2 = int.from_bytes(digest[8:], "little") | 1   # "| 1" makes h2 odd so positions don't repeat
        return [(h1 + i * h2) % self.num_bits for i in range(self.num_hashes)]

    def add(self, item):
        for pos in self._positions(item):
            byte = pos // 8          # which byte holds this bit
            bit = pos % 8            # which bit inside that byte
            self.bits[byte] |= (1 << bit)   # turn that bit on
        self.count += 1

    def __contains__(self, item):
        for pos in self._positions(item):
            byte = pos // 8
            bit = pos % 8
            if not self.bits[byte] & (1 << bit):   # this bit is off
                return False                        # so it was never added
        return True                                 # all bits on, so probably added


def sha1_hex(password):
    # Hash a password the way Have I Been Pwned stores it: uppercase SHA-1
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()