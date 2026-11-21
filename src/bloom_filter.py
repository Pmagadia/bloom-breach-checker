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