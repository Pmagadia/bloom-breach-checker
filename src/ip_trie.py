"""Firewall-style IP address lookup with a binary trie (longest-prefix match).

A firewall rule applies to a range of addresses written as a prefix, like 10.20.0.0/16
(every address whose first 16 bits match 10.20). When several rules match, the most
specific one wins: the one with the longest prefix. A trie finds it by walking the
address one bit at a time, so a lookup takes at most 32 steps for IPv4, no matter how
many rules there are. A radix tree (PATRICIA; Morrison, 1968) is the same idea with
chains of single-child nodes merged into one, which saves memory.

Usage:
    python src/ip_trie.py
"""

import ipaddress
import random
import time


class Node:
    def __init__(self):
        self.children = [None, None]   # child for bit 0, child for bit 1
        self.rule = None               # set when a prefix ends at this node


class IPTrie:
    def __init__(self):
        self.root = Node()
        self.node_count = 1

    def insert(self, prefix, action, reason):
        network = ipaddress.ip_network(prefix)
        address_bits = int(network.network_address)
        node = self.root
        for i in range(network.prefixlen):
            bit = (address_bits >> (31 - i)) & 1    # the i-th bit, counting from the left
            if node.children[bit] is None:
                node.children[bit] = Node()
                self.node_count += 1
            node = node.children[bit]
        node.rule = (prefix, action, reason)

    def lookup(self, address):
        """Return the most specific matching rule and how many steps it took."""
        address_bits = int(ipaddress.ip_address(address))
        node = self.root
        best = node.rule        # a 0.0.0.0/0 default rule sits at the root
        steps = 0
        for i in range(32):
            node = node.children[(address_bits >> (31 - i)) & 1]
            if node is None:
                break           # no longer prefix exists down this path
            steps += 1
            if node.rule is not None:
                best = node.rule    # a longer (more specific) match
        return best, steps

    def radix_node_count(self):
        """How many nodes a radix tree would keep. It merges every node that has one child and
        no rule into its child, so only branch points and rule endpoints remain."""
        count, stack = 0, [self.root]
        while stack:
            node = stack.pop()
            kids = [c for c in node.children if c is not None]
            if node is self.root or node.rule is not None or len(kids) == 2:
                count += 1
            stack.extend(kids)
        return count


def parse_rules(rules):
    """Turn each prefix string into a network object once, so the list lookup is a fair test."""
    return [(ipaddress.ip_network(prefix), action, reason) for prefix, action, reason in rules]


def linear_lookup(parsed_rules, address):
    """The simple way: check every rule in a list and keep the longest match."""
    ip = ipaddress.ip_address(address)
    best, best_length, checked = None, -1, 0
    for network, action, reason in parsed_rules:
        checked += 1
        if ip in network and network.prefixlen > best_length:
            best, best_length = (str(network), action, reason), network.prefixlen
    return best, checked


# Example rules. The addresses are private ranges and the ranges reserved for documentation,
# not real networks.
RULES = [
    ("0.0.0.0/0", "ALLOW", "default: internet traffic"),
    ("10.0.0.0/8", "ALLOW", "company internal network"),
    ("10.20.0.0/16", "DENY", "guest Wi-Fi cannot reach servers"),
    ("10.20.5.0/24", "ALLOW", "IT staff on the guest floor"),
    ("192.0.2.0/24", "DENY", "known malicious range"),
    ("198.51.100.0/24", "DENY", "known malicious range"),
    ("203.0.113.128/25", "DENY", "botnet command servers"),
]

TEST_ADDRESSES = ["10.1.2.3", "10.20.9.9", "10.20.5.7", "192.0.2.44", "203.0.113.200", "203.0.113.5", "8.8.8.8"]


def main():
    trie = IPTrie()
    for rule in RULES:
        trie.insert(*rule)
    parsed = parse_rules(RULES)

    print(f"Loaded {len(RULES)} firewall rules into a trie with {trie.node_count} nodes\n")
    print(f"{'Address':<15} {'Matched rule':<18} {'Action':<6} {'Reason':<34} {'Trie steps':>10} {'List checks':>11}")
    print("-" * 99)
    for address in TEST_ADDRESSES:
        (prefix, action, reason), steps = trie.lookup(address)
        linear_rule, checked = linear_lookup(parsed, address)
        assert linear_rule[0] == prefix, "trie and list disagree"
        print(f"{address:<15} {prefix:<18} {action:<6} {reason:<34} {steps:>10} {checked:>11}")
    print(f"\nA radix tree would merge the single-child chains: {trie.node_count} nodes become "
          f"{trie.radix_node_count()}.")

    scale_test()


def scale_test(lookups=1_000, seed=469):
    """With 7 rules the list is fine. Real firewalls and routers have thousands of rules."""
    rng = random.Random(seed)
    addresses = [str(ipaddress.ip_address(rng.getrandbits(32))) for _ in range(lookups)]
    print(f"\nScale test: average time per lookup over {lookups:,} random addresses")
    print(f"{'Rules':>8} {'Trie (µs)':>10} {'List (µs)':>10} {'Most trie steps':>16} {'List checks':>12}")
    print("-" * 60)
    for count in [10, 100, 1_000, 10_000]:
        rules = [("0.0.0.0/0", "ALLOW", "default")]
        for _ in range(count - 1):
            length = rng.randint(8, 24)
            network = ipaddress.ip_network((rng.getrandbits(32) >> (32 - length) << (32 - length), length))
            rules.append((str(network), "DENY", "random rule"))
        trie = IPTrie()
        for rule in rules:
            trie.insert(*rule)

        # Run each timing several times and keep the fastest, so background noise doesn't skew it
        trie_runs = []
        for _ in range(5):
            start = time.perf_counter()
            most_steps = max(trie.lookup(a)[1] for a in addresses)
            trie_runs.append((time.perf_counter() - start) / lookups * 1e6)
        trie_us = min(trie_runs)

        parsed = parse_rules(rules)
        list_runs = []
        for _ in range(3):
            start = time.perf_counter()
            for a in addresses:
                linear_lookup(parsed, a)
            list_runs.append((time.perf_counter() - start) / lookups * 1e6)
        list_us = min(list_runs)
        print(f"{count:>8,} {trie_us:>10.1f} {list_us:>10.1f} {most_steps:>16} {count:>12,}")


if __name__ == "__main__":
    main()