# Bloom Filter Breached-Password Checker

CS 469 project by Peterson Magadia. This repo tests how data structures from outside the course handle real
cybersecurity tasks:

- **Bloom filter:** checks passwords against a list of known breached passwords from
  [Have I Been Pwned](https://haveibeenpwned.com/Passwords), compared with a Python set (hash table).
- **Binary trie / radix tree:** matches IP addresses to firewall rules by longest prefix, compared with a plain list.

NIST SP 800-63B-4 says new passwords should be checked against a list of passwords from previous breaches.
A Bloom filter does that check in a small fraction of the memory a hash table needs, in exchange for a small,
predictable chance of flagging a safe password.

## Files

| File | What it does |
| --- | --- |
| `src/bloom_filter.py` | The Bloom filter: sizing from Bloom's formulas, double hashing (Kirsch & Mitzenmacher, 2008), add and check |
| `src/collect_hashes.py` | Downloads a random sample of breached password hashes using the Pwned Passwords range service |
| `src/benchmark.py` | Measures memory, lookup time, false positives, and false negatives for the set and the Bloom filter |
| `src/plot_results.py` | Draws the charts in `results/` |
| `src/ip_trie.py` | Firewall rule lookup with a trie, a radix node count, and a scale test against a list |
| `src/check_password.py` | Interactive demo: type a password and see if it is on the breach list |
| `tests/test_bloom_filter.py` | Tests for sizing, no false negatives, false-positive rate, and hash format |

## How to run

```
pip install -r requirements.txt
python -m unittest discover -s tests -v
python src/collect_hashes.py      # about 500 requests, under a minute
python src/benchmark.py           # 1 to 2 minutes
python src/plot_results.py
python src/ip_trie.py
python src/check_password.py
```

The `data/` folder is not uploaded because the files are large. `collect_hashes.py` recreates it.

## Results so far (1,000,000 real breached hashes)

| Structure | Memory | False-positive rate (theory) | False negatives | Time per check |
| --- | --- | --- | --- | --- |
| Python set (hash table) | 114.55 MB | 0% | 0 | 0.15 µs |
| Bloom filter, 1% target | 1.20 MB | 1.021% (1.004%) | 0 | 3.17 µs |
| Bloom filter, 0.1% target | 1.80 MB | 0.096% (0.100%) | 0 | 3.79 µs |

The Bloom filter used 64 to 95 times less memory and never missed a breached password. The Python set was faster
per check because it is built into Python and written in C, while this Bloom filter is plain Python.

## Privacy

The range service only receives the first 5 characters of a password's SHA-1 hash, so it never sees the password
or the full hash. The demo hashes passwords on your own computer and does not save or send them.