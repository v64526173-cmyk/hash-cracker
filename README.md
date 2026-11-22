# 🔓 Hash Cracker

[![CI](https://github.com/YOUR_USERNAME/hash-cracker/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/hash-cracker/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A from-scratch, multiprocessing hash-cracking toolkit built to understand
**why** MD5/SHA1/unsalted-SHA256 are unsafe for password storage, and what
properly designed password hashing (bcrypt/scrypt/argon2) protects against.

Built as an offensive-security portfolio project — implements dictionary
attacks, brute-force attacks, salted-hash cracking, batch cracking of
multiple hashes in a single pass, and CPU-parallel performance scaling.

> ⚠️ **Authorized use only.** This tool is for CTFs, security education,
> and penetration testing engagements where you have explicit permission
> to test the target. See [`docs/SECURITY_NOTES.md`](docs/SECURITY_NOTES.md)
> for scope and legal/ethical context.

---

## Features

- ✅ **MD5 / SHA1 / SHA256** hash generation and cracking
- ✅ **Dictionary attack** against any wordlist file
- ✅ **Brute-force attack** with configurable charset (lower/upper/digits/
  special/custom) and length range, implemented with lazy generators so
  memory use stays flat regardless of search-space size
- ✅ **Salted hash support** (append or prepend salt position)
- ✅ **Batch cracking** — check a whole file of leaked hashes against the
  wordlist in a single pass, instead of re-scanning per hash
- ✅ **Multiprocessing** across all CPU cores, with live progress
  reporting (hashes/sec, elapsed time, found count)
- ✅ Clean, tested, type-hinted Python package with a real CLI
  (`python -m hashcracker ...`)

## Why this project

Most "hello world" security projects just call `hashlib.md5()` in a loop.
This one is built to actually demonstrate the concepts an internship
interviewer would want to hear you explain:

- *Why* dictionary attacks are fast and brute-force is exponential
- *Why* salts defeat rainbow tables but don't change a single guess's cost
- *Why* MD5/SHA1 are "broken" and what that specifically means
- *Why* fast hash functions (even unbroken ones like SHA256) are still
  unsuitable for password storage, and what bcrypt/scrypt/argon2 do
  differently
- How to actually get CPU-core-scaling parallel speedup in Python despite
  the GIL (hint: processes, not threads, for CPU-bound work)

See [`docs/HASH_ALGORITHMS.md`](docs/HASH_ALGORITHMS.md) and
[`docs/SECURITY_NOTES.md`](docs/SECURITY_NOTES.md) for the full write-up.

## Project structure

```
hash-cracker/
├── hashcracker/
│   ├── __init__.py       # package exports
│   ├── __main__.py       # `python -m hashcracker` entry point
│   ├── hashers.py        # MD5/SHA1/SHA256 generation, salting, verification
│   ├── candidates.py     # wordlist + brute-force candidate generators
│   ├── engine.py         # multiprocessing crack orchestration + progress
│   └── cli.py            # argparse CLI (hash / crack subcommands)
├── tests/
│   ├── test_hashers.py
│   ├── test_candidates.py
│   └── test_engine.py
├── wordlists/
│   └── sample_wordlist.txt   # 50 common weak passwords for demos
├── docs/
│   ├── HASH_ALGORITHMS.md
│   └── SECURITY_NOTES.md
├── .github/workflows/ci.yml
├── requirements.txt
├── pyproject.toml
├── LICENSE
└── README.md
```

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/hash-cracker.git
cd hash-cracker
pip install -r requirements.txt
```

No external dependencies are required to run the tool itself — only
`pytest` for running the test suite.

## Usage

### 1. Generate a hash (to create test targets)

```bash
python -m hashcracker hash --text "password123" --algorithm md5
# -> 482c811da5d5b4bc6d497ffa98491e38

python -m hashcracker hash --text "password123" --algorithm sha256
```

### 2. Dictionary attack

```bash
python -m hashcracker crack --algorithm sha256 \
  --hash a941a4c4fd0c01cddef61b8be963bf4c1e2b0811c037ce3f1835fddf6ef6c223 \
  --wordlist wordlists/sample_wordlist.txt
```

```text
[*] Dictionary attack using wordlist: wordlists/sample_wordlist.txt
[*] Algorithm: sha256   Targets: 1   Workers: auto (cpu_count)
[progress] 50 tried | 4,720 h/s | elapsed 0.0s | found 1/1

=== Results ===
  [CRACKED] a941a4c4fd0c01cddef61b8be963bf4c1e2b0811c037ce3f1835fddf6ef6c223  ->  'sunshine'

Done. 1/1 cracked. 50 hashes computed in 0.01s (4,720 h/s).
```

### 3. Brute-force attack

```bash
python -m hashcracker crack --algorithm md5 \
  --hash <target-hash> \
  --bruteforce --lowercase --digits --min-length 1 --max-length 5 \
  --threads 8
```

Flags `--lowercase`, `--uppercase`, `--digits`, `--special`, and
`--custom-charset "<chars>"` combine to build the brute-force character
set; `--min-length` / `--max-length` bound the search.

### 4. Salted hashes

```bash
python -m hashcracker crack --algorithm sha1 \
  --hash <target-hash> \
  --wordlist wordlists/sample_wordlist.txt \
  --salt a1b2c3 --salt-position append
```

### 5. Batch cracking (many hashes, one pass)

```bash
python -m hashcracker crack --algorithm sha256 \
  --hash-file leaked_hashes.txt \
  --wordlist wordlists/sample_wordlist.txt --threads 8
```

`leaked_hashes.txt` contains one hex digest per line. A single scan of the
wordlist checks every hash in the file simultaneously (O(1) set lookup
per candidate), rather than re-scanning once per target.

### All options

```bash
python -m hashcracker crack --help
```

## Running tests

```bash
pip install pytest
pytest tests/ -v
```

All core logic (hashing correctness against `hashlib`, salt positioning,
dictionary/brute-force/salted/batch cracking via the real multiprocessing
engine) is covered. CI runs this suite automatically on every push — see
`.github/workflows/ci.yml`.

## Performance notes

Hashing is CPU-bound, so this project uses **multiprocessing** (separate
interpreter processes), not threading — Python's GIL means threads would
serialize on pure-Python/`hashlib` C-extension calls and not meaningfully
parallelize across cores. Work is distributed in chunks (default 2,000
candidates per task) rather than one password per task, to amortize
inter-process communication overhead. Expect throughput on the order of a
few hundred thousand to low millions of hashes/second on a modern
multi-core CPU for MD5/SHA1/SHA256, scaling close to linearly with
`--threads`. This is orders of magnitude slower than GPU-accelerated
tools like Hashcat — see `docs/SECURITY_NOTES.md` for why that gap exists
and why it matters for real-world attacker capability.

## Roadmap / possible extensions

- [ ] Rule-based mangling (append digits, leetspeak substitution, case
      toggling) layered on top of dictionary words
- [ ] GPU acceleration via OpenCL/CUDA bindings
- [ ] Resume support for interrupted long-running brute-force jobs
- [ ] JSON/CSV output mode for integration with reporting pipelines

## License

MIT — see [`LICENSE`](LICENSE).

## Disclaimer

This project is for educational and authorized-testing purposes only.
The author is not responsible for misuse. Always obtain explicit written
authorization before testing any system you do not own.
