"""
hashcracker.candidates
~~~~~~~~~~~~~~~~~~~~~~

Generators that produce candidate passwords for the two classic attack
methodologies:

* Dictionary attack: read real/likely passwords from a wordlist file.
  Fast because it only tries probable passwords (people reuse "password123",
  pet names, keyboard patterns, etc.) -- this is the first thing any real
  attacker or pentester tries against a dumped hash.

* Brute-force attack: enumerate *every* possible string over a character
  set, up to a maximum length. Guaranteed to eventually find any password
  within the length bound, but the search space grows exponentially with
  both charset size and length, so it is only practical for short/weak
  passwords.

Both generators are lazy (they yield one candidate at a time) so that
brute-forcing, say, all 8-character alphanumeric+symbol strings (around
6 quadrillion combinations) doesn't try to materialize a list in memory.
"""

from __future__ import annotations

import itertools
from pathlib import Path
from typing import Iterable, Iterator

CHARSETS = {
    "lower": "abcdefghijklmnopqrstuvwxyz",
    "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "digits": "0123456789",
    "special": "!@#$%^&*()-_=+[]{};:,.<>/?",
}


def build_charset(
    lowercase: bool = True,
    uppercase: bool = False,
    digits: bool = False,
    special: bool = False,
    custom: str = "",
) -> str:
    """Assemble a character set string from boolean flags plus an optional
    custom set of extra characters. Order is deterministic so that runs
    are reproducible."""
    charset = ""
    if lowercase:
        charset += CHARSETS["lower"]
    if uppercase:
        charset += CHARSETS["upper"]
    if digits:
        charset += CHARSETS["digits"]
    if special:
        charset += CHARSETS["special"]
    charset += custom
    # de-duplicate while preserving order
    seen = set()
    deduped = []
    for ch in charset:
        if ch not in seen:
            seen.add(ch)
            deduped.append(ch)
    if not deduped:
        raise ValueError("Resulting charset is empty -- enable at least one character class")
    return "".join(deduped)


def count_bruteforce_space(charset_size: int, min_length: int, max_length: int) -> int:
    """Return the total number of candidates a brute-force run will try,
    useful for printing an upfront 'this will take N guesses' estimate
    before committing CPU time."""
    return sum(charset_size ** length for length in range(min_length, max_length + 1))


def iter_bruteforce(charset: str, min_length: int = 1, max_length: int = 4) -> Iterator[str]:
    """Lazily yield every string over `charset` with length in
    [min_length, max_length], shortest first (shorter/weaker passwords
    are far more likely to be hit early, so trying them first is the
    sensible default)."""
    if min_length < 1:
        raise ValueError("min_length must be >= 1")
    if max_length < min_length:
        raise ValueError("max_length must be >= min_length")
    for length in range(min_length, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            yield "".join(combo)


def iter_wordlist(path: str, encoding: str = "utf-8", errors: str = "ignore") -> Iterator[str]:
    """Lazily yield one stripped, non-empty line at a time from a wordlist
    file. Using a generator here means a 14-million-line rockyou.txt-sized
    wordlist never has to fully live in memory."""
    wordlist_path = Path(path)
    if not wordlist_path.is_file():
        raise FileNotFoundError(f"Wordlist not found: {path}")
    with wordlist_path.open("r", encoding=encoding, errors=errors) as handle:
        for line in handle:
            word = line.rstrip("\n\r")
            if word:
                yield word


def chunked(iterable: Iterable, size: int) -> Iterator[list]:
    """Batch a (possibly huge, lazy) iterable into fixed-size lists.

    This is the bridge between a lazy candidate generator and a
    multiprocessing worker pool: instead of sending one password at a
    time to a worker process (slow, dominated by IPC overhead), we send
    chunks of e.g. 2,000 candidates per task.
    """
    iterator = iter(iterable)
    while True:
        batch = list(itertools.islice(iterator, size))
        if not batch:
            return
        yield batch
