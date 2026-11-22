"""
hashcracker.engine
~~~~~~~~~~~~~~~~~~

The orchestration layer: takes a stream of candidate passwords (from
candidates.py), hashes each one in parallel worker processes, and checks
the result against one or more target hashes (hashers.py). Reports
live hashes-per-second / ETA, and supports batch-cracking many hashes of
the same algorithm in a single pass over the candidate space.

Design notes
------------
We use multiprocessing (not threading) for CPU-bound hash computation
because of Python's Global Interpreter Lock: threads would serialize on
the GIL for pure-Python hashlib calls and give no real speedup across
cores. Separate processes each get their own interpreter and GIL, so
hash throughput scales close to linearly with CPU core count.

Work is distributed in chunks (lists of candidate strings) rather than
one-candidate-per-task, because IPC (pickling a task, sending it to a
worker, pickling the result back) has fixed overhead that would dwarf
the cost of a single hash operation if we sent one string at a time.
"""

from __future__ import annotations

import multiprocessing as mp
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

from .candidates import chunked
from .hashers import hash_string, hash_with_salt

DEFAULT_CHUNK_SIZE = 2000


@dataclass
class CrackTarget:
    """One hash we are trying to break, keyed by its own hex digest."""
    hash_value: str
    label: str = ""  # optional friendly name, e.g. a username


@dataclass
class CrackResult:
    hash_value: str
    password: Optional[str]
    label: str = ""


@dataclass
class CrackSummary:
    results: List[CrackResult] = field(default_factory=list)
    attempts: int = 0
    elapsed_seconds: float = 0.0
    found_all: bool = False

    @property
    def hashes_per_second(self) -> float:
        if self.elapsed_seconds <= 0:
            return 0.0
        return self.attempts / self.elapsed_seconds


def _worker_check_chunk(args):
    """Executed inside a worker process. Hash every candidate in `chunk`
    and return the subset of (candidate, matched_hash) pairs that hit one
    of the remaining target hashes.

    `args` is a single tuple (not multiple positional args) because
    Pool.imap_unordered only passes one argument per task.
    """
    chunk, algorithm, remaining_hashes, salt, salt_position = args
    remaining_set = set(remaining_hashes)
    hits = []
    if salt:
        hasher = lambda candidate: hash_with_salt(candidate, salt, algorithm, salt_position)
    else:
        hasher = lambda candidate: hash_string(candidate, algorithm)

    for candidate in chunk:
        digest = hasher(candidate)
        if digest in remaining_set:
            hits.append((candidate, digest))
    return hits, len(chunk)


def crack(
    candidate_stream: Iterable[str],
    targets: List[CrackTarget],
    algorithm: str,
    salt: str = "",
    salt_position: str = "append",
    processes: Optional[int] = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_callback=None,
    stop_when_all_found: bool = True,
) -> CrackSummary:
    """Run a cracking job against one or more target hashes.

    Args:
        candidate_stream: any iterable (typically a lazy generator) of
            candidate plaintext strings, e.g. iter_wordlist(...) or
            iter_bruteforce(...).
        targets: list of CrackTarget hashes to search for. Supports batch
            cracking -- a single pass over the candidate space checks
            every target hash at once, which is far more efficient than
            re-scanning the wordlist once per hash.
        algorithm: "md5", "sha1", or "sha256". All targets in one run
            must share an algorithm (mixed-algorithm batches should be
            split into separate crack() calls).
        salt: optional salt string applied to every candidate before
            hashing (see hashers.hash_with_salt).
        salt_position: "append" or "prepend".
        processes: worker process count (defaults to os.cpu_count()).
        chunk_size: candidates per task sent to each worker.
        progress_callback: optional callable(attempts, elapsed, found_count,
            total_targets) invoked periodically for live UI/CLI reporting.
        stop_when_all_found: if True (default), stop early once every
            target hash has been matched instead of exhausting the
            candidate stream.

    Returns:
        CrackSummary with one CrackResult per target (password=None if
        not found), total attempts, elapsed time, and derived
        hashes-per-second.
    """
    remaining: Dict[str, CrackTarget] = {t.hash_value.lower(): t for t in targets}
    found: Dict[str, str] = {}

    start_time = time.monotonic()
    attempts = 0
    last_report = start_time

    pool = mp.Pool(processes=processes)
    try:
        task_iter = (
            (chunk, algorithm, list(remaining.keys()), salt, salt_position)
            for chunk in chunked(candidate_stream, chunk_size)
        )
        for hits, chunk_len in pool.imap_unordered(_worker_check_chunk, task_iter):
            attempts += chunk_len
            for candidate, digest in hits:
                if digest in remaining and digest not in found:
                    found[digest] = candidate

            now = time.monotonic()
            if progress_callback and (now - last_report) >= 0.5:
                progress_callback(attempts, now - start_time, len(found), len(remaining))
                last_report = now

            if stop_when_all_found and len(found) >= len(remaining):
                break
    finally:
        pool.terminate()
        pool.join()

    elapsed = time.monotonic() - start_time
    if progress_callback:
        progress_callback(attempts, elapsed, len(found), len(remaining))

    results = [
        CrackResult(hash_value=h, password=found.get(h), label=t.label)
        for h, t in remaining.items()
    ]
    return CrackSummary(
        results=results,
        attempts=attempts,
        elapsed_seconds=elapsed,
        found_all=len(found) >= len(remaining) and len(remaining) > 0,
    )
