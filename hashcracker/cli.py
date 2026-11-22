"""
hashcracker.cli
~~~~~~~~~~~~~~~

Command-line entry point. Two subcommands:

    hashcracker hash      -- generate a hash from plaintext (for testing)
    hashcracker crack      -- run a dictionary or brute-force attack

Examples
--------
Generate a hash to use as a test target:
    $ python -m hashcracker hash --text "password123" --algorithm sha256

Dictionary attack against one hash:
    $ python -m hashcracker crack --algorithm md5 \\
        --hash 482c811da5d5b4bc6d497ffa98491e38 \\
        --wordlist wordlists/sample_wordlist.txt

Dictionary attack against a batch of hashes from a file (one per line):
    $ python -m hashcracker crack --algorithm sha1 \\
        --hash-file leaked_hashes.txt \\
        --wordlist wordlists/sample_wordlist.txt --threads 8

Brute force, lowercase+digits, up to length 5:
    $ python -m hashcracker crack --algorithm sha256 \\
        --hash <digest> --bruteforce --lowercase --digits --max-length 5

Salted hash:
    $ python -m hashcracker crack --algorithm sha256 \\
        --hash <digest> --wordlist wordlists/sample_wordlist.txt \\
        --salt a1b2c3 --salt-position append
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import List

from .candidates import build_charset, count_bruteforce_space, iter_bruteforce, iter_wordlist
from .engine import CrackTarget, crack
from .hashers import SUPPORTED_ALGORITHMS, hash_string, hash_with_salt


def _format_eta(seconds: float) -> str:
    if seconds <= 0 or seconds != seconds:  # NaN guard
        return "unknown"
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f}m"
    if seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86400:.1f}d"


def _load_hash_values(args: argparse.Namespace) -> List[str]:
    values = []
    if args.hash:
        values.append(args.hash)
    if args.hash_file:
        path = Path(args.hash_file)
        if not path.is_file():
            raise FileNotFoundError(f"--hash-file not found: {args.hash_file}")
        for line in path.read_text().splitlines():
            line = line.strip()
            if line:
                values.append(line)
    if not values:
        raise ValueError("Provide at least one target with --hash or --hash-file")
    return values


def _cmd_hash(args: argparse.Namespace) -> int:
    if args.salt:
        digest = hash_with_salt(args.text, args.salt, args.algorithm, args.salt_position)
    else:
        digest = hash_string(args.text, args.algorithm)
    print(digest)
    return 0


def _cmd_crack(args: argparse.Namespace) -> int:
    hash_values = _load_hash_values(args)
    targets = [CrackTarget(hash_value=h, label=f"target[{i}]") for i, h in enumerate(hash_values)]

    if args.bruteforce:
        charset = build_charset(
            lowercase=args.lowercase or not any(
                [args.uppercase, args.digits, args.special]
            ),
            uppercase=args.uppercase,
            digits=args.digits,
            special=args.special,
            custom=args.custom_charset or "",
        )
        space = count_bruteforce_space(len(charset), args.min_length, args.max_length)
        print(
            f"[*] Brute-force mode: charset size={len(charset)}, "
            f"lengths {args.min_length}-{args.max_length} "
            f"=> {space:,} total candidates to try"
        )
        candidate_stream = iter_bruteforce(charset, args.min_length, args.max_length)
    else:
        if not args.wordlist:
            print("error: --wordlist is required unless --bruteforce is set", file=sys.stderr)
            return 2
        print(f"[*] Dictionary attack using wordlist: {args.wordlist}")
        candidate_stream = iter_wordlist(args.wordlist)

    print(f"[*] Algorithm: {args.algorithm}   Targets: {len(targets)}   Workers: {args.threads or 'auto (cpu_count)'}")
    if args.salt:
        print(f"[*] Salt: '{args.salt}' ({args.salt_position})")

    def progress(attempts, elapsed, found_count, total_targets):
        rate = attempts / elapsed if elapsed > 0 else 0
        print(
            f"\r[progress] {attempts:,} tried | {rate:,.0f} h/s | "
            f"elapsed {elapsed:.1f}s | found {found_count}/{total_targets}      ",
            end="",
            flush=True,
        )

    summary = crack(
        candidate_stream,
        targets,
        algorithm=args.algorithm,
        salt=args.salt or "",
        salt_position=args.salt_position,
        processes=args.threads,
        chunk_size=args.chunk_size,
        progress_callback=progress,
    )
    print()  # newline after the carriage-return progress line

    print("\n=== Results ===")
    cracked = 0
    for result in summary.results:
        if result.password is not None:
            cracked += 1
            print(f"  [CRACKED] {result.hash_value}  ->  '{result.password}'")
        else:
            print(f"  [NOT FOUND] {result.hash_value}")

    print(
        f"\nDone. {cracked}/{len(summary.results)} cracked. "
        f"{summary.attempts:,} hashes computed in {summary.elapsed_seconds:.2f}s "
        f"({summary.hashes_per_second:,.0f} h/s)."
    )
    return 0 if cracked == len(summary.results) else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hashcracker",
        description="Educational hash cracking tool (dictionary + brute-force) "
        "for MD5/SHA1/SHA256, with optional salt support and multiprocessing.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    hash_parser = subparsers.add_parser("hash", help="Generate a hash from plaintext (for testing)")
    hash_parser.add_argument("--text", required=True, help="Plaintext to hash")
    hash_parser.add_argument("--algorithm", choices=SUPPORTED_ALGORITHMS, required=True)
    hash_parser.add_argument("--salt", default="", help="Optional salt to mix in")
    hash_parser.add_argument(
        "--salt-position", choices=["append", "prepend"], default="append"
    )
    hash_parser.set_defaults(func=_cmd_hash)

    crack_parser = subparsers.add_parser("crack", help="Crack a hash via dictionary or brute-force")
    crack_parser.add_argument("--algorithm", choices=SUPPORTED_ALGORITHMS, required=True)
    crack_parser.add_argument("--hash", help="A single target hash (hex digest)")
    crack_parser.add_argument(
        "--hash-file", help="File with one target hash per line, for batch cracking"
    )
    crack_parser.add_argument("--wordlist", help="Path to a wordlist file for dictionary attack")
    crack_parser.add_argument(
        "--bruteforce", action="store_true", help="Use brute-force mode instead of a wordlist"
    )
    crack_parser.add_argument("--lowercase", action="store_true", help="Include a-z (brute-force)")
    crack_parser.add_argument("--uppercase", action="store_true", help="Include A-Z (brute-force)")
    crack_parser.add_argument("--digits", action="store_true", help="Include 0-9 (brute-force)")
    crack_parser.add_argument(
        "--special", action="store_true", help="Include common special characters (brute-force)"
    )
    crack_parser.add_argument(
        "--custom-charset", default="", help="Extra literal characters to add to the brute-force charset"
    )
    crack_parser.add_argument("--min-length", type=int, default=1, help="Brute-force minimum length")
    crack_parser.add_argument("--max-length", type=int, default=4, help="Brute-force maximum length")
    crack_parser.add_argument("--salt", default="", help="Salt to apply to every candidate")
    crack_parser.add_argument(
        "--salt-position", choices=["append", "prepend"], default="append"
    )
    crack_parser.add_argument(
        "--threads", type=int, default=None, help="Worker processes (default: all CPU cores)"
    )
    crack_parser.add_argument(
        "--chunk-size", type=int, default=2000, help="Candidates per task sent to each worker"
    )
    crack_parser.set_defaults(func=_cmd_crack)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
