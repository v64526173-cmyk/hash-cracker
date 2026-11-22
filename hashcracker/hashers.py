"""
hashcracker.hashers
~~~~~~~~~~~~~~~~~~~

Thin, well-tested wrappers around Python's `hashlib` for the three
algorithms this project supports: MD5, SHA1, and SHA256.

All three are deterministic, one-way functions: the same input always
produces the same fixed-length output, and (in theory) there is no
efficient way to go from the output back to the input. That one-way
property is exactly what makes "cracking" a search problem rather than
a computation problem -- we can't invert the hash, so instead we hash
a huge number of *candidate* passwords and compare digests until one
matches.

MD5 and SHA1 are considered cryptographically broken for purposes like
digital signatures and collision resistance, and neither was ever
designed for password storage. Both are fast, general-purpose digests,
which is precisely the problem: an attacker with commodity GPU hardware
can compute billions of MD5/SHA1 hashes per second. SHA256 is still
considered secure against preimage/collision attacks at the time of
writing, but it is *still fast*, so it is also a poor choice for
password storage on its own -- see docs/SECURITY_NOTES.md for why
bcrypt/scrypt/argon2 exist.
"""

from __future__ import annotations

import hashlib
import hmac

SUPPORTED_ALGORITHMS = ("md5", "sha1", "sha256")


def hash_string(text: str, algorithm: str, encoding: str = "utf-8") -> str:
    """Hash `text` with the given algorithm and return a lowercase hex digest.

    Args:
        text: the plaintext string to hash.
        algorithm: one of "md5", "sha1", "sha256" (case-insensitive).
        encoding: text encoding used before hashing (default utf-8).

    Raises:
        ValueError: if `algorithm` is not supported.
    """
    algorithm = algorithm.lower()
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm '{algorithm}'. "
            f"Choose from: {', '.join(SUPPORTED_ALGORITHMS)}"
        )
    digest = hashlib.new(algorithm)
    digest.update(text.encode(encoding))
    return digest.hexdigest()


def hash_with_salt(
    text: str,
    salt: str,
    algorithm: str,
    position: str = "append",
    encoding: str = "utf-8",
) -> str:
    """Hash `text` combined with `salt`.

    A salt is random data mixed into a password before hashing. Two users
    with the same password get different hashes because their salts
    differ, which defeats precomputed rainbow tables and forces an
    attacker to brute-force each hash independently rather than reuse one
    dictionary pass across every account.

    Args:
        text: candidate plaintext password.
        salt: the (usually random, per-user) salt value as a string.
        algorithm: one of "md5", "sha1", "sha256".
        position: "append" (password + salt) or "prepend" (salt + password).
            Real systems vary in convention; both are supported here.
    """
    if position == "append":
        combined = text + salt
    elif position == "prepend":
        combined = salt + text
    else:
        raise ValueError("position must be 'append' or 'prepend'")
    return hash_string(combined, algorithm, encoding)


def verify_hash(candidate_hash: str, target_hash: str) -> bool:
    """Constant-time-ish comparison of two hex digest strings.

    Uses hmac.compare_digest to avoid leaking timing information, which
    is good practice even though in an offline cracker (no network round
    trip) timing side channels aren't really exploitable -- it's included
    to model how a *real* authentication check should compare secrets.
    """
    return hmac.compare_digest(candidate_hash.lower(), target_hash.lower())


def identify_algorithm(hash_value: str) -> list:
    """Guess which algorithm(s) could have produced a hash, by hex length.

    This is a heuristic, not a proof: MD5 digests are 32 hex chars (128
    bits), SHA1 digests are 40 hex chars (160 bits), SHA256 digests are
    64 hex chars (256 bits). Multiple algorithms never collide in length
    here, so length alone is actually sufficient to disambiguate between
    these three specific algorithms.
    """
    length_map = {32: ["md5"], 40: ["sha1"], 64: ["sha256"]}
    cleaned = hash_value.strip().lower()
    if not all(c in "0123456789abcdef" for c in cleaned):
        return []
    return length_map.get(len(cleaned), [])
