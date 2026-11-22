"""
hashcracker
~~~~~~~~~~~

An educational hash-cracking toolkit demonstrating dictionary attacks,
brute-force attacks, salted-hash cracking, and multiprocessing
performance optimization against MD5, SHA1, and SHA256 digests.

This project is for authorized security education, CTF practice, and
penetration testing of systems you own or are explicitly permitted to
test. See README.md and docs/SECURITY_NOTES.md for details.
"""

__version__ = "1.0.0"

from .hashers import hash_string, hash_with_salt, verify_hash, SUPPORTED_ALGORITHMS

__all__ = [
    "hash_string",
    "hash_with_salt",
    "verify_hash",
    "SUPPORTED_ALGORITHMS",
    "__version__",
]
