# Security Notes

## Scope and authorized use

This tool is built for:

- **Learning** how hash cracking works, as part of understanding why
  password storage design matters.
- **CTF practice** against intentionally weak/sample hashes.
- **Authorized penetration testing / red team engagements**, where you
  have explicit, documented permission to test the target systems, and
  cracking recovered hash dumps is in scope.

Running this tool, or any cracking tool, against hashes or systems you do
not own and do not have explicit written authorization to test is illegal
in most jurisdictions (e.g., under the US Computer Fraud and Abuse Act,
UK Computer Misuse Act, and equivalent laws elsewhere) and is not
something this project is intended to enable. If you're using this as
part of a bug bounty or pentest engagement, keep your scope document and
authorization on hand.

## Dictionary attacks vs. brute-force attacks

**Dictionary attack** (`--wordlist`): hash every entry in a wordlist file
and compare against the target hash(es). This is the first thing any real
attacker tries, because people are bad at choosing unique passwords —
lists like `rockyou.txt` (leaked in a 2009 breach, ~14 million real
passwords) crack a surprisingly large fraction of real-world password
hashes in seconds, because so many people reuse the same weak passwords.
Dictionary attacks are fast *because* they are narrow: they only test
plausible human-chosen passwords, not the entire possible keyspace.

**Brute-force attack** (`--bruteforce`): enumerate every possible string
over a chosen character set, up to a maximum length, and test each one.
This is exhaustive — it is *guaranteed* to eventually find any password
within the length/charset bound — but the search space grows
exponentially:

```
total candidates = sum over length L in [min_length, max_length] of (charset_size ^ L)
```

A 4-character lowercase-only password has `26^4` = 456,976 combinations —
trivial. An 8-character password mixing upper/lower/digits/symbols
(charset size ~90) has `90^8` ≈ 4.3 × 10^15 combinations — at even a fast
10 billion hashes/second, that's roughly 5 days for SHA256 on capable
hardware, and that's *before* accounting for a slow algorithm or a salt.
This exponential blowup is exactly why password **length** matters more
than most people expect, and why "use a mix of character types" helps
far less than "make it long."

## Salts: what they do and why they matter

A **salt** is random data generated per password and mixed in before
hashing (`hash(password + salt)` or `hash(salt + password)`). It solves
two specific problems that plain hashing does not:

1. **Rainbow tables.** A rainbow table is a precomputed lookup table
   mapping common password hashes back to their plaintext, built once and
   reused against *any* unsalted hash dump. A salt makes every stored hash
   unique even for identical passwords, so a precomputed table for
   `sha256("password")` is useless — the attacker would need a separate
   precomputed table *per possible salt value*, which is infeasible if
   salts are long and random.
2. **Cross-account reuse of attacker effort.** Without salts, cracking one
   password hash in a leaked database effectively cracks it for *every*
   other user with the same password, in one dictionary pass. With salts,
   the attacker must redo the full hashing work independently for every
   single hash, because each one is combined with different salt data —
   there is no shared precomputation to exploit.

Critically: **a salt does not make brute-forcing a single password
meaningfully more expensive in isolation** — if you already know the salt
(salts are stored in plaintext alongside the hash; they don't need to be
secret), hashing `candidate + known_salt` costs the same as hashing
`candidate` alone. The exponential cost increase from salting is about
*defeating precomputation and amortization across many hashes*, not about
making each individual hash harder to compute. This tool models that
correctly: `--salt` is provided to the cracker exactly as it would be read
from a real leaked database.

## Multi-threading and real-world cracking performance

Dedicated cracking tools like **Hashcat** and **John the Ripper** achieve
billions of hashes per second on MD5/SHA1 using GPU acceleration, because
GPUs have thousands of simple cores ideal for the repetitive math of hash
functions. This project uses CPU multiprocessing instead (see
`hashcracker/engine.py`), which is far slower in absolute terms, but
demonstrates the same core principle real tools rely on: hash cracking is
"embarrassingly parallel" — every candidate password can be checked
completely independently of every other one, so throughput scales almost
linearly with the number of parallel workers (CPU cores here, GPU cores
in Hashcat).

## Real-world context: where this fits in penetration testing

In an authorized internal penetration test or red team engagement, a
common sequence looks like:

1. Gain some form of access or an exported credential database (e.g., via
   a vulnerable web app, a misconfigured backup, or an `NTDS.dit` dump
   from Active Directory).
2. Identify the hash algorithm in use (hash length/format is often enough
   to narrow it down — see `hashers.identify_algorithm`).
3. Run a dictionary attack first (fast, high success rate against reused
   passwords), often combined with "mangling rules" (append digits,
   capitalize first letter, leetspeak substitutions) that real tools like
   Hashcat support and this project's `--custom-charset` brute-force
   option gestures toward.
4. Fall back to targeted brute-force only for short hashes or specific
   known patterns (e.g., "the password is a 4-digit PIN").
5. Report cracked credentials as a finding, demonstrating real business
   risk (e.g., "63% of the 400 recovered password hashes were cracked in
   under 10 minutes using a public wordlist"), and recommend remediations:
   enforce password managers/passphrases, migrate hashing to
   bcrypt/argon2, enable MFA so a cracked password alone isn't sufficient
   for account takeover.

## Summary of recommendations for defenders

- Never store passwords with MD5, SHA1, or unsalted SHA256.
- Use bcrypt, scrypt, or argon2id with a modern cost factor.
- Always use a unique, random, sufficiently long (≥16 bytes) salt per
  password, generated with a cryptographically secure random source.
- Enforce minimum password length (length matters far more than
  character-class complexity rules).
- Add MFA so that a cracked password hash isn't a full account
  compromise by itself.
- Rate-limit and monitor authentication endpoints so *online* brute-force
  (against the live login form, not a stolen hash dump) is also
  impractical.
