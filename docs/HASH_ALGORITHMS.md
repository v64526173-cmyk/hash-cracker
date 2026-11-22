# Hash Algorithms: Mechanics and Properties

## What a cryptographic hash function is

A cryptographic hash function takes an input of any size and produces a
fixed-length output (the "digest" or "hash"). Three properties matter for
this project:

1. **Deterministic** — the same input always produces the same output.
   `sha256("password")` is always `5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d`.
2. **One-way (preimage resistant)** — given a digest, there is no
   efficient way to compute an input that produces it, other than trying
   inputs and checking. This is *why* cracking is a search problem.
3. **Avalanche effect** — a tiny change in input produces a completely
   different, unpredictable digest. `sha256("password")` and
   `sha256("Password")` share no visible structure.

Because of property #2, you cannot "decrypt" a hash — there is nothing to
decrypt. All a hash cracker does is **re-create the forward computation**
(hash a guess) and compare it to the target digest. If millions of guesses
are cheap to compute, and the password is common or short, you will find a
match quickly. If the password is long, random, and the hash function is
deliberately slow, you won't — within any practical timeframe.

## The three algorithms this tool supports

| Algorithm | Digest size | Status for password storage |
|---|---|---|
| MD5    | 128 bits (32 hex chars) | **Broken.** Collision attacks are practical; never use for passwords or integrity checks where an adversary can choose input. |
| SHA1   | 160 bits (40 hex chars) | **Broken.** Google/CWI demonstrated a practical collision in 2017 (SHAttered). Deprecated across the industry. |
| SHA256 | 256 bits (64 hex chars) | **Not broken**, but **still unsuitable alone for passwords** — see below. |

### Why MD5 and SHA1 are "cryptographically broken"

"Broken" here specifically means **collision resistance** has failed:
researchers can construct two *different* inputs that hash to the *same*
digest, far faster than brute force would predict. That matters enormously
for digital signatures and certificate validity (an attacker could forge a
document with the same signature as a legitimate one). It matters less
directly for *password cracking* — collisions don't make guessing a
specific password easier — but MD5/SHA1 share a more relevant weakness for
this project: **they are extremely fast**. A single consumer GPU can
compute tens of billions of MD5 hashes per second. That speed, intended as
a feature for file-integrity checksums, is a liability for password
hashing, because it means an attacker can try an enormous number of
candidate passwords per second against a stolen hash dump.

### Why SHA256 alone is still not enough for passwords

SHA256 has no known practical collision or preimage attack. But it was
designed to be **fast**, because its typical uses (TLS certificates, git
commit hashes, blockchain proof-of-work, file checksums) all *want* speed.
Speed is the opposite of what you want for password storage: if an
attacker steals your SHA256(password) database, modern hardware can still
attempt billions of guesses per second, because SHA256 itself takes only
nanoseconds to compute.

## Why real systems use bcrypt / scrypt / argon2 instead

Purpose-built password hashing algorithms solve the speed problem directly
by being **deliberately, tunably slow**, and by requiring significant
**memory**, not just CPU:

- **bcrypt** — based on the Blowfish cipher, with a configurable "cost
  factor" (work factor) that exponentially increases computation time.
  Increasing the cost factor by 1 doubles the time to compute a single
  hash. Widely supported, industry standard since the late 1990s.
- **scrypt** — adds a *memory-hardness* requirement on top of CPU cost,
  making GPU/ASIC parallel cracking far more expensive, because cheap GPU
  cores don't have the RAM-per-core that scrypt demands.
- **argon2** — winner of the 2015 Password Hashing Competition; tunable
  for both CPU time and memory, and generally considered today's best
  default choice for new systems (argon2id variant specifically).

Each of these also **generates and stores a random salt per password
automatically**, and often includes the cost parameters in the stored
hash string itself (e.g. `$2b$12$...` for bcrypt), so verification knows
exactly how the hash was produced.

### The core trade-off

| | MD5/SHA1/SHA256 | bcrypt/scrypt/argon2 |
|---|---|---|
| Speed | Nanoseconds/hash — great for checksums | Deliberately milliseconds+/hash |
| Attacker cost for 1 billion guesses | Seconds on a GPU | Days to years, depending on cost factor |
| Legitimate login cost | Negligible | Tens to hundreds of milliseconds — imperceptible to a real user logging in once |
| Memory hardness | None | scrypt/argon2: yes, by design |

This asymmetry — cheap for the legitimate single login, expensive for the
attacker trying billions of guesses — is the entire point of a password
hashing algorithm, and it's why "just hash it with SHA256" is a common and
dangerous mistake in system design.

## This project's scope

This tool intentionally targets MD5/SHA1/SHA256 because they are fast
enough to crack in a reasonable classroom/demo timeframe and because they
remain common in real-world legacy systems, CTF challenges, and leaked
password dumps you may encounter in authorized penetration testing. It
does **not** implement bcrypt/scrypt/argon2 cracking, because doing so
"successfully" against a well-configured modern system is, by design,
not something that should be fast or easy — that's the whole lesson.
