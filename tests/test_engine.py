from hashcracker.candidates import build_charset, iter_bruteforce, iter_wordlist
from hashcracker.engine import CrackTarget, crack
from hashcracker.hashers import hash_string, hash_with_salt


def test_dictionary_attack_finds_known_password(tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("123456\npassword\nletmein\ndragon\n")

    secret = "password"
    target_hash = hash_string(secret, "sha256")

    summary = crack(
        iter_wordlist(str(wordlist)),
        [CrackTarget(hash_value=target_hash, label="user1")],
        algorithm="sha256",
        processes=2,
    )

    assert summary.found_all is True
    assert summary.results[0].password == secret


def test_dictionary_attack_reports_not_found(tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("aaa\nbbb\nccc\n")
    target_hash = hash_string("not-in-list", "md5")

    summary = crack(
        iter_wordlist(str(wordlist)),
        [CrackTarget(hash_value=target_hash)],
        algorithm="md5",
        processes=2,
    )

    assert summary.found_all is False
    assert summary.results[0].password is None


def test_bruteforce_attack_finds_short_password():
    secret = "ab"
    target_hash = hash_string(secret, "md5")
    charset = build_charset(lowercase=True)

    summary = crack(
        iter_bruteforce(charset, 1, 2),
        [CrackTarget(hash_value=target_hash)],
        algorithm="md5",
        processes=2,
    )

    assert summary.results[0].password == secret


def test_salted_hash_cracking(tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("password\nqwerty\nsunshine\n")

    secret, salt = "sunshine", "x9Z"
    target_hash = hash_with_salt(secret, salt, "sha1", "append")

    summary = crack(
        iter_wordlist(str(wordlist)),
        [CrackTarget(hash_value=target_hash)],
        algorithm="sha1",
        salt=salt,
        salt_position="append",
        processes=2,
    )

    assert summary.results[0].password == secret


def test_batch_cracking_multiple_hashes_in_one_pass(tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("alpha\nbravo\ncharlie\ndelta\n")

    secrets = ["bravo", "delta"]
    targets = [
        CrackTarget(hash_value=hash_string(s, "sha256"), label=s) for s in secrets
    ]

    summary = crack(iter_wordlist(str(wordlist)), targets, algorithm="sha256", processes=2)

    found_passwords = {r.password for r in summary.results}
    assert found_passwords == set(secrets)
    assert summary.found_all is True
