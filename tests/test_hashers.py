import hashlib

import pytest

from hashcracker.hashers import (
    hash_string,
    hash_with_salt,
    identify_algorithm,
    verify_hash,
)


@pytest.mark.parametrize("algorithm", ["md5", "sha1", "sha256"])
def test_hash_string_matches_stdlib(algorithm):
    text = "password123"
    expected = hashlib.new(algorithm, text.encode("utf-8")).hexdigest()
    assert hash_string(text, algorithm) == expected


def test_hash_string_is_deterministic():
    assert hash_string("hello", "sha256") == hash_string("hello", "sha256")


def test_hash_string_case_insensitive_algorithm():
    assert hash_string("hello", "SHA256") == hash_string("hello", "sha256")


def test_hash_string_rejects_unknown_algorithm():
    with pytest.raises(ValueError):
        hash_string("hello", "sha512")


def test_hash_with_salt_append():
    expected = hashlib.sha256(b"passwordSALT").hexdigest()
    assert hash_with_salt("password", "SALT", "sha256", "append") == expected


def test_hash_with_salt_prepend():
    expected = hashlib.sha256(b"SALTpassword").hexdigest()
    assert hash_with_salt("password", "SALT", "sha256", "prepend") == expected


def test_hash_with_salt_rejects_bad_position():
    with pytest.raises(ValueError):
        hash_with_salt("password", "SALT", "sha256", "middle")


def test_verify_hash_true_and_false():
    digest = hash_string("secret", "md5")
    assert verify_hash(digest, digest) is True
    assert verify_hash(digest, "0" * 32) is False


def test_verify_hash_is_case_insensitive():
    digest = hash_string("secret", "md5")
    assert verify_hash(digest.upper(), digest.lower()) is True


@pytest.mark.parametrize(
    "algorithm,expected_len", [("md5", 32), ("sha1", 40), ("sha256", 64)]
)
def test_identify_algorithm_by_length(algorithm, expected_len):
    digest = hash_string("anything", algorithm)
    assert digest in identify_algorithm(digest) or algorithm in identify_algorithm(digest)
    assert len(digest) == expected_len


def test_identify_algorithm_rejects_non_hex():
    assert identify_algorithm("not-a-hash!!") == []
