import pytest

from hashcracker.candidates import (
    build_charset,
    chunked,
    count_bruteforce_space,
    iter_bruteforce,
    iter_wordlist,
)


def test_build_charset_lowercase_only():
    charset = build_charset(lowercase=True)
    assert charset == "abcdefghijklmnopqrstuvwxyz"


def test_build_charset_combines_classes_without_duplicates():
    charset = build_charset(lowercase=True, digits=True, custom="a1!")
    assert charset.count("a") == 1
    assert charset.count("1") == 1
    assert "!" in charset


def test_build_charset_empty_raises():
    with pytest.raises(ValueError):
        build_charset(lowercase=False)


def test_count_bruteforce_space():
    # charset of size 2, lengths 1..2 => 2^1 + 2^2 = 6
    assert count_bruteforce_space(2, 1, 2) == 6


def test_iter_bruteforce_order_and_count():
    results = list(iter_bruteforce("ab", 1, 2))
    assert results[0] == "a"
    assert results[1] == "b"
    assert set(results[2:]) == {"aa", "ab", "ba", "bb"}
    assert len(results) == 6


def test_iter_bruteforce_rejects_bad_lengths():
    with pytest.raises(ValueError):
        list(iter_bruteforce("ab", 0, 2))
    with pytest.raises(ValueError):
        list(iter_bruteforce("ab", 3, 2))


def test_iter_wordlist_reads_and_strips_lines(tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("password\n123456\n\nletmein\n")
    assert list(iter_wordlist(str(wordlist))) == ["password", "123456", "letmein"]


def test_iter_wordlist_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        list(iter_wordlist(str(tmp_path / "nope.txt")))


def test_chunked_splits_into_expected_batches():
    batches = list(chunked(range(10), 3))
    assert batches == [[0, 1, 2], [3, 4, 5], [6, 7, 8], [9]]


def test_chunked_empty_iterable():
    assert list(chunked([], 5)) == []
