import json
import string

import pytest

from passguard import analyze, generate
from passguard.cli import main
from passguard.core import charset_size, find_sequences, humanize_seconds


def test_empty_password_is_very_weak():
    result = analyze("")
    assert result.score == 0
    assert result.rating == "Very weak"


def test_common_password_is_capped():
    result = analyze("password")
    assert result.rating == "Very weak"
    assert any("common" in i.lower() for i in result.issues)


def test_leetspeak_common_password_is_caught():
    assert analyze("p@ssw0rd").rating == "Very weak"


def test_trailing_digits_do_not_hide_common_password():
    assert analyze("Password123!").rating in ("Very weak", "Weak")


def test_repeated_characters_are_penalized():
    assert analyze("aaaaaaaaaaaaaaaa").entropy_bits < analyze("abXk29Qz!pLmWn4r").entropy_bits
    assert any("repeated" in i.lower() for i in analyze("aaaaaaaa").issues)


def test_sequences_detected_forward_and_backward():
    assert find_sequences("xx123yy") == ["123"]
    assert find_sequences("zzcbayy") == ["cba"]
    assert find_sequences("qwerty") == ["qwerty"]
    assert find_sequences("ab") == []


def test_long_random_password_is_strong():
    result = analyze("vT9#kLq2!xZp7@mWd4&R")
    assert result.rating in ("Strong", "Very strong")
    assert result.suggestions == []


def test_year_is_flagged():
    assert any("year" in i.lower() for i in analyze("Sunshine2024xyz").issues)


def test_analysis_never_contains_password():
    secret = "S3cret-Value-Here!"
    assert secret not in json.dumps(analyze(secret).to_dict())


def test_charset_size():
    assert charset_size("abc") == 26
    assert charset_size("aB3") == 26 + 26 + 10
    assert charset_size("a!") == 26 + len(string.punctuation)


def test_humanize_seconds():
    assert humanize_seconds(0.2) == "instantly"
    assert humanize_seconds(30) == "30 seconds"
    assert humanize_seconds(3600 * 5) == "5 hours"
    assert humanize_seconds(86400 * 365 * 5) == "5 years"
    assert "billions" in humanize_seconds(1e30)


def test_generate_contains_every_class():
    for _ in range(50):
        pw = generate(16)
        assert len(pw) == 16
        assert any(c.islower() for c in pw)
        assert any(c.isupper() for c in pw)
        assert any(c.isdigit() for c in pw)
        assert any(not c.isalnum() for c in pw)


def test_generate_without_symbols_and_bad_length():
    assert generate(20, symbols=False).isalnum()
    with pytest.raises(ValueError):
        generate(4)


def test_cli_check_stdin_json(monkeypatch, capsys):
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO("hunter2\n"))
    assert main(["check", "--stdin", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["length"] == 7
    assert "hunter2" not in json.dumps(data)


def test_cli_generate(capsys):
    assert main(["generate", "-l", "12", "-n", "3"]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 3 and all(len(line) == 12 for line in lines)
    assert main(["generate", "-l", "3"]) == 2
