import hashlib
import io
import json
import urllib.error

import pytest

from passguard import analyze
from passguard.breach import BreachCheckError, parse_range, pwned_count
from passguard.cli import main
from passguard.core import apply_breach_count

SHA1_PASSWORD = hashlib.sha1(b"password").hexdigest().upper()
PREFIX, SUFFIX = SHA1_PASSWORD[:5], SHA1_PASSWORD[5:]


class FakeResponse:
    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self.body.encode("utf-8")


def opener_returning(body):
    def _open(request, timeout=None):
        return FakeResponse(body)

    return _open


def test_only_the_hash_prefix_is_sent():
    seen = {}

    def opener(request, timeout=None):
        seen["url"] = request.full_url
        return FakeResponse("0000000000000000000000000000000000A:1\n")

    pwned_count("password", opener=opener)
    path = seen["url"].split("/range/", 1)[1]
    assert path == PREFIX  # exactly 5 hex characters and nothing else
    assert SUFFIX not in seen["url"]


def test_count_found_and_not_found():
    body = f"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:2\r\n{SUFFIX}:9545824\r\n"
    assert pwned_count("password", opener=opener_returning(body)) == 9545824
    assert pwned_count("password", opener=opener_returning("AAAA:1\n")) == 0


def test_padding_entries_with_zero_count_are_not_hits():
    assert parse_range(f"{SUFFIX}:0\n", SUFFIX) == 0


def test_network_errors_become_breach_check_error():
    def failing(request, timeout=None):
        raise urllib.error.URLError("offline")

    with pytest.raises(BreachCheckError):
        pwned_count("password", opener=failing)


def test_apply_breach_count_marks_password_compromised():
    result = apply_breach_count(analyze("vT9#kLq2!xZp7@mWd4&R"), 42)
    assert result.rating == "Compromised" and result.score == 0
    assert result.breach_count == 42
    assert any("42" in issue for issue in result.issues)


def test_apply_breach_count_zero_leaves_rating_alone():
    before = analyze("vT9#kLq2!xZp7@mWd4&R")
    after = apply_breach_count(analyze("vT9#kLq2!xZp7@mWd4&R"), 0)
    assert after.rating == before.rating and after.breach_count == 0


def run_check(monkeypatch, capsys, args, password="vT9#kLq2!xZp7@mWd4&R"):
    monkeypatch.setattr("sys.stdin", io.StringIO(password + "\n"))
    code = main(["check", "--stdin", *args])
    return code, capsys.readouterr()


def test_cli_breach_check_reports_hits(monkeypatch, capsys):
    monkeypatch.setattr("passguard.cli.pwned_count", lambda pw: 1234)
    code, out = run_check(monkeypatch, capsys, ["--breach-check", "--json"])
    data = json.loads(out.out)
    assert code == 0
    assert data["breach_count"] == 1234 and data["rating"] == "Compromised"


def test_cli_breach_check_failure_is_a_warning_not_a_crash(monkeypatch, capsys):
    def boom(pw):
        raise BreachCheckError("offline")

    monkeypatch.setattr("passguard.cli.pwned_count", boom)
    code, out = run_check(monkeypatch, capsys, ["--breach-check"])
    assert code == 0
    assert "breach check skipped" in out.err
    assert "Breaches" not in out.out


def test_cli_min_score_sets_exit_status(monkeypatch, capsys):
    code, _ = run_check(monkeypatch, capsys, ["--min-score", "60"], password="password")
    assert code == 1
    code, _ = run_check(monkeypatch, capsys, ["--min-score", "60"])
    assert code == 0
