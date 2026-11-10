"""Optional breach lookup using the Have I Been Pwned range API (k-anonymity).

Only the first 5 characters of the password's SHA-1 hash leave your machine. The
server returns every known hash suffix with that prefix, and the comparison
happens locally, so neither the password nor its full hash is ever sent.
"""

from __future__ import annotations

import hashlib
import urllib.error
import urllib.request
from typing import Callable

API_URL = "https://api.pwnedpasswords.com/range/"


class BreachCheckError(Exception):
    """The breach lookup could not be completed (offline, timeout, bad response)."""


def parse_range(body: str, suffix: str) -> int:
    """Find `suffix` in a range response ("SUFFIX:COUNT" per line) and return its count."""
    suffix = suffix.upper()
    for line in body.splitlines():
        candidate, _, count = line.partition(":")
        if candidate.strip().upper() == suffix:
            try:
                return int(count.strip() or 0)
            except ValueError:
                return 0
    return 0


def pwned_count(
    password: str,
    timeout: float = 5.0,
    opener: Callable = urllib.request.urlopen,
) -> int:
    """How many times the password appears in known breaches (0 if never seen)."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324 (API requires SHA-1)
    prefix, suffix = digest[:5], digest[5:]
    request = urllib.request.Request(
        API_URL + prefix,
        # Padding makes every response a similar size, hiding which prefix matched.
        headers={"User-Agent": "passguard", "Add-Padding": "true"},
    )
    try:
        with opener(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError, OSError, UnicodeDecodeError) as err:
        raise BreachCheckError(str(err)) from err
    return parse_range(body, suffix)
