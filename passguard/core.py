"""Password analysis: an entropy estimate reduced by common-pattern penalties.

Nothing here touches the network, and the analysis result never contains the
password itself.
"""

from __future__ import annotations

import math
import re
import secrets
import string
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

# Rough speed of an offline attack on a fast hash using a GPU rig.
GUESSES_PER_SECOND = 1e10

COMMON_PASSWORDS = frozenset(
    """
    password 123456 123456789 12345678 12345 1234567 1234567890 qwerty qwerty123
    abc123 password1 password123 iloveyou admin welcome login letmein monkey
    dragon football baseball master sunshine princess shadow superman trustno1
    passw0rd 111111 000000 123123 654321 666666 121212 qazwsx qwertyuiop
    1q2w3e4r 1qaz2wsx zaq12wsx changeme secret hello freedom whatever starwars
    batman flower hunter ranger
    """.split()
)

# Rows a person might type in order; also checked in reverse.
_ROWS = (
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)

# Undo common letter-for-symbol swaps (p@ssw0rd -> password).
_LEET = str.maketrans(
    {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"}
)

_RATINGS = (
    (28, "Very weak"),
    (36, "Weak"),
    (60, "Fair"),
    (80, "Strong"),
)


@dataclass
class Analysis:
    """Result of analyzing one password. Never stores the password itself."""

    length: int
    entropy_bits: float
    score: int
    rating: str
    crack_time: str
    issues: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)
    breach_count: Optional[int] = None  # None means "not checked"

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def charset_size(password: str) -> int:
    """Size of the alphabet an attacker would need to cover for this password."""
    pool = 0
    if any(c.isascii() and c.islower() for c in password):
        pool += 26
    if any(c.isascii() and c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() and c.isascii() for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += len(string.punctuation)
    if any(not c.isascii() or c.isspace() for c in password):
        pool += 32
    return pool


def find_sequences(password: str) -> List[str]:
    """Return runs of 3+ characters that follow a row or the alphabet, forwards or backwards."""
    lowered = password.lower()
    found: List[str] = []
    i = 0
    while i < len(lowered) - 2:
        best = 0
        for row in _ROWS:
            for seq in (row, row[::-1]):
                j = i
                while j + 1 < len(lowered):
                    pos = seq.find(lowered[j])
                    if pos == -1 or seq[pos + 1 : pos + 2] != lowered[j + 1]:
                        break
                    j += 1
                best = max(best, j - i + 1)
        if best >= 3:
            found.append(password[i : i + best])
            i += best
        else:
            i += 1
    return found


def humanize_seconds(seconds: float) -> str:
    """Turn a duration into something a person can read."""
    if seconds < 1:
        return "instantly"
    units = (
        (60, "second", 1),
        (3600, "minute", 60),
        (86400, "hour", 3600),
        (86400 * 365, "day", 86400),
    )
    for limit, name, size in units:
        if seconds < limit:
            value = int(seconds // size)
            return f"{value} {name}{'s' if value != 1 else ''}"
    years = seconds / (86400 * 365)
    if years < 1000:
        value = int(years)
        return f"{value} year{'s' if value != 1 else ''}"
    if years < 1e6:
        return f"~{years / 1e3:.0f} thousand years"
    if years < 1e9:
        return f"~{years / 1e6:.0f} million years"
    return "billions of years or more"


def analyze(password: str) -> Analysis:
    """Estimate how hard a password would be to guess offline."""
    if not password:
        return Analysis(
            length=0,
            entropy_bits=0.0,
            score=0,
            rating="Very weak",
            crack_time="instantly",
            issues=["The password is empty."],
            suggestions=["Use a long passphrase or a generated password."],
        )

    issues: List[str] = []
    pool = charset_size(password)

    # Collapse runs of 3+ like "aaaa" into one character: they add almost no strength.
    collapsed = re.sub(r"(.)\1{2,}", r"\1", password)
    effective = len(collapsed)
    if len(collapsed) < len(password):
        issues.append("Contains repeated characters.")

    for run in find_sequences(collapsed):
        effective -= len(run) - 1
        issues.append(f"Contains a predictable sequence ({len(run)} characters).")

    years = re.findall(r"(?:19|20)\d{2}", password)
    if years:
        effective -= 2 * len(years)
        issues.append("Contains a year, which is easy to guess.")

    lowered = password.lower()
    stripped = re.sub(r"[\d\W_]+$", "", lowered)
    candidates = {lowered, lowered.translate(_LEET), stripped, stripped.translate(_LEET)}
    is_common = any(c in COMMON_PASSWORDS for c in candidates)
    if is_common:
        issues.append("This is a very common password.")
    else:
        for word in COMMON_PASSWORDS:
            if len(word) >= 5 and any(word in c for c in candidates):
                effective -= len(word)
                issues.append("Contains a very common password or word.")
                break

    if len(password) < 8:
        issues.append("Shorter than 8 characters.")

    effective = max(effective, 0)
    entropy = effective * math.log2(pool) if pool > 1 else 0.0
    if is_common:
        entropy = min(entropy, 12.0)
    entropy = round(entropy, 1)

    rating = "Very strong"
    for limit, label in _RATINGS:
        if entropy < limit:
            rating = label
            break
    score = min(100, round(entropy / 80 * 100))

    seconds = (2.0 ** (min(entropy, 1000) - 1)) / GUESSES_PER_SECOND
    crack_time = humanize_seconds(seconds)

    suggestions: List[str] = []
    if rating in ("Very weak", "Weak", "Fair"):
        if len(password) < 12:
            suggestions.append("Use at least 12 characters; 16 or more is better.")
        suggestions.append("Try a passphrase of 4+ unrelated random words.")
        suggestions.append("Use a password manager and a unique password for every site.")

    return Analysis(
        length=len(password),
        entropy_bits=entropy,
        score=score,
        rating=rating,
        crack_time=crack_time,
        issues=issues,
        suggestions=suggestions,
    )


def generate(length: int = 16, symbols: bool = True) -> str:
    """Generate a random password with the OS secure random source."""
    if length < 8:
        raise ValueError("length must be at least 8")
    classes = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        classes.append("!@#$%^&*()-_=+[]{};:,.?")
    alphabet = "".join(classes)
    chars = [secrets.choice(c) for c in classes]  # guarantee one of each class
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def apply_breach_count(result: Analysis, count: int) -> Analysis:
    """Fold a breach-lookup result into an analysis.

    A password found in public breach lists is unsafe however random it looks.
    """
    result.breach_count = count
    if count > 0:
        result.issues.append(f"Found in known data breaches {count:,} times.")
        result.rating = "Compromised"
        result.score = 0
        result.crack_time = "instantly (it is in public breach lists)"
        result.suggestions.insert(0, "Stop using this password everywhere and choose a new one.")
    return result
