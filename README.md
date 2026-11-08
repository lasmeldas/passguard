# passguard

[![CI](https://github.com/lasmeldas/passguard/actions/workflows/ci.yml/badge.svg)](https://github.com/lasmeldas/passguard/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

An offline password strength analyzer and secure generator for the command line. It estimates how long a password would survive an offline attack, explains what's wrong with it, and never sends anything over the network.

## Features

- **Entropy estimate** based on length and character variety, reduced for patterns attackers try first.
- **Pattern detection:** repeated characters, keyboard and alphabet sequences (`qwerty`, `abc`, `987`), years, common passwords, and leetspeak tricks like `p@ssw0rd`.
- **Readable output:** a rating, a 0-100 score, an estimated offline cracking time, and concrete suggestions.
- **Secure by design:** the password is read with hidden input (or stdin), never from command-line arguments, and is never included in the result.
- **Generator** using Python's `secrets` module.
- **Zero dependencies**, with tests and CI on Python 3.9, 3.11 and 3.13.

## Install

```bash
git clone https://github.com/lasmeldas/passguard.git
cd passguard
pip install -e .
```

## Usage

Check a password (input is hidden):

```console
$ passguard check
Password to check (input hidden):
Strength : Very weak (score 15/100)
Entropy  : ~12.0 bits
Cracking : instantly (offline, 10 billion guesses/s)
Issues:
  - This is a very common password.
Suggestions:
  - Use at least 12 characters; 16 or more is better.
  - Try a passphrase of 4+ unrelated random words.
  - Use a password manager and a unique password for every site.
```

Machine-readable output, for scripts:

```bash
printf '%s\n' "$PASSWORD" | passguard check --stdin --json
```

Generate passwords:

```bash
passguard generate               # one 16-character password
passguard generate -l 24 -n 5    # five 24-character passwords
passguard generate --no-symbols  # letters and digits only
```

Use it as a library:

```python
from passguard import analyze, generate

result = analyze("correct-horse-battery-staple")
print(result.rating, result.entropy_bits, result.crack_time)
print(generate(20))
```

## How scoring works

1. Work out the **alphabet size** from the character classes used (lowercase, uppercase, digits, symbols, other).
2. Take the **effective length**: runs of 3+ repeated characters count once, each sequence keeps only one character of value, years count as about two characters, and common words are subtracted.
3. `entropy = effective_length × log2(alphabet size)`. Exact matches to common passwords are capped at 12 bits.
4. Rating by entropy: under 28 *Very weak*, under 36 *Weak*, under 60 *Fair*, under 80 *Strong*, otherwise *Very strong*. The score is `entropy / 80`, capped at 100.
5. Cracking time assumes an attacker making 10 billion guesses per second and finding the password halfway through.

## Limitations

This is a heuristic teaching tool, not a guarantee. It knows a small built-in list of common passwords rather than a full breach database, and it can't know your personal details. Treat the result as a guide, and use a password manager with unique passwords everywhere.

## Development

```bash
pip install -e . pytest
pytest -q
```

## License

[MIT](LICENSE)
