"""passguard: a small, offline password strength analyzer and generator."""

from .breach import BreachCheckError, pwned_count
from .core import Analysis, analyze, apply_breach_count, generate

__all__ = ["Analysis", "BreachCheckError", "analyze", "apply_breach_count", "generate", "pwned_count"]
__version__ = "0.2.0"
