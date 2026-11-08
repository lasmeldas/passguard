"""passguard: a small, offline password strength analyzer and generator."""

from .core import Analysis, analyze, generate

__all__ = ["Analysis", "analyze", "generate"]
__version__ = "0.1.0"
