"""Compatibility wrapper around :mod:`csaf.errors`.

First-run diagnostics used to live only here. New code should import
:mod:`csaf.errors` directly. This module keeps the original function names so
existing tests and call sites continue to work.
"""

from __future__ import annotations

from .errors import ERROR_CODES, explain_exception, format_fatal, from_exception

__all__ = ["ERROR_CODES", "explain_exception", "format_fatal", "from_exception"]
