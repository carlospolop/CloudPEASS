"""Shared helpers for optional, potentially slow PEASS operations."""

from __future__ import annotations

import sys
from typing import Callable


def confirm_slow_operation(
    description: str,
    *,
    force: bool = False,
    no_ask: bool = False,
    input_func: Callable[[str], str] = input,
) -> bool:
    """Return whether an optional slow operation should run.

    force is the explicit CLI opt-in and bypasses the prompt. no_ask never
    silently opts into expensive enumeration; it selects the safe default and
    skips the operation. Non-interactive stdin behaves the same way.
    """

    if force:
        return True
    if no_ask or not sys.stdin.isatty():
        return False

    try:
        answer = input_func(f"{description} [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in {"y", "yes"}
