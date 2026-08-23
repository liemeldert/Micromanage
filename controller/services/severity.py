"""The one rank table for the alert severity scale.

Shared by Dispatcher board and ATC gate ladder. Unknown values rank 0 and escalate unchanged.
See docs/controller/services/severity.md for design rationale, including ALIASES and the planned rename.
"""

from typing import Dict, List

# Ascending: the last entry is the top of the ladder and escalates to itself.
ORDER: List[str] = ["green", "yellow", "red", "black"]

# One-based, so UNKNOWN_RANK below sits under every real value.
RANK: Dict[str, int] = {name: i + 1 for i, name in enumerate(ORDER)}

# What a value nobody recognises ranks. Read the module docstring before changing it.
UNKNOWN_RANK = 0

# One rung up, with the top pinned to itself.
ESCALATE: Dict[str, str] = {
    name: ORDER[min(i + 1, len(ORDER) - 1)] for i, name in enumerate(ORDER)
}

# Old name to current name. Empty until the rename.
ALIASES: Dict[str, str] = {}


def canonical(value: str) -> str:
    """Map old severity names to current names via ALIASES; identity when empty.

    Does not lowercase, strip, or coerce; those belong to the planned rename.
    """
    return ALIASES.get(value, value)


def rank(value: str) -> int:
    """Board rank: higher is more severe, UNKNOWN_RANK for anything unrecognised."""
    return RANK.get(canonical(value), UNKNOWN_RANK)


def escalate(value: str) -> str:
    """One step up the ladder, capped at the top. Unknown values come back unchanged."""
    return ESCALATE.get(canonical(value), value)
