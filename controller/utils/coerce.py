"""Reading loosely typed values from documents, command params and the environment."""
import os
from typing import Any, List

_TRUE_WORDS = ("1", "true", "yes", "on")


def truthy(value: Any) -> bool:
    """Whether a value reads as a true word once turned into a string. None and False read as false."""
    return str(value).strip().lower() in _TRUE_WORDS


def flag_param(value: Any) -> bool:
    """A document flag as an author would mean it. A string is read as a word, anything else by Python truthiness."""
    if isinstance(value, str):
        return value.strip().lower() in _TRUE_WORDS
    return bool(value)


def str_list(value: Any) -> List[str]:
    """A list or a single value as a list of strings, with empty items dropped."""
    items = value if isinstance(value, list) else ([value] if value else [])
    return [str(x) for x in items if x]


def env_flag(name: str, default: str = "") -> bool:
    """An environment variable read as a true word, at call time. default applies while the variable is unset."""
    return truthy(os.getenv(name, default))
