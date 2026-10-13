"""Helpers for NT/LM hashes, accepted both as credentials and in password files."""

import re

_HASH_PATTERN = re.compile(r"^[0-9a-fA-F]{32}$")


def is_nt_hash(value: str) -> bool:
    """True if the value looks like an NT hash (32 hex characters), sprayed as pass-the-hash."""
    return bool(_HASH_PATTERN.match(value))


def parse_hashes(hashes: str) -> tuple[str, str]:
    """
    Parse hashes given as LM:NT, :NT or NT.

    Returns:
        (lm_hash, nt_hash), lm_hash being empty when not provided

    Raises:
        ValueError: If a hash is not 32 hexadecimal characters
    """
    lm_hash, _, nt_hash = hashes.rpartition(":")
    for value in filter(None, (lm_hash, nt_hash)):
        if not is_nt_hash(value):
            msg = f"Invalid hash format: {value} (expected LM:NT, :NT or NT)"
            raise ValueError(msg)
    if not nt_hash:
        msg = "The NT hash is missing (expected LM:NT, :NT or NT)"
        raise ValueError(msg)
    return lm_hash, nt_hash
