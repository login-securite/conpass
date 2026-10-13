"""Utility functions and helpers."""

from conpass.utils.dns import find_pdc_hostname, resolve_hostname
from conpass.utils.hash import is_nt_hash, parse_hashes, format_hash_for_ldap
from conpass.utils.logger import get_logger
from conpass.utils.ntlm import NtlmInfo
from conpass.utils.time import dc_now, filetime_to_datetime, win_timestamp_to_datetime


def read_file_blocks(file_handle, block_size: int = 8192):
    """
    Read a file in blocks for efficient memory usage.

    Args:
        file_handle: Open file handle
        block_size: Size of each block to read

    Yields:
        Blocks of text from the file
    """
    while True:
        block = file_handle.read(block_size)
        if not block:
            break
        yield block


__all__ = [
    "get_logger",
    "is_nt_hash",
    "parse_hashes",
    "format_hash_for_ldap",
    "NtlmInfo",
    "dc_now",
    "filetime_to_datetime",
    "find_pdc_hostname",
    "resolve_hostname",
    "win_timestamp_to_datetime",
    "read_file_blocks",
]
