"""Time-related utilities."""

from datetime import datetime, timedelta, timezone

# 100-nanosecond intervals between 1601-01-01 (FILETIME epoch) and 1970-01-01
WINDOWS_TICKS_TO_UNIX_EPOCH = 116444736000000000
FILETIME_NEVER = 0x7FFFFFFFFFFFFFFF


def win_timestamp_to_datetime(timestamp: int) -> datetime:
    """
    Convert Windows FILETIME timestamp to datetime.

    Windows FILETIME is a 64-bit value representing the number of 100-nanosecond
    intervals since January 1, 1601 (UTC).

    Args:
        timestamp: Windows FILETIME timestamp

    Returns:
        datetime object in UTC
    """
    return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(
        microseconds=(timestamp - WINDOWS_TICKS_TO_UNIX_EPOCH) // 10
    )


def filetime_to_datetime(timestamp: int) -> datetime | None:
    """Convert an AD FILETIME attribute to datetime, None when unset (0) or 'never'."""
    if timestamp <= 0 or timestamp >= FILETIME_NEVER:
        return None
    return win_timestamp_to_datetime(timestamp)


def dc_now(time_delta: timedelta) -> datetime:
    """Current time on the domain controller clock."""
    return datetime.now(timezone.utc) - time_delta
