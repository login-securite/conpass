"""Conversions between Active Directory time formats and datetime."""

from datetime import datetime, timedelta, timezone

# Number of 100-nanosecond intervals between 1601-01-01 (FILETIME epoch) and 1970-01-01
_FILETIME_UNIX_EPOCH = 116444736000000000
_FILETIME_NEVER = 0x7FFFFFFFFFFFFFFF
# Value of interval attributes (maxPwdAge, lockoutDuration...) meaning "never" / "forever"
_INTERVAL_NEVER = -0x8000000000000000


def filetime_to_datetime(filetime: int) -> datetime | None:
    """
    Convert a FILETIME attribute (badPasswordTime, lockoutTime...) to an aware datetime.

    Returns:
        The UTC datetime, or None when the attribute is unset (0) or set to "never"
    """
    if filetime <= 0 or filetime >= _FILETIME_NEVER:
        return None
    return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=(filetime - _FILETIME_UNIX_EPOCH) // 10)


def interval_to_seconds(interval: int) -> int:
    """
    Convert an interval attribute (stored as a negative number of 100 ns units) to seconds.

    Returns:
        The duration in seconds, 0 when the attribute means "never" or "forever"
    """
    if interval == _INTERVAL_NEVER:
        return 0
    return abs(interval) // 10_000_000


def dc_now(time_delta: timedelta) -> datetime:
    """
    Current time on the domain controller clock.

    Args:
        time_delta: Local clock minus DC clock
    """
    return datetime.now(timezone.utc) - time_delta
