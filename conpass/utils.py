from datetime import datetime, timedelta, timezone


def win_timestamp_to_datetime(ts):
    us = (ts - 116444736000000000) // 10
    return (datetime(1970, 1, 1) + timedelta(microseconds=us)).replace(tzinfo=timezone.utc)
