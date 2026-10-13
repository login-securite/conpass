"""Hashes, time conversions, credentials and database."""

from datetime import datetime, timezone

import pytest

from conpass.config import Credentials
from conpass.database import NOTE_PREVIOUS, Database
from conpass.hashes import is_nt_hash, parse_hashes
from conpass.protocols.ldap import LdapEntry, domain_to_dn, parse_lockout_state
from conpass.timeutils import filetime_to_datetime, interval_to_seconds

NT_HASH = "8846f7eaee8fb117ad06bdd830b7586c"


def test_parse_hashes():
    assert parse_hashes(NT_HASH) == ("", NT_HASH)
    assert parse_hashes(f":{NT_HASH}") == ("", NT_HASH)
    assert parse_hashes(f"{NT_HASH}:{NT_HASH}") == (NT_HASH, NT_HASH)
    with pytest.raises(ValueError, match="Invalid hash"):
        parse_hashes("nothex")


def test_is_nt_hash():
    assert is_nt_hash(NT_HASH)
    assert not is_nt_hash("Password1")


def test_credentials_domain():
    assert Credentials.parse("pixis", "hackn.lab", "pw", None).domain == "hackn.lab"
    credentials = Credentials.parse("OTHER\\pixis", "hackn.lab", None, NT_HASH)
    assert (credentials.domain, credentials.username, credentials.nt_hash) == ("OTHER", "pixis", NT_HASH)


def test_filetime_to_datetime():
    assert filetime_to_datetime(0) is None
    assert filetime_to_datetime(0x7FFFFFFFFFFFFFFF) is None
    assert filetime_to_datetime(116444736000000000) == datetime(1970, 1, 1, tzinfo=timezone.utc)


def test_interval_to_seconds():
    assert interval_to_seconds(-18000000000) == 1800
    assert interval_to_seconds(-0x8000000000000000) == 0


def test_domain_to_dn():
    assert domain_to_dn("hackn.lab") == "DC=hackn,DC=lab"


def test_parse_lockout_state():
    entry = LdapEntry(
        "CN=alice",
        {
            "badpwdcount": [b"3"],
            "badpasswordtime": [b"134046000000000000"],
            "msds-user-account-control-computed": [b"16"],
            "useraccountcontrol": [b"514"],
        },
    )
    state = parse_lockout_state(entry)
    assert state.bad_pwd_count == 3
    assert state.bad_pwd_filetime == 134046000000000000
    assert state.locked
    assert state.disabled
    assert state.lockout_time is None


def test_database_roundtrip(tmp_path):
    database = Database(tmp_path / "conpass.db", "hackn.lab")
    database.record("alice", "Password1", True)
    database.record("bob", "Winter2025", False, NOTE_PREVIOUS)
    database.record("bob", "Winter2025", False, NOTE_PREVIOUS)
    assert database.is_tested("bob", "Winter2025")
    assert database.found_credentials() == [("alice", "Password1", None)]
    assert database.previous_passwords() == [("bob", "Winter2025")]
    assert database.stats() == (2, 1)
    database.close()
    assert Database(tmp_path / "conpass.db", "hackn.lab").is_tested("alice", "Password1")
