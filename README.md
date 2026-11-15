# ConPass

[![PyPI version](https://badge.fury.io/py/conpass.svg)](https://pypi.org/project/conpass)
[![PyPI Statistics](https://img.shields.io/pypi/dm/conpass.svg)](https://pypistats.org/packages/conpass)
[![Twitter](https://img.shields.io/twitter/follow/hackanddo?label=HackAndDo&style=social)](https://twitter.com/intent/follow?screen_name=hackanddo)

Python tool for continuous password spraying taking into account the password policy.

## Associated Blogposts
* English: https://en.hackndo.com/password-spraying-lockout/
* French: https://www.login-securite.com/blog/spray-passwords-avoid-lockouts

## Warning

Although this tool implements robust thread-safe anti-lockout protection, there can still be edge cases where accounts might be locked out. Always use with caution in production environments.

## N-1 / N-2 Password History Rule

ConPass implements detection of Active Directory's **N-2 Rule** behavior:

> When a user attempts to authenticate with either of their two most recently used historical passwords (n-1 or n-2), authentication fails but the `badPwdCount` attribute is **not incremented**. This avoids punishing users who accidentally try to authenticate with a recently changed password.

### How it works

1. Before each authentication attempt, ConPass reads `badPwdCount` from LDAP
2. After a failed authentication, it re-reads `badPwdCount`
3. If `badPwdCount` is unchanged, the password is flagged as a **potential n-1/n-2 history match**

These candidates are:
- Displayed in yellow with `(potential history match)` during the spray
- Persisted to the SQLite database (if `--database` is used)
- Shown in an end-of-run summary table
- Skipped in subsequent runs (they're known to be previous passwords, not the current one)

⚠️ **Limitations:**
- **Offline mode** (`--user-file` without LDAP) cannot detect history candidates — this requires LDAP to read `badPwdCount`
- **False positives**: `badPwdCount` may also remain unchanged due to DC replication delay, account restrictions, or other factors. Treat candidates as *suspected* matches, not confirmed.
- **Detection timing**: AD takes a moment to update `badPwdCount` after a failed authentication. conpass waits `--n2-detection-delay` seconds (default: 1s) before re-querying LDAP. Increase this if you see too many false positives, or decrease it to speed up spraying.

## Installation

**conpass** works with python >= 3.10

### From source

```bash
cd conpass
pipx install .
```

## Usage

**conpass** will get all domain users and try a list of passwords provided in a password file. When a user can be locked out, the tool will wait for the lockout reset period before trying another password.

```bash
conpass -d domain.local -u pixis -p P4ssw0rd -P /tmp/passwords.txt
```

All passwords provided in `/tmp/passwords.txt` will be added to a testing Queue, and will be tested against all users, whenever it is possible without locking users out.

### Security Threshold

The security threshold (`-s`, default: 2) provides a safety margin before the lockout threshold. For example:
- Lockout threshold: 5
- Security threshold: 2
- Maximum tests per user: 3

This accounts for potential concurrent authentications from the user or other tools.

## License

MIT
