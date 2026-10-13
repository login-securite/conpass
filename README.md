# conpass

[![PyPI version](https://badge.fury.io/py/conpass.svg)](https://pypi.org/project/conpass)
[![Twitter](https://img.shields.io/twitter/follow/hackanddo?label=HackAndDo&style=social)](https://twitter.com/intent/follow?screen_name=hackanddo)

Continuous password spraying for Active Directory, as fast as the password policy allows, without locking accounts out.

conpass reads every user's effective password policy (domain policy or fine-grained PSO) and bad password counter on the PDC Emulator, then tries each password as soon as it is safe for that user. Passwords can be added to the password file while it runs.

## Blog posts

- English: https://en.hackndo.com/password-spraying-lockout/
- French: https://www.login-securite.com/blog/spray-passwords-avoid-lockouts

## Warning

conpass does its best to find the effective policy of each account, but a policy it cannot see (for example a PSO it is not allowed to read) can still lead to lockouts. Use it with caution in production environments. In an emergency:

```powershell
Search-ADAccount -LockedOut | Unlock-ADAccount
```

## Installation

conpass requires Python 3.10 or later.

```bash
pipx install conpass
# or, from the sources
pipx install git+https://github.com/login-securite/conpass
```

## Usage

```bash
conpass -d hackn.lab -u pixis -p 'P4ssw0rd' -P passwords.txt
```

Every password of `passwords.txt` is sprayed on every enabled user, one password on all users before the next one. Users who have no attempt left wait for their observation window to elapse, without blocking the others. The file is watched: passwords added to it later are queued too, and conpass keeps running until `Ctrl+C`.

Common options:

| Option | Description |
| --- | --- |
| `-d, --domain` | Domain to spray (FQDN) |
| `-u, --username` / `-p, --password` / `-H, --hashes` | Domain account used to read users and policies. Use `DOMAIN\user` to authenticate in another trusted domain |
| `-D, --dc-ip` | Any domain controller: the PDC Emulator is found from there |
| `--dns-ip` | DNS server, by default `--dc-ip` |
| `--ldaps` | Only use LDAPS (see below) |
| `-P, --password-file` | Passwords to spray, one per line. A 32 hexadecimal characters line is sprayed as an NT hash |
| `-U, --user-file` | Only spray these users |
| `-a, --user-as-pass` | Also try each username as password |
| `-s, --security-threshold` | Attempts always left unused below the lockout threshold (default 2, minimum 1) |
| `-db, --database` | SQLite database of tested credentials (default `~/.config/conpass/conpass.db`) |
| `--show` | Display the credentials found for a domain |
| `--disable-spray` | Only display the policies and users |
| `-m, --max-threads` | Number of parallel workers (default 10) |

### Resuming and results

Every test is recorded in the database, so an interrupted session can be resumed: passwords already tested on a user are skipped, and users whose password was found are not sprayed again.

```bash
conpass -d hackn.lab --show
```

### LDAP signing and channel binding

By default conpass connects with LDAP on port 389, authenticating with NTLM and signing and sealing every message, which works whether or not the domain controller requires LDAP signing. If it fails, LDAPS (port 636) is tried, with the channel binding token, which works whether or not the domain controller requires channel binding. `--ldaps` only uses LDAPS.

### Offline mode

Without domain credentials, give the users and the policy to assume. No lockout state can be read, so conpass relies on its own count of failures only:

```bash
conpass -d hackn.lab -D 10.0.0.1 -U users.txt -t 5 -o 1800 -P passwords.txt
```

## How it avoids lockouts

The logic follows what domain controllers actually do:

- **Everything goes through the PDC Emulator.** `badPwdCount` and `badPasswordTime` are not replicated: a failure on another DC is forwarded to the PDC, which holds the authoritative counter and decides the lockout. conpass finds the PDC (`fSMORoleOwner`, or the `_ldap._tcp.pdc._msdcs` DNS record), reads the counters there and authenticates there, so the counter it reads is the counter its attempts move. This also avoids the cases where a DC does not forward failures to the PDC.
- **Nothing is reset by a timer.** When `badPasswordTime` is older than the observation window, the next failure restarts the counter at 1, whatever `badPwdCount` still contains. conpass computes the effective counter the same way, on the PDC clock.
- **The counter is read before every attempt**, so failures of the users themselves are taken into account, and a local estimate of conpass' own failures is kept as a floor in case a read lags behind.
- **Locked out accounts are detected** with `msDS-User-Account-Control-Computed` (the lockout bit of `userAccountControl` is never set), and are only retried once their lockout is over.
- **An attempt lost on a dropped connection is never replayed blindly**: it is counted as a failure first.
- **Spraying stops at the first lockout.** Attempts already running at that moment may still lock one account each, so a wrong policy can lock out up to one account per worker.

## What it detects

- **Valid passwords**, including when the logon is refused for another reason: expired password, password to change, expired or disabled account, logon hours or workstation restrictions. These answers are only given once the password is validated.
- **Previous passwords.** The DC does not count a failure with one of the two previous passwords (N-1, N-2): when `badPasswordTime` does not move after a failure, the password is reported as a previous one. They often reveal how a user builds passwords.
- **NTLM grace period.** For a few minutes after a password change, NTLM still accepts the previous password. A success on a recently changed password is confirmed with Kerberos, which rejects the previous password without counting a failure. Successes that Kerberos cannot confirm are flagged.

Accounts in Protected Users cannot authenticate with NTLM and are skipped.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check . && ruff format --check .
```

The tests include a simulated PDC applying the lockout rules above, with users failing their own logons and dropped connections, to check that spraying never locks an account out.

## License

MIT
