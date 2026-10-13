"""Tables displayed to the user."""

from collections import Counter
from datetime import datetime

from rich.table import Table

from conpass.database import NOTE_UNCONFIRMED, Database
from conpass.lockout import User
from conpass.output import console
from conpass.targets import Targets


def print_policies(targets: Targets) -> None:
    """Password policies with the number of enabled users under each of them."""
    table = Table(title="Password policies")
    for column in (
        "Name",
        "Lockout threshold",
        "Observation window (s)",
        "Lockout duration (s)",
        "Min length",
        "History",
        "Max age (days)",
        "Min age (days)",
        "Complexity",
        "Enabled users",
    ):
        table.add_column(column)
    for policy in targets.policies:
        table.add_row(
            policy.name,
            str(policy.lockout_threshold),
            str(policy.lockout_window_seconds),
            str(policy.lockout_duration_seconds),
            str(policy.min_pwd_length),
            str(policy.pwd_history_length),
            str(policy.max_pwd_age_days),
            str(policy.min_pwd_age_days),
            "Yes" if policy.complexity_enabled else "No",
            str(targets.user_counts.get(policy.name, 0)),
        )
    readable = {policy.name for policy in targets.policies}
    for name, count in targets.user_counts.items():
        if name not in readable:
            table.add_row(name, *["?"] * 8, str(count), style="bright_black")
    console.print(table)


def print_bad_password_counts(users: list[User], now: datetime) -> None:
    """Distribution of the bad password counters that still matter (within the window)."""
    if not users or not users[0].online:
        return
    counts = Counter("locked out" if user.lockout_end(now) else user.effective_bad_count(now) for user in users)
    table = Table(title="Current bad password count")
    table.add_column("Bad password count")
    table.add_column("Users")
    for key in sorted(counts, key=lambda k: (isinstance(k, str), k if isinstance(k, int) else 0)):
        table.add_row(str(key), str(counts[key]))
    console.print(table)


def print_found_credentials(database: Database, domain: str) -> None:
    """Credentials and previous passwords stored in the database for a domain."""
    total, valid = database.stats()
    console.print(f"[cyan]{database.path}: {total} tests recorded for {domain}, {valid} valid credential(s)[/cyan]")

    found = database.found_credentials()
    if found:
        table = Table(title=f"Valid credentials ({len(found)})")
        table.add_column("Username", style="cyan")
        table.add_column("Password", style="green")
        table.add_column("Note", style="bright_black")
        for username, password, note in sorted(found):
            table.add_row(username, password, "may be the previous password" if note == NOTE_UNCONFIRMED else "")
        console.print(table)

    previous = database.previous_passwords()
    if previous:
        table = Table(title=f"Previous passwords ({len(previous)})")
        table.add_column("Username", style="cyan")
        table.add_column("Previous password", style="magenta")
        for username, password in sorted(previous):
            table.add_row(username, password)
        console.print(table)
