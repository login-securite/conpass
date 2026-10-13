"""Command line interface."""

from pathlib import Path
from typing import Annotated

import typer

from conpass import __version__
from conpass.config import Credentials, SprayConfig
from conpass.database import DEFAULT_DATABASE_PATH, Database
from conpass.errors import ConfigurationError, ConpassError
from conpass.lockout import PasswordPolicy
from conpass.orchestrator import Orchestrator
from conpass.output import console, error, set_debug, success, warning
from conpass.report import print_found_credentials
from conpass.targets import read_lines

# Above this number of passwords, ask for confirmation: each password may take a full observation window
LARGE_PASSWORD_FILE = 100

app = typer.Typer(
    context_settings={"help_option_names": ["-h", "--help"]},
    add_completion=False,
    pretty_exceptions_enable=False,
)

AUTH = "Authentication"
TARGET = "Target"
SPRAY = "Spraying"
OFFLINE = "Offline mode (no LDAP access)"


def _version(value: bool) -> None:
    if value:
        console.print(f"conpass {__version__}")
        raise typer.Exit


@app.command()
def main(  # noqa: PLR0913, PLR0917 (one parameter per option)
    domain: Annotated[str, typer.Option("--domain", "-d", help="Domain to spray (FQDN)", rich_help_panel=TARGET)],
    username: Annotated[
        str | None,
        typer.Option(
            "--username",
            "-u",
            help="Domain user, DOMAIN\\user to authenticate in another (trusted) domain",
            rich_help_panel=AUTH,
        ),
    ] = None,
    password: Annotated[
        str | None, typer.Option("--password", "-p", help="Password of the domain user", rich_help_panel=AUTH)
    ] = None,
    hashes: Annotated[
        str | None,
        typer.Option("--hashes", "-H", help="NT hash of the domain user (LM:NT, :NT or NT)", rich_help_panel=AUTH),
    ] = None,
    dc_ip: Annotated[
        str | None,
        typer.Option(
            "--dc-ip", "-D", help="Any domain controller, the PDC Emulator is found from there", rich_help_panel=TARGET
        ),
    ] = None,
    dns_ip: Annotated[
        str | None,
        typer.Option("--dns-ip", help="DNS server (default: --dc-ip, or the system resolver)", rich_help_panel=TARGET),
    ] = None,
    use_ldaps: Annotated[
        bool,
        typer.Option(
            "--ldaps",
            "--use-ssl",
            help="Only use LDAPS (default: LDAP with signing and sealing, then LDAPS)",
            rich_help_panel=TARGET,
        ),
    ] = False,
    password_file: Annotated[
        Path | None,
        typer.Option(
            "--password-file",
            "-P",
            help="Passwords to spray, one per line. The file is watched: passwords added later are sprayed too",
            rich_help_panel=SPRAY,
        ),
    ] = None,
    user_file: Annotated[
        Path | None,
        typer.Option(
            "--user-file",
            "-U",
            exists=True,
            dir_okay=False,
            help="Only spray these users, one per line",
            rich_help_panel=SPRAY,
        ),
    ] = None,
    user_as_pass: Annotated[
        bool, typer.Option("--user-as-pass", "-a", help="Also try each username as password", rich_help_panel=SPRAY)
    ] = False,
    security_threshold: Annotated[
        int,
        typer.Option(
            "--security-threshold",
            "-s",
            min=1,
            help="Attempts always left unused below the lockout threshold",
            rich_help_panel=SPRAY,
        ),
    ] = 2,
    database_path: Annotated[
        Path,
        typer.Option(
            "--database",
            "-db",
            dir_okay=False,
            help="SQLite database of tested credentials, used to resume",
            show_default="~/.config/conpass/conpass.db",
            rich_help_panel=SPRAY,
        ),
    ] = DEFAULT_DATABASE_PATH,
    disable_spray: Annotated[
        bool, typer.Option("--disable-spray", help="Only display the policies and users", rich_help_panel=SPRAY)
    ] = False,
    threads: Annotated[
        int, typer.Option("--max-threads", "-m", min=1, help="Number of parallel workers", rich_help_panel=SPRAY)
    ] = 10,
    timeout: Annotated[
        int, typer.Option("--timeout", min=1, help="Network timeout in seconds", rich_help_panel=SPRAY)
    ] = 5,
    lockout_threshold: Annotated[
        int | None,
        typer.Option("--lockout-threshold", "-t", min=0, help="Lockout threshold to assume", rich_help_panel=OFFLINE),
    ] = None,
    lockout_window: Annotated[
        int | None,
        typer.Option(
            "--lockout-observation-window",
            "-o",
            min=1,
            help="Observation window to assume, in seconds",
            rich_help_panel=OFFLINE,
        ),
    ] = None,
    show: Annotated[bool, typer.Option("--show", help="Display the credentials found for the domain and exit")] = False,
    debug: Annotated[bool, typer.Option("--debug", help="Display debug messages")] = False,
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Display the version and exit")
    ] = False,
) -> None:
    """
    Spray passwords on all Active Directory users without locking them out.

    The policy of each user (domain policy or PSO) and its bad password count, read on the PDC Emulator, decide when the next password can be tried.

    Without credentials (offline mode), give the users (-U) and the policy to assume (-t, -o).
    """
    options = locals().copy()
    set_debug(debug)
    try:
        if "." not in domain:
            msg = "The domain must be a FQDN (domain.local, not DOMAIN)"
            raise ConfigurationError(msg)
        if show:
            _show(database_path, domain)
            return
        config = _build_config(options)
        Orchestrator(config).run()
    except ConpassError as e:
        error(str(e))
        raise typer.Exit(1) from None
    except KeyboardInterrupt:
        warning("Interrupted")
        raise typer.Exit(130) from None


def _show(database_path: Path, domain: str) -> None:
    if not database_path.exists():
        msg = f"Database {database_path} does not exist"
        raise ConfigurationError(msg)
    database = Database(database_path, domain)
    try:
        print_found_credentials(database, domain)
    finally:
        database.close()


def _build_config(options: dict) -> SprayConfig:
    """Validate the command line options and build the session settings."""
    credentials = _credentials(options)
    manual_policy = _manual_policy(options, online=credentials is not None)
    password_file = options["password_file"]
    if password_file:
        _prepare_password_file(password_file)
    return SprayConfig(
        domain=options["domain"],
        credentials=credentials,
        dc_ip=options["dc_ip"],
        dns_ip=options["dns_ip"],
        use_ldaps=options["use_ldaps"],
        password_file=password_file,
        user_file=options["user_file"],
        database_path=_prepare_database(options["database_path"]),
        user_as_pass=options["user_as_pass"],
        security_threshold=options["security_threshold"],
        spray=not options["disable_spray"] and bool(password_file or options["user_as_pass"]),
        manual_policy=manual_policy,
        threads=options["threads"],
        timeout=options["timeout"],
    )


def _credentials(options: dict) -> Credentials | None:
    username, password, hashes = options["username"], options["password"], options["hashes"]
    if username is None:
        if password or hashes:
            msg = "--password and --hashes need --username"
            raise ConfigurationError(msg)
        return None
    if (password is None) == (hashes is None):
        msg = "Give either --password or --hashes"
        raise ConfigurationError(msg)
    try:
        return Credentials.parse(username, options["domain"], password, hashes)
    except ValueError as e:
        raise ConfigurationError(str(e)) from None


def _manual_policy(options: dict, online: bool) -> PasswordPolicy | None:
    threshold, window = options["lockout_threshold"], options["lockout_window"]
    if online:
        if threshold is not None or window is not None:
            msg = "--lockout-threshold and --lockout-observation-window are only used without --username"
            raise ConfigurationError(msg)
        return None
    if options["user_file"] is None or threshold is None or window is None:
        msg = "Without --username, --user-file, --lockout-threshold and --lockout-observation-window are required"
        raise ConfigurationError(msg)
    if 0 < threshold <= options["security_threshold"]:
        msg = f"The lockout threshold ({threshold}) leaves no attempt above the security threshold"
        raise ConfigurationError(msg)
    return PasswordPolicy("Manual policy", threshold, window)


def _prepare_password_file(path: Path) -> None:
    """Create the password file if needed (it is watched), and confirm very long ones."""
    if not path.exists():
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        except OSError as e:
            msg = f"Cannot create {path}: {e}"
            raise ConfigurationError(msg) from None
        success(f"Created {path}: add passwords to it while conpass is running")
        return
    count = len(read_lines(path))
    if count > LARGE_PASSWORD_FILE and not typer.confirm(
        f"{path} has {count} passwords, spraying them all may take a very long time. Continue?"
    ):
        raise typer.Exit(1)


def _prepare_database(path: Path) -> Path | None:
    """Ask before creating the database. Returns None when the user declines it."""
    if path.exists():
        return path
    warning(f"Database {path} does not exist. It records tested credentials, to resume a session.")
    if not typer.confirm("Create it?", default=True):
        warning("Tested credentials will not be recorded")
        return None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        msg = f"Cannot create {path.parent}: {e}"
        raise ConfigurationError(msg) from None
    return path
