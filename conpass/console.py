from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
import re
from rich.console import Console

from conpass.core import ThreadPool
from conpass.utils import blocks
from conpass.utils.logger import get_logger

app = typer.Typer(context_settings={"help_option_names": ["-h", "--help"]})


def complete_path():  # Typer bug : https://github.com/fastapi/typer/issues/951
    return []


@app.command(
    help='Spray given passwords to all Active Directory users and taking password policies into account',
)
def spray(

    domain: Annotated[
        str,
        typer.Option("--domain", "-d", help="Domain name", rich_help_panel="Authentication"),
    ],
    password_file: Annotated[
        Path | None,
        typer.Option(
            "--password-file",
            "-P",
            exists=True,
            file_okay=True,
            readable=True,
            resolve_path=True,
            help="File containing passwords to test",
            autocompletion=complete_path,
            rich_help_panel="Spray",
        ),
    ] = None,
    username: Annotated[
        str | None,
        typer.Option("--username", "-u", help="Domain user", rich_help_panel="Authentication"),
    ] = None,
    password: Annotated[
        str | None,
        typer.Option(
            "--password",
            "-p",
            help="Domain password",
            rich_help_panel="Authentication"
        ),
    ] = None,
    hashes: Annotated[
        str | None,
        typer.Option(
            "--hashes",
            "-H",
            help="NTLM hashes, format is LMHASH:NTHASH",
            rich_help_panel="Authentication",
        ),
    ] = None,
    user_file: Annotated[
        Path | None,
        typer.Option(
            "--user-file",
            "-U",
            exists=True,
            file_okay=True,
            readable=True,
            resolve_path=True,
            help="File containing users to test",
            autocompletion=complete_path,
            rich_help_panel="Spray",
        ),
    ] = None,
    lockout_threshold: Annotated[
        int | None,
        typer.Option(
            "--lockout-threshold",
            "-t",
            help="Manually provide lockout threshold (Necessary when users list if provided)",
            rich_help_panel="Spray",
        ),
    ] = None,
    lockout_observation_window: Annotated[
        int | None,
        typer.Option(
            "--lockout-observation-window",
            "-o",
            help="Manually provide lockout observation window in seconds (Necessary when users list if provided)",
            rich_help_panel="Spray",
        ),
    ] = None,
    user_as_pass: Annotated[
        bool | None,
        typer.Option(
            "--user-as-pass",
            "-a",
            help="Enables user-as-pass for each user",
            rich_help_panel="Spray",
        ),
    ] = False,
    security_threshold: Annotated[
        int | None,
        typer.Option(
            "--security-threshold",
            "-s",
            help="Specifies the number of remaining attempts allowed before reaching the lockout threshold",
            rich_help_panel="Spray",
        ),
    ] = 2,
    max_threads: Annotated[
        int | None,
        typer.Option(
            "--max-threads",
            "-m",
            help="Max threads number",
            rich_help_panel="Spray",
        ),
    ] = 10,
    limit_memory: Annotated[
        bool | None,
        typer.Option(
            "--limit-memory",
            "-l",
            help="Limit the size of internal queues. Could be useful for 10k users and more",
            rich_help_panel="Spray",
        ),
    ] = False,
    disable_spray: Annotated[
        bool | None,
        typer.Option(
            "--disable-spray",
            help="Disable password spraying. Useful to only retrieve PSO details",
            rich_help_panel="Spray",
        ),
    ] = False,
    dc_ip: Annotated[
        str | None,
        typer.Option("--dc-ip", "-D", help="Domain Controller IP address", rich_help_panel="Authentication"),
    ] = None,
    dc_host: Annotated[
        str | None,
        typer.Option(
            "--dc-host",
            help="Hostname of the domain controller. If omitted it uses the --dc-ip or --domain",
            rich_help_panel="Authentication",
        ),
    ] = None,

    use_ssl: Annotated[
        bool,
        typer.Option(
            "--use-ssl",
            help="Uses LDAP over SSL/TLS (port 636)",
            rich_help_panel="Authentication",
        ),
    ] = False,

    use_kerberos: Annotated[
        bool,
        typer.Option(
            "--kerberos",
            "-k",
            help="Uses kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters",
            rich_help_panel="Authentication",
        ),
    ] = False,
    aes_key: Annotated[
        str | None,
        typer.Option(
            "--aes-key",
            "-a",
            help="AES key to use for Kerberos Authentication (128 or 256 bits)",
            rich_help_panel="Authentication",
        ),
    ] = None,


):
    console = Console()
    logger = get_logger(console)
    if username is None and user_file is None:
        logger.error("Either --username or --users-file is required")
        raise typer.Exit(code=1)
    if '.' not in domain:
        logger.error("Provide fully qualified domain name (e.g. domain.local instead of DOMAIN)")
        raise typer.Exit(code=1)

    if username is not None and password is None and hashes is None and (use_kerberos is False or aes_key is None):
        logger.error(f"--password or --hashes{' or --aes-key' if use_kerberos else ''} is required for authentication")
        raise typer.Exit(code=1)

    if len([c for c in (password, hashes, aes_key) if c is not None]) > 1:
        logger.error("Only one secret can be provided")
        raise typer.Exit(code=1)

    if username is None and user_file and (not lockout_threshold or not lockout_observation_window):
        logger.error("When using --users-file, --lockout-threshold and --lockout-observation-window are required")
        raise typer.Exit(code=1)

    if password_file is not None:
        with open(password_file) as f:
            nb_passwords = sum(bl.count("\n") for bl in blocks(f))
            if nb_passwords > 100:
                res = console.input(f"[yellow]The password file has {nb_passwords} passwords. It will take a very long time to try them all[/yellow]\nDo you want to continue? \\[y/N] ")
                if not res.lower().startswith('y'):
                    raise typer.Exit(code=1)
    else:
        disable_spray = True

    try:
        thread_pool = ThreadPool(
            username,
            password,
            domain,
            use_ssl,
            dc_ip,
            dc_host,
            password_file,
            user_file,
            lockout_threshold,
            lockout_observation_window,
            user_as_pass,
            security_threshold,
            max_threads,
            limit_memory,
            disable_spray,
            console
        )
        thread_pool.run()
    except Exception as e:
        logger.critical(e)
        console.print_exception()
        raise typer.Exit(code=1) from None
