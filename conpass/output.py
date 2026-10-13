"""Console output shared by all modules."""

from rich.console import Console

console = Console(highlight=False)

_debug_enabled = False


def set_debug(enabled: bool) -> None:
    """Enable or disable debug messages."""
    global _debug_enabled  # noqa: PLW0603
    _debug_enabled = enabled


def debug(message: str) -> None:
    """Print a debug message when --debug is set."""
    if _debug_enabled:
        console.print(f"[bright_black][DEBUG] {message}[/bright_black]")


def success(message: str) -> None:
    console.print(f"[green]{message}[/green]")


def warning(message: str) -> None:
    console.print(f"[yellow]{message}[/yellow]")


def error(message: str) -> None:
    console.print(f"[red]{message}[/red]")
