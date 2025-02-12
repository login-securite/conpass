import logging

from rich.logging import RichHandler


def get_logger(console):
    logger = logging.getLogger("conpass")
    logger.setLevel(logging.DEBUG)
    handler = RichHandler(show_path=False, console=console, rich_tracebacks=True)
    handler.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    return logger
