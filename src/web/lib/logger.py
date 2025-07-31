import logging
from logging.handlers import SysLogHandler
from pathlib import Path

from lib import config


def _get_file_handler(path: Path) -> logging.FileHandler:
    """
    Returns a universal file handler for logging with a correct log format.
    """
    formatter = logging.Formatter("%(asctime)s: [%(levelname)s] %(message)s")
    file_handler = logging.FileHandler(path)
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
    return file_handler


class SyslogSingleLineFormatter(logging.Formatter):
    """
    Simple syslog formatter that replaces newlines with ' | '.
    This is needed because newline in logs are problematic.
    """

    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        return original.replace("\n", " | ")


def _get_syslog_handler(text: str) -> SysLogHandler:
    """
    Returns a handler for syslog.
    """
    formatter = SyslogSingleLineFormatter("[%(levelname)s] %(message)s")
    syslog_handler = SysLogHandler(address="/dev/log")
    syslog_handler.setFormatter(formatter)
    # This is so that syslog has "VA2AM-incoming" instead of "python3"
    # as the identity of the service.
    syslog_handler.ident = f"VA2AM-{text}: "
    syslog_handler.setLevel(logging.INFO)
    return syslog_handler


def get_logger(text: str, debug: bool = False, silent: bool = False) -> logging.Logger:
    """
    Returns an instance of a logger object.
    """
    logger = logging.getLogger(text)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(_get_file_handler(config.log_dir() / f"{text}.log"))
    logger.addHandler(_get_syslog_handler(text))

    # If it is run manually (from makefile), log both to stdout and to logs.
    if not silent:
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(logging.DEBUG if debug else logging.INFO)
        logger.addHandler(stream_handler)

    return logger
