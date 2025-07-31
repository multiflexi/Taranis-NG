import logging
import traceback
from argparse import ArgumentParser
from email.mime.text import MIMEText
from pathlib import Path
from subprocess import PIPE, Popen
from typing import Optional

from lib.config_reader import ConfigReader

# Constants that can be anywhere in the lib directory.
IP_ADDRESS = str

TEST_DIR = Path("lib/test")

config = ConfigReader()


def get_script_argument_parser() -> ArgumentParser:
    """
    Returns an argument parser with silent and debug options, which
    can be used in script such as rescan or process-incoming.
    """
    parser = ArgumentParser()
    parser.add_argument(
        "--silent",
        action="store_true",
        help="do not print anything but errors to the standard output",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="also log the debug outputs",
    )
    return parser


def send_mail(
    body: str,
    subject: str,
    recipients: list[str],
    logger: Optional[logging.Logger] = None,
    sender: str = "va2am@cesnet.cz",
    force_send: bool = False,
) -> None:
    """
    Sends an email with the given parameters using sendmail,
    but only if the VA2AM is in production mode or force_send
    is True (send even in dev mode).
    Logs error output if it was unsuccessful.
    """
    if config.is_production() or force_send:
        msg = MIMEText(body)
        msg["From"] = sender
        msg["To"] = ", ".join(recipients)
        msg["Subject"] = subject
        try:
            p = Popen(["/usr/sbin/sendmail", *recipients], stdin=PIPE)  # pylint: disable=locally-disabled, consider-using-with
            p.communicate(msg.as_bytes())
        except Exception:  # pylint: disable=locally-disabled, broad-exception-caught
            error_message = f"Sending mail with subject '{subject}' to '{msg['To']}' failed."
            if logger:
                logger.exception(error_message)
            else:
                print(error_message)
                print(msg)
    else:
        info_message = (
            f"Development mode is enabled, this e-mail was not sent:\n"
            f"Recipients: {', '.join(recipients)}\n"
            f"Sender: {sender}\n"
            f"Subject: {subject}\n"
            f"Body: {body}"
        )
        print(info_message)
        if logger:
            logger.info(info_message)


def handle_exception(
    message: str,
    subject: str,
    logger: Optional[logging.Logger] = None,
    info: bool = True,
    force_send: bool = True,
) -> None:
    """
    Log the exception and send it via e-mail.
    """
    if logger:
        logger.exception(message)

    recipients = config.info_mail() if info else config.admin_mail()
    mail_message = f"{message}\n\n{traceback.format_exc()}"
    send_mail(mail_message, subject, recipients, logger, force_send=force_send)
