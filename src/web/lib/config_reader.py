# pylint: disable=missing-function-docstring
import json
from configparser import ConfigParser
from pathlib import Path
from typing import Any, Optional


class ConfigReader:
    """
    Class for reading and parsing config.ini and other config
    files such as language.json and warden_client.cfg.
    """

    CONF_DIR = Path("conf")
    WARDEN_CONF = CONF_DIR / "warden_client.cfg"
    TRANSLATIONS_CONF = CONF_DIR / "language.json"

    def __init__(self) -> None:
        self._config = ConfigParser()
        self._config.read(self.CONF_DIR / "config.ini", encoding="utf-8")
        self._translations: Optional[Any] = None

    def is_production(self) -> bool:
        production = self._config["VA2AM"]["production"].upper()
        return production == "TRUE"

    def should_send_to_warden(self) -> bool:
        production = self._config["VA2AM"]["send_to_warden"].upper()
        return production == "TRUE"

    def info_mail(self) -> list[str]:
        addresses = self._config["VA2AM"]["mail_addresses_info"].split(",")
        return list(map(str.strip, addresses))

    def admin_mail(self) -> list[str]:
        addresses = self._config["VA2AM"]["mail_addresses_admins"].split(",")
        return list(map(str.strip, addresses))

    def SNER_apikey(self) -> Optional[str]:
        return self._config.get("VA2AM", "sner_apikey")

    def special_os(self) -> set[str]:
        ignored_os = self._config["VA2AM"]["special_OS"].split(",")
        return set(map(str.lower, map(str.strip, ignored_os)))

    def reports_dir(self) -> Path:
        reports_dir = self._config.get("PATHS", "reports_dir")
        if not reports_dir:
            reports_dir = "reports"
        return Path(reports_dir)

    def incoming_dir(self) -> Path:
        incoming_dir = self._config.get("PATHS", "incoming_dir")
        if not incoming_dir:
            incoming_dir = "incoming"
        return Path(incoming_dir)

    def archive_dir(self) -> Path:
        archive_dir = self._config.get("PATHS", "archive_dir")
        if not archive_dir:
            archive_dir = "archive"
        return Path(archive_dir)

    def log_dir(self) -> Path:
        log_dir = self._config.get("PATHS", "log_dir")
        if log_dir:
            return Path(log_dir)
        return self.archive_dir() / "logs"

    def max_reports_homepage(self) -> int:
        return int(self._config.get("WEB", "max_reports_homepage").strip())

    def max_reports_rss(self) -> int:
        return int(self._config.get("WEB", "max_reports_rss").strip())

    def slovak_authors(self) -> list[str]:
        slovak_authors = self._config.get("WEB", "slovak_authors")
        return list(map(str.strip, slovak_authors.split(",")))

    def website_hostname(self) -> str:
        return self._config.get("WEB", "hostname") or "localhost:5000"

    def feedback_questions(self) -> dict[str, str]:
        return {
            "question1": self._config["FEEDBACK"]["question1"],
            "question2": self._config["FEEDBACK"]["question2"],
            "question3": self._config["FEEDBACK"]["question3"],
            "comment": self._config["FEEDBACK"]["comment"],
        }

    def warden_conf_path(self) -> Path:
        return self.WARDEN_CONF

    def get_translations(self, language: str) -> Any:
        """
        Loads translations from language.json file (if not already loaded)
        and returns the translations to the given language.
        """
        if self._translations is None:
            with Path.open(self.TRANSLATIONS_CONF, encoding="utf-8") as file:
                self._translations = json.load(file)
        return self._translations[language]
