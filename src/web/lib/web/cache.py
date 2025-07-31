from typing import Optional

from cachelib import FileSystemCache
from flask import Response

from lib import config
from lib.report import get_report_files
from lib.report.vulnerability_report import VulnerabilityReport

CACHE_KEY_ALL_REPORTS = "ALL_REPORTS"
CACHE_KEY_RSS_RESPONSE = "RSS_RESPONSE"
CACHE_KEY_MTIME = "REPORTS_MTIME"


class WebCache:
    """
    Represents Cache for reports for VA2AM's web.
    """

    def __init__(self) -> None:
        self.cache = FileSystemCache(
            cache_dir="/tmp/va2am_cache",  # noqa: S108
            default_timeout=2 * 60 * 60,  # 2 hours
        )

    @staticmethod
    def _get_current_mtime() -> Optional[float]:
        """
        Returns the current mtime of the reports directory.
        """
        try:
            return config.reports_dir().stat().st_mtime
        except FileNotFoundError:
            return None

    def _is_valid(self, cache_key: str) -> bool:
        """
        Checks if the cache is still valid. This is done based on the
        mtime of the reports file, which should change if new report
        is added.
        """
        if not self.cache.has(CACHE_KEY_MTIME) or not self.cache.has(cache_key):
            return False

        return self._get_current_mtime() == self.cache.get(CACHE_KEY_MTIME)

    def get_all_reports(self) -> list[VulnerabilityReport]:
        """
        Returns report files sorted by their ID from the highest to the lowest.
        These reports are cached.
        """
        if not self._is_valid(CACHE_KEY_ALL_REPORTS):
            reports = sorted(
                get_report_files(config.reports_dir()),
                key=lambda report: int(report[0].replace(".json", "")),
                reverse=True,
            )
            result = [VulnerabilityReport(path) for _, path in reports]
            self.cache.set(CACHE_KEY_ALL_REPORTS, result)
            self.cache.set(CACHE_KEY_MTIME, self._get_current_mtime())

        return self.cache.get(CACHE_KEY_ALL_REPORTS)

    def get_rss_response(self) -> Optional[Response]:
        """
        Returns cached RSS response, or None if the cache is invalid.
        """
        if not self._is_valid(CACHE_KEY_RSS_RESPONSE):
            return None
        return self.cache.get(CACHE_KEY_RSS_RESPONSE)

    def cache_rss_response(self, response: Response) -> None:
        """
        Saves the RSS response to cache.
        """
        self.cache.set(CACHE_KEY_RSS_RESPONSE, response)
        self.cache.set(CACHE_KEY_MTIME, self._get_current_mtime())
