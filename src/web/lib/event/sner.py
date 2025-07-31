import logging
from typing import Any, Optional

from requests import post

from lib import config, send_mail


class SnerSearcher:
    """
    Class that can be used to search Sner (https://sner.flab.cesnet.cz).
    """

    VERSION_INFO_URL = "https://sner-hub.flab.cesnet.cz/api/v2/public/storage/versioninfo"
    HOST_URL = "https://sner-hub.flab.cesnet.cz/api/v2/public/storage/host"
    SPECIAL_OS = config.special_os()

    def __init__(self, logger: Optional[logging.Logger] = None) -> None:
        self.logger = logger
        self._os_cache: dict[str, Optional[str]] = {}

    def _post(self, url: str, post_obj: dict[str, str], no_result: Any) -> Any:
        """
        Helper method for calling an API and handling its response.
        Returns JSON from the response, or None if there was an error.

        Note: Sner's API key must be set in the config file.
        """
        headers = {
            "Accept": "application/json",
            "X-API-KEY": config.SNER_apikey(),
        }
        response = post(url, headers=headers, json=post_obj, timeout=600)
        if not response.ok:
            # 404 is returned also when nothing is found, which is a valid
            # result and does not need to be reported as an error.
            if response.status_code != 404:
                error_message = (
                    f"Error with status code {response.status_code} while trying to get data from SNER.\n"
                    f"Error: {response.text.strip()}.\n"
                    f"URL: {url}\n"
                    f"Request (post JSON): {post_obj}"
                )
                if self.logger:
                    self.logger.error(error_message)
                send_mail(
                    error_message,
                    "[VA2AM] Sner scan failed",
                    recipients=config.admin_mail(),
                    logger=self.logger,
                )
            return no_result
        return response.json()

    def host_search(self, ip: str) -> Any:
        """
        Calls Sner's host API for given ip address.
        """
        return self._post(self.HOST_URL, {"address": ip}, {})

    def guess_host_OS(self, ip: str) -> Optional[str]:
        """
        Tries to guess which Linux distribution is the host using.
        This is mostly derived from Apache/OpenSSH banner.
        """
        if ip in self._os_cache:
            return self._os_cache[ip]

        host_result = self.host_search(ip)
        if "services" in host_result:
            for service in host_result["services"]:
                if "info" not in service:
                    continue
                for os in self.SPECIAL_OS:
                    if os in service["info"].lower():
                        self._os_cache[ip] = os
                        return os
        self._os_cache[ip] = None
        return None

    def _get_OS_from_result(self, result: Any) -> Optional[str]:
        """
        Returns OS from the results, or by "guessing" it based
        on the services running on that host.
        """
        if result.get("extra", {}).get("os"):
            return result.get("extra", {}).get("os")
        # Check if OS is not in the version string (e.g. 9.2p1 Debian 2+deb12u3).
        for os in self.SPECIAL_OS:
            if os in result.get("version", "").lower():
                return os
        return self.guess_host_OS(result["host_address"])

    def _satisfies_os_spec(self, detected_os: Optional[str], os_spec: str) -> bool:
        """
        Returns if the detected operating system satisfies the
        specification of the operating system.

        Examples of OS specification:
        - "debian"
        - "debian,ubuntu" (debian or ubuntu)
        - "" (all OS except those in SPECIAL_OS list)
        - "*" (ignore OS when searching)
        """
        if os_spec in ["", "vanilla"]:
            return detected_os is None or detected_os not in self.SPECIAL_OS
        return detected_os is not None and detected_os in os_spec

    def version_search(self, product: str, version_spec: str, os_spec: str = "") -> Any:
        """
        Calls Sner's versioninfo API for given product, OS and version specification.
        The results are then filtered to get only relevant results.
        """
        post_obj = {
            "product": product,
            "versionspec": version_spec,
            "filter": "",
        }

        results = []
        for result in self._post(self.VERSION_INFO_URL, post_obj, []):
            if os_spec != "*":
                # Enrich results with operating system information.
                result["os"] = self._get_OS_from_result(result)
                if not self._satisfies_os_spec(result["os"], os_spec):
                    continue

            results.append(result)
        return results
