import logging
from copy import deepcopy
from pathlib import Path
from typing import Any, Optional, cast

from lib import (
    IP_ADDRESS,
    config,
    handle_exception,
    send_mail,
    warden,
)
from lib.event.history import EventHistory
from lib.event.idea import IDEAEvent, IDEAType
from lib.event.sner import SnerSearcher
from lib.report.report_item import EventsGeneration
from lib.report.vulnerability_report import VulnerabilityReport


class Events:
    """
    This class is used to call Sner's VersionInfo API, aggregate
    the results and then create IDEA messages for the events.
    It also provides the ability to send these events to Warden,
    print them, save them or return them as a Python dict.
    """

    def __init__(self, report: VulnerabilityReport, logger: Optional[logging.Logger] = None) -> None:
        self.report = report
        self.logger = logger
        self.sner_searcher = SnerSearcher(logger)
        self.results = self._generate_results()
        self.events = self._generate_events()

    @staticmethod
    def _process_results(processed: dict[str, Any], results: list[dict[str, Any]], report_item: int) -> None:
        """
        1. Aggregate results by hostname - if the hostname is available
        under IPv4 and IPv6, only one event will be generated, and it
        will include both IPv4 and IPv6 addresses as sources. If it is
        not available, results will be aggregated based on the IP.
        Key "host_address" will become "host_addresses" and can include
        both the IPv4 and the IPv6 of this hostname.
        2. The results for a hostname are then put into a dictionary,
        where the key is the service proto and port, e.g. "45/tcp".
        This is useful if multiple services run under this hostname/IP
        on a different port. It also eliminates duplicates, because
        only 1 result per protocol port will be kept.
        3. The results are enriched with the information about which
        report items are related to this source - "items" key.

        Resulting list can look like this:
        [
            {
                "443/tcp": {
                    "extra": {},
                    "host_addresses": ["79.128.216.110", "2001:71:f09:233::16"],
                    "host_hostname": "armorg.cesnet.cz",
                    "os": "debian",
                    "product": "openbsd openssh",
                    "service_port": 443,
                    "service_proto": "tcp",
                    "version": "6.7p1",
                    "via_target": "78.128.216.110",
                    "items": {1, 2}
                },
                "80/tcp": {
                    ...
                }
            },
            {
                "54/udp": {
                    "host_hostname": "hostname3.cesnet.cz",
                    ...
                }
            }
        }
        """
        for result in results:
            ip = result.get("host_address")
            # Use IP if the hostname is unknown.
            hostname = cast(str, result.get("host_hostname", ip))
            processed.setdefault(hostname, {})
            protoport = f"{result.get('service_port')}/{result.get('service_proto')}"
            if protoport not in processed[hostname]:
                # Transform to the format described above.
                processed[hostname][protoport] = deepcopy(result)
                processed[hostname][protoport].pop("host_address")
                processed[hostname][protoport]["host_addresses"] = {ip}
                processed[hostname][protoport]["items"] = {report_item}
            else:
                processed[hostname][protoport]["items"].add(report_item)
                processed[hostname][protoport]["host_addresses"].add(ip)

    def _generate_results(self) -> list[dict[str, Any]]:
        """
        Compiles results from all affected systems from all report items
        into single deduplicated list of results. The saved result format
        is described in the _process_results method above.
        """
        processed: dict[str, Any] = {}
        for i, item in enumerate(self.report.get_report_items()):
            # Skip searching if this item should not be searched in Sner.
            if not item.should_search():
                continue

            partial_results = []
            for j in range(1, len(item.get_affected_systems()) + 1):
                # Search in Sner only if the product and version specification is complete.
                if specification := item.get_product_and_OS_specification(j):
                    product, os_spec = specification
                    if product and (version_spec := item.get_versions(j)):
                        partial_results.extend(self.sner_searcher.version_search(product, version_spec, os_spec))
            self._process_results(processed, partial_results, i + 1)
        return list(processed.values())

    @staticmethod
    def _is_new(report_history: set[str], results: dict[str, Any]) -> bool:
        """
        Helper method which returns if the vulnerability is new (True)
        or if it was detected before (False).
        """
        for result in results.values():
            if any(ip in report_history for ip in result["host_addresses"]):
                return False
        return True

    def _generate_events(self) -> list["IDEAEvent"]:
        """
        Generates IDEA events from the results.
        If a very similar event was already generated before, it is skipped.
        (Very similar = the same report ID and the same IP address)
        This is done using a pickled file called "history".
        This file is important and should be backed up regularly.
        """
        events = []
        with EventHistory() as history:
            report_history = history.get_report_history(self.report.get_id(), initialize=True)
            for results in self.results:
                is_new = self._is_new(report_history, results)
                events.append(IDEAEvent(results.values(), self.report, is_new))
                for result in results.values():
                    for ip in result["host_addresses"]:
                        report_history.add(ip)
        return events

    def get_all(self) -> list[IDEAType]:
        """
        Returns a list of all the events represented as dictionaries.
        """
        return [event.get_dict() for event in self.events]

    def get_all_IDs(self) -> list[tuple[str, tuple[set[IP_ADDRESS], set[str]], bool]]:
        """
        Returns a list of all IDEA event IDs.
        Also include a list of all ips and hostnames from the event.
        """
        return [(event.get_ID(), event.get_all_hosts(), event.is_new) for event in self.events]

    def get_all_IDs_as_mentat_links(self) -> str:
        """
        Returns ID of all IDEA events formatted as a list of IPs and links to
        Mentat, which are separated with newline.
        """
        events = []
        for ID, (ips, hostnames), is_new in self.get_all_IDs():
            result_string = "+ " if is_new else ""
            result_string += f"{', '.join(set(ips))}"
            if hostnames:
                result_string += f" ({', '.join(set(hostnames))})"
            result_string += f"\nhttps://mentat-hub.cesnet.cz/mentat/events/{ID}/show"
            events.append(result_string)
        return str.join("\n", events)

    def print(self) -> None:
        """
        Prints all the events.
        """
        for event in self.events:
            event.print()

    def save(self, directory: str | Path) -> None:
        """
        Saves all the events to a provided directory.
        """
        for event in self.events:
            event.save(directory)

    def send_to_warden(self, is_rescan: bool = False) -> bool:
        """
        Send all events generated from this report to Warden. All generated events
        are also saved to archive/idea directory. For now, results from Warden are
        sent to admins, so they can check them.

        If something fails, admins will be notified through mail.
        Returns if the process was successful.
        """
        if len(self.get_all()) > 0 and config.should_send_to_warden():
            archive_dir = config.archive_dir()
            try:
                self.save(archive_dir / "idea")
                client = warden.Client(**warden.read_cfg(config.warden_conf_path()))  # type: ignore
                result = client.sendEvents(self.get_all())  # type: ignore
                log_message = (
                    f"Result from sending events to Warden "
                    f"(report {self.report.get_title()} with ID "
                    f"{self.report.get_id()}): {result}"
                )
                if "errors" in result and self.logger:
                    self.logger.error(log_message)
                elif self.logger:
                    ids = ", ".join(ID for ID, ips, _ in self.get_all_IDs())
                    self.logger.info("%s. Event IDs: %s", log_message, ids)
                subject = f"[VA2AM] {'Rescan: ' if is_rescan else ''}Event generation results"
                if self.report.should_generate_events() == EventsGeneration.TEST:
                    subject += " (Test)"
                send_mail(
                    f"{log_message}\n\nGenerated events:\n{self.get_all_IDs_as_mentat_links()}",
                    subject,
                    recipients=config.info_mail(),
                    logger=self.logger,
                )
            except Exception:  # pylint: disable=locally-disabled, broad-exception-caught
                message = f"An error has occurred while generating events for Warden " f"from the report with ID {self.report.get_id()}."
                subject = f"[VA2AM] {'Rescan: ' if is_rescan else ''}Event generation failed"
                handle_exception(message, subject, self.logger, info=False)
                return False
        return True
