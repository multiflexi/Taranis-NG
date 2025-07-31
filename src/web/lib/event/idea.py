import json
from datetime import UTC, datetime
from ipaddress import IPv4Address, ip_address
from pathlib import Path
from typing import Any, NotRequired, Optional, TypedDict
from uuid import uuid4

from lib import IP_ADDRESS, config
from lib.report.report_item import EventsGeneration
from lib.report.vulnerability_report import VulnerabilityReport

IPv4 = 4
IPv6 = 6


class IDEANodeType(TypedDict):
    """
    Type for a dictionary representing Node in the IDEA format.
    (https://idea.cesnet.cz)
    """

    Name: str
    Note: str
    Type: list[str]


class IDEASourceType(TypedDict, total=False):
    """
    Type for a dictionary representing Source in the IDEA format.
    (https://idea.cesnet.cz)
    """

    Hostname: list[str]
    IP4: list[str]
    IP6: list[str]
    Port: list[int]
    Proto: list[str]
    Ref: list[str]
    ServiceName: str
    ServiceVersion: str
    Note: str


class IDEAType(TypedDict):
    """
    Type for a dictionary following the IDEA format.
    (https://idea.cesnet.cz)
    """

    Category: list[str]
    Description: str
    DetectTime: str
    Format: str
    ID: str
    Node: list[IDEANodeType]
    Ref: NotRequired[list[str]]
    Source: list[IDEASourceType]
    TLP: str


class IDEAEvent:
    """
    This class represents 1 IDEA message. It can be saved, printed, returned
    as JSON or as a Python dictionary.
    """

    def __init__(self, results: Any, report: VulnerabilityReport, is_new: bool = False) -> None:
        self.message: IDEAType = {
            "Format": "IDEA0",
            "ID": str(uuid4()),
            "TLP": "AMBER",
            "Category": ["Vulnerable.Open"],
            "Description": "Vulnerable version of a software was found",
            "DetectTime": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "Source": [],
            "Node": [
                {
                    "Name": "cz.cesnet.va2am",
                    "Note": "Vulnerability Assessment to Asset Management Integration",
                    "Type": ["Recon"],
                }
            ],
        }
        self._fill_IDEA(results, report)
        self.is_new = is_new

    @staticmethod
    def _get_ip_type(ip: str) -> Optional[int]:
        """
        Returns:
        IPv4 if the string is a valid IPv4 address
        IPv6 if the string is a valid IPv6 address
        None  if it is neither
        """
        try:
            if isinstance(ip_address(ip), IPv4Address):
                return IPv4
            return IPv6
        except ValueError:
            return None

    def _fill_IDEA(self, results: list[dict[str, Any]], report: VulnerabilityReport) -> None:
        """
        Creates an IDEA message for this event and returns it.
        """
        # From Taranis report
        if not config.is_production() or report.should_generate_events() == EventsGeneration.TEST:
            self.message["Category"].append("Test")

        items = set()
        for result in results:
            items.update(result["items"])
        if len(items) == len(report.get_report_items()):
            self.message["Ref"] = [f"cvr:{report.get_id()}"]
        else:
            self.message["Ref"] = [f"cvr:{report.get_id()}-{','.join(map(str, items))}"]

        if report.get_max_cvss_number(items):
            self.message["Description"] += f" (CVSS {report.get_max_cvss_number(items)})"

        # From Sner
        for result in results:
            source: IDEASourceType = {}
            for idea_identifier, sner_identifier in [
                ("Hostname", "host_hostname"),
                ("Port", "service_port"),
                ("Proto", "service_proto"),
            ]:
                if result.get(sner_identifier) not in [None, "null"]:
                    source[idea_identifier] = [result.get(sner_identifier)]  # type: ignore
            if product := result.get("product"):
                source["ServiceName"] = product
            if version := result.get("version"):
                source["ServiceVersion"] = version
            else:
                source["Note"] = (
                    "Network scanner was not able to detect a specific version. Please "
                    "make sure you are running a version that is not vulnerable."
                )
            source["Ref"] = report.get_CVEs(result.get("items"))

            # IPs need to be split between the lists of IPv4 and IPv6 addresses.
            ips_v4 = list(
                filter(
                    lambda ip: self._get_ip_type(ip) == IPv4,
                    result.get("host_addresses", []),
                )
            )
            ips_v6 = list(
                filter(
                    lambda ip: self._get_ip_type(ip) == IPv6,
                    result.get("host_addresses", []),
                )
            )
            if ips_v4:
                source["IP4"] = ips_v4
            if ips_v6:
                source["IP6"] = ips_v6

            self.message["Source"].append(source)

    def get_all_hosts(self) -> tuple[set[IP_ADDRESS], set[str]]:
        """
        Returns a set of all IPs and a set of all hostnames
        from the IDEA message.
        """
        hostnames = set()
        IPs = set()
        for source in self.message["Source"]:
            IPs.update(source.get("IP4", []) + source.get("IP6", []))
            hostnames.update(source.get("Hostname", []))
        return (IPs, hostnames)

    def get_dict(self) -> IDEAType:
        """
        Returns the Python (dict) representation of the IDEA message.
        """
        return self.message

    def get_ID(self) -> str:
        """
        Returns ID of the generated IDEA message.
        """
        return self.message["ID"]

    def get_json(self) -> str:
        """
        Returns the IDEA message as a JSON string (in a text form).
        """
        return json.dumps(self.message, indent=4, sort_keys=True)

    def print(self) -> None:
        """
        Prints the IDEA message to the standard output as a JSON.
        """
        print(self.get_json())

    def save(self, directory: str | Path) -> None:
        """
        Saves the IDEA message as a file to the directory provided by
        the directory_path argument. Naming format is 'ID.idea.json'.
        """
        path = Path(directory) / f"{self.message['ID']}.idea.json"
        with Path.open(path, "w", encoding="utf-8") as f:
            json.dump(self.message, f, indent=4, sort_keys=True)
