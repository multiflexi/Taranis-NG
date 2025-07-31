# pylint: disable=missing-function-docstring

import logging
import re
from enum import Enum
from typing import Any, Optional
from xml.etree import ElementTree

from lib import handle_exception, version_parser
from lib.report import (
    MissingFieldError,
    capitalize_and_fix_spaces,
    format_date,
    reformat_date,
)

CWE_XML_FILE = ElementTree.parse("CWEs.xml")  # noqa: S314


class EventsGeneration(Enum):
    """
    Enum for values representing if IDEA events should be
    generated from the report or not.
    """

    DISABLED = 1
    TEST = 2
    GENERATE = 3


class VulnerabilityReportPart:
    """
    This class represents a generic part of Vulnerability Report from Taranis.
    """

    def __init__(self, item: dict[str, Any]) -> None:
        self.item = item
        self.validate()

    def validate(self) -> None:
        assert self.item.get("attrs") is not None, "Attrs field is missing in the report item!"
        # These methods will fail if something is missing.
        self.get_name()
        self.get_description()

    def _get(self, field: str, invalid_value: Any = None, required: bool = False) -> Any:
        """
        Helper method for getting 'field' from the report item.
        'Invalid_value' specifies what to return if the field is missing.
        If required is True, Error is thrown if the field is missing.
        """
        if self.item.get(field) is None and required:
            raise MissingFieldError(field, self)
        return self.item.get(field, invalid_value)

    def _get_from_attrs(self, field: str, invalid_value: Any = None, required: bool = False) -> Any:
        """
        Helper method for getting 'field' from attributes of the report.
        'Invalid_value' specifies what to return if the field is missing.
        If required is True, Error is thrown if the field is missing.
        """
        attrs = self.item.get("attrs", None)
        if attrs is None:
            raise MissingFieldError("attrs", self)
        if attrs.get(field) is None and required:
            raise MissingFieldError(field, self)
        return attrs.get(field, invalid_value)

    def get_name(self) -> str:
        return capitalize_and_fix_spaces(
            self._get("name", required=True),
        )

    def get_created(self) -> Optional[str]:
        created = self.item.get("created")
        if created is None:
            return None
        return format_date(created)

    def get_last_updated(self) -> Optional[str]:
        last_updated = self.item.get("last_updated")
        if last_updated is None:
            return None
        return format_date(last_updated)

    def get_description(self) -> str:
        return capitalize_and_fix_spaces(
            self._get_from_attrs("description", required=True),
        )

    def get_recommendations(self) -> Optional[str]:
        if (recommendations := self._get_from_attrs("recommendations")) is None:
            return None
        return capitalize_and_fix_spaces(recommendations)

    def get_links(self) -> list[str]:
        return self._get_from_attrs("links", [])


class VulnerabilityReportIntro(VulnerabilityReportPart):
    """
    This class represents Vulnerability Report - Intro from Taranis.
    """

    def should_generate_events(self) -> EventsGeneration:
        value = self._get_from_attrs("generate_events")
        if value == "generate":
            return EventsGeneration.GENERATE
        if value == "do not generate":
            return EventsGeneration.DISABLED
        return EventsGeneration.TEST


class ReportItem(VulnerabilityReportPart):
    """
    This class represents Report Item from Taranis.
    """

    def __init__(self, item: dict[str, Any]) -> None:
        super().__init__(item)
        self.search_in_sner = self.validate_versions()

    def _should_parse_versions(self) -> bool:
        """
        Returns if the version specification should be parsed.
        If the version is not parsed, VA2AM will not try to
        find the vulnerability in Sner.
        """
        # If the value is missing, assume that it should be parsed.
        return self._get_from_attrs("affected_versions_parsability", "Parse").lower() == "parse"

    def validate(self) -> None:
        """
        Basic report item validation from the input JSON.
        Mostly just if the field is there, not if the content is correct.
        """
        super().validate()
        self.get_affected_systems()
        if self.get_CVEs():
            for cve in self.get_CVEs():
                if cve:
                    assert re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve), f"CVE '{cve}' has wrong format."
        if self.get_CWEs():
            for cwe in self.get_CWEs():
                if cwe:
                    assert re.fullmatch(r"\d+", cwe), f"CWE '{cwe}' has wrong format."

    def validate_versions(
        self,
        send_mail: bool = False,
        logger: Optional[logging.Logger] = None,
    ) -> bool:
        """
        Tries to parse the version specification. If it fails, an
        info mail is sent (if send_mail is True).
        Returns True if all versions are valid, and False if one
        or more versions are invalid.
        """
        if not self._should_parse_versions():
            return False

        try:
            for i in range(1, len(self.get_affected_systems()) + 1):
                versions = self.get_versions(i)
                if versions:
                    version_parser.parse(versions)  # check if it can be parsed
            return True
        except version_parser.InvalidFormatException:
            message = (
                f"VA2AM was unable to parse the version specifier from "
                f"the report item {self.get_name()}. Make sure the version "
                f"specification is correct. Until this problem is resolved, "
                f"VA2AM will not search in Sner for the vulnerable services "
                f"described in this report."
            )
            subject = "[VA2AM] Unable to parse version specification"
            if send_mail:
                handle_exception(message, subject, logger, force_send=False)
            return False

    def should_search(self) -> bool:
        """
        Returns if this vulnerability should be searched in Sner.
        """
        return self.search_in_sner

    def get_CVEs(self) -> list[str]:
        return [cve.strip() for cve in self._get_from_attrs("cve", [])]

    def get_CWEs(self) -> list[str]:
        return [cwe.strip() for cwe in self._get_from_attrs("cwe", [])]

    def get_cwe_name_and_description(self, index: int) -> Optional[tuple[str, str]]:
        """
        Get the name and the description of the CWE on index, which starts
        at number 1.
        """
        CWEs = self.get_CWEs()
        if len(CWEs) < index:
            return None
        cwe_element = CWE_XML_FILE.find(f".//*[@ID='{CWEs[index - 1]}']")
        if cwe_element is None:
            return None
        name = cwe_element.get("Name")
        if name is None:
            return None
        # If description is not found, return an empty string instead.
        description_element = cwe_element.find("{http://cwe.mitre.org/cwe-7}Description")
        if description_element is None or description_element.text is None:
            return (name, "")
        return (name, description_element.text)

    def get_iocs(self) -> Optional[str]:
        # IOCs are in a form of a list, so they need to be joined into 1 string.
        return ", ".join(self._get_from_attrs("IOC", [])) or None

    def get_cvss(self) -> Optional[str] | Optional[dict[str, Any]]:
        return self._get_from_attrs("cvss")

    def get_cvss_vector(self) -> Optional[str]:
        cvss = self.get_cvss()
        if isinstance(cvss, dict):
            return cvss.get("vectorString")
        return cvss

    def get_cvss_number(self) -> Optional[float]:
        cvss = self.get_cvss()
        if isinstance(cvss, dict) and cvss.get("baseScore"):
            return cvss.get("baseScore")
        if self._get_from_attrs("cvss_number"):
            return float(self._get_from_attrs("cvss_number"))
        return None

    def get_update_date(self) -> Optional[str]:
        date = self._get_from_attrs("update_date")
        if not date or len(date.split(".")) != 3:
            return None
        return reformat_date(date)

    def get_exposure_date(self) -> Optional[str]:
        date = self._get_from_attrs("exposure_date", required=True)
        if not date or len(date.split(".")) != 3:
            return None
        return reformat_date(self._get_from_attrs("exposure_date", required=True))

    def get_affected_systems(self) -> list[str]:
        return self._get_from_attrs("affected_systems", required=True)

    def get_affected_system(self, index: int) -> Optional[str]:
        """
        Get the affected system at index 'index', starting from 1.
        """
        systems = self.get_affected_systems()
        if index > len(systems):  # Out of range.
            return None
        return systems[index - 1]

    def _get_product_part(self, index: int) -> Optional[str]:
        """
        Get the product part of the affected system at index 'index', starting from 1.
        If the index is less than 1, ValueError is raised.
        """
        if index < 1:
            raise ValueError(f"Index must start from one, but was {index}.")
        system = self.get_affected_system(index)
        if not system or not system.strip():
            return None
        if ";" not in system:  # Version was not specified ("product;" format).
            return system
        # Version was specified. ("product; versions" format).
        return system[: system.index(";")]

    def get_product_and_OS_specification(self, index: int) -> Optional[tuple[str, str]]:
        """
        Get a tuple of product and OS specification of the affected system
        at index 'index', starting from 1.
        """
        product = self._get_product_part(index)
        if product is None:
            return None
        if ":" not in product:  # Format without OS specification
            return product.strip(), ""
        product_parts = product.split(":", maxsplit=2)
        return product_parts[1].strip(), product_parts[0].strip().lower()

    def get_product_display(self, index: int) -> Optional[str]:
        """
        Get a string representation of product and OS specification
        of the affected system at index 'index', starting from 1.
        """
        result = self.get_product_and_OS_specification(index)
        if result is None:
            return None
        product, os_spec = result
        # "*" is just internal symbol for SNER.
        if os_spec in ["", "*"]:
            return product
        return f"{product} ({os_spec})"

    def get_versions(self, index: int) -> Optional[str]:
        """
        Get the version of the affected system at index 'index', starting from 1.
        If the index is less than 1, ValueError is raised.
        """
        if index < 1:
            raise ValueError(f"Index must start from one, but was {index}.")
        system = self.get_affected_system(index)
        # If no version was specified.
        if not system or not system.strip() or ";" not in system:
            return None
        system = system.strip()
        if len(system) == system.index(";"):  # No version was specified.
            return None
        # Remove the product from the string
        versions = system[(system.index(";") + 1) :].strip()
        # If there is an extra ";" at the end, remove it.
        if len(versions) > 0 and versions[-1] == ";":
            versions = versions[:-1]
        return versions

    def get_formatted_versions(self, index: int) -> Optional[str]:
        """
        Get the affected version of affected system at index 'index', starting
        from 1, and parse it into human-readable form with OR/AND and brackets.
        """
        versions = self.get_versions(index)
        if not versions:
            return None
        result = ""
        version_parts = versions.split(";")
        if len(version_parts) == 1:
            return version_parts[0].replace(",", " AND ").strip()

        for i, version_specifier in enumerate(version_parts):
            result += "(" + version_specifier.replace(",", " AND ").strip() + ")"
            if i < len(version_parts) - 1:
                result += " OR "
        return result
