# pylint: disable=missing-function-docstring,missing-class-docstring,protected-access
# ruff: noqa: E501

import unittest

from lib import TEST_DIR, config
from lib.report import (
    format_date,
    get_cvss_severity,
    get_report_files,
    reformat_date,
)
from lib.report.report_item import EventsGeneration, ReportItem
from lib.report.vulnerability_report import VulnerabilityReport


class Test(unittest.TestCase):
    def load_report(self) -> VulnerabilityReport:
        report_path = TEST_DIR / "report_test.json"
        return VulnerabilityReport(report_path)

    def load_invalid_report(self, filename: str) -> VulnerabilityReport:
        return VulnerabilityReport(TEST_DIR / "invalid_reports" / filename)

    def test_vulnerability_report(self):
        report = self.load_report()
        self.assertEqual(report.get_id(), "2")
        self.assertEqual(report.get_tlp(), "CLEAR")
        self.assertEqual(report.get_formatted_tlp(with_space=True), "[TLP:CLEAR] ")
        self.assertEqual(report.get_formatted_tlp(), "[TLP:CLEAR]")
        self.assertEqual(
            report.get_title(),
            "Juniper opravuje 5 zraniteľností v zariadeniach série SRX a EX",
        )
        self.assertEqual(
            report.get_description(),
            "Juniper opravuje 5 stredne závažných zraniteľností v zariadeniach série SRX a EX.",
        )
        self.assertEqual(
            report.get_intro_description(),
            "Zneužitím všetkých zraniteľností je možné vykonať vzdialené spúšťanie kódu a zvýšiť tak dopad na kritický. [1]",
        )
        self.assertEqual(report.should_generate_events(), EventsGeneration.DISABLED)
        self.assertEqual(report.get_author(), "Martin Krajči")
        self.assertEqual(report.get_author_username(), "krajci")
        self.assertEqual(report.get_publish_date(), "21. 11. 2023")
        self.assertEqual(
            report.get_links(),
            [
                "https://supportportal.juniper.net/s/article/2023-08-Out-of-Cycle-Security-Bulletin-Junos-OS-SRX-Series-and-EX-Series-Multiple-vulnerabilities-in-J-Web-can-be-combined-to-allow-a-preAuth-Remote-Code-Execution?language=en_US"
            ],
        )
        self.assertEqual(len(report.get_report_items()), 2)
        self.assertEqual(report.get_CWEs(), {"CWE-306"})
        self.assertEqual(len(report.get_CVEs()), 5)
        self.assertEqual(len(report.get_CVEs({1, 2})), 5)
        self.assertEqual(
            set(report.get_CVEs()),
            {
                "cve:CVE-2023-36846",
                "cve:CVE-2023-36847",
                "cve:CVE-2023-36851",
                "cve:CVE-2023-36844",
                "cve:CVE-2023-36845",
            },
        )
        self.assertEqual(len(report.get_CVEs({1})), 2)
        self.assertEqual(len(report.get_CVEs({2})), 3)
        self.assertEqual(report.get_max_cvss_number(), 7.5)
        self.assertEqual(report.get_max_cvss_number({}), None)
        self.assertEqual(report.get_max_cvss_number({1}), 7.5)
        self.assertEqual(report.get_max_cvss_number({2}), 4.0)
        self.assertEqual(report.get_max_cvss_number({1, 2}), 7.5)
        for item in report.get_report_items():
            self.assertIsInstance(item, ReportItem)

        # Test keyword matching.
        self.assertTrue(report.matches_keyword("21. 11. 2023"))
        self.assertTrue(report.matches_keyword("SRX a EX"))
        self.assertTrue(report.matches_keyword("2"))
        self.assertTrue(report.matches_keyword("TLP:CLEAR"))
        self.assertTrue(report.matches_keyword("[tlp:clear]"))
        self.assertTrue(report.matches_keyword("stredne závažných"))
        self.assertTrue(report.matches_keyword("CVE-2023-36845"))
        self.assertTrue(report.matches_keyword("MARTIN"))
        self.assertTrue(report.matches_keyword("vzdialené spúšťanie kódu"))
        self.assertTrue(report.matches_keyword("7.5"))
        self.assertTrue(report.matches_keyword("High"))
        self.assertTrue(report.matches_keyword("high"))
        self.assertTrue(report.matches_keyword("HIGH"))
        self.assertFalse(report.matches_keyword("fdvegver"))
        self.assertFalse(report.matches_keyword("CRITICAL"))
        self.assertFalse(report.matches_keyword("2024"))
        self.assertFalse(report.matches_keyword("Unauthorized"))
        self.assertFalse(report.matches_keyword("Michaela"))

    def test_validation(self):
        for file in [
            "overview_invalid1_missing_product.json",
            "overview_invalid2_missing_id.json",
            "overview_invalid3_missing_tlp.json",
            "overview_invalid5_missing_publish_date.json",
            "overview_invalid6_missing_author.json",
            "overview_invalid7_missing_report_items.json",
            "overview_invalid8_missing_title.json",
            "overview_invalid10_missing_name.json",
            "overview_invalid11_missing_attrs.json",
            "overview_invalid13_missing_desc.json",
            "overview_invalid14_wrong_cve.json",
            "overview_invalid15_wrong_cwe.json",
            "overview_invalid16_missing_affected_systems.json",
            "overview_invalid20_tlp_red.json",
            "overview_invalid21_tlp_amber.json",
            "overview_invalid22_tlp_green.json",
        ]:
            with self.assertRaises((ValueError, AssertionError, TypeError)):
                self.load_invalid_report(file)
                print(f"{file} did not raise an error.")

    def test_date_functions(self):
        self.assertEqual(
            format_date({"day": 2, "month": 10, "year": 2023}),
            "2. 10. 2023",
        )
        self.assertEqual(
            format_date({"month": 12, "year": 1984, "day": 25}),
            "25. 12. 1984",
        )
        for input_dict in [{"month": 12, "day": 25}, {"month": 12}, None]:
            with self.assertRaises(ValueError):
                format_date(input_dict)

        self.assertEqual(reformat_date("2023.10.2"), "2. 10. 2023")
        self.assertEqual(reformat_date("1984.12.25"), "25. 12. 1984")
        for input_str in ["2023.10", "2023.10.2.1", None]:
            with self.assertRaises(ValueError):
                format_date(input_str)

    def test_report_items(self):
        items = self.load_report().get_report_items()
        report_item1, report_item2 = items[0], items[1]

        # First report item
        self.assertFalse(report_item1.search_in_sner)
        self.assertFalse(report_item1.validate_versions(False))
        self.assertFalse(report_item1._should_parse_versions())
        self.assertEqual(report_item1.get_name(), "JunosOS 1 (CVE-2023-36844, CVE-2023-36845)")
        self.assertEqual(
            report_item1.get_description(),
            "Neautentizovanému vzdialenému útočníkovi je v J-Web pomocou špeciálne vytvorenej požiadavky umožnené meniť PHP premenné prostredia. [1]",
        )
        self.assertEqual(
            report_item1.get_recommendations(),
            "Postihnuté produkty a ich opravené verzie:\nEX Series - 20.4R3-S8, 21.2R3-S6, 21.3R3-S5*, 21.4R3-S4, 22.1R3-S3, 22.2R3-S1",
        )
        self.assertEqual(
            report_item1.get_links(),
            [
                "https://supportportal.juniper.net/s/article/2023-08-Out-of-Cycle-Security-Bulletin-Junos-OS-SRX-Series-and-EX-Series-Multiple-vulnerabilities-in-J-Web-can-be-combined-to-allow-a-preAuth-Remote-Code-Execution?language=en_US"
            ],
        )
        self.assertEqual(report_item1.get_CVEs(), ["CVE-2023-36844", "CVE-2023-36845"])
        self.assertEqual(
            report_item1.get_cvss_vector(),
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        )
        self.assertEqual(report_item1._get_product_part(1), "Juniper Junos")
        self.assertEqual(report_item1._get_product_part(2), "debian:Juniper Junos")
        self.assertEqual(report_item1.get_product_and_OS_specification(1), ("Juniper Junos", ""))
        self.assertEqual(
            report_item1.get_product_and_OS_specification(2),
            ("Juniper Junos", "debian"),
        )
        self.assertEqual(report_item1.get_product_display(1), "Juniper Junos")
        self.assertEqual(report_item1.get_product_display(2), "Juniper Junos (debian)")
        self.assertEqual(report_item1.get_CWEs(), [])
        self.assertEqual(report_item1.get_iocs(), None)
        self.assertEqual(report_item1.get_cvss_number(), 7.5)
        self.assertEqual(get_cvss_severity(report_item1.get_cvss_number()), "High")
        self.assertEqual(
            report_item1.get_affected_system(1),
            "Juniper Junos; >=21.1, <23.0; >=23.4, <24.0",
        )
        self.assertEqual(report_item1.get_versions(1), ">=21.1, <23.0; >=23.4, <24.0")
        self.assertEqual(
            report_item1.get_formatted_versions(1),
            "(>=21.1 AND  <23.0) OR (>=23.4 AND  <24.0)",
        )
        self.assertEqual(report_item1.get_created(), "25. 9. 2023")
        self.assertEqual(report_item1.get_last_updated(), "25. 9. 2023")
        self.assertEqual(report_item1.get_exposure_date(), "17. 8. 2023")
        self.assertEqual(report_item1.get_update_date(), "7. 9. 2023")

        # Second report item (only interesting attributes)
        self.assertTrue(report_item2.search_in_sner)
        self.assertTrue(report_item2.validate_versions(False))
        self.assertTrue(report_item2._should_parse_versions())  # No value = parse
        self.assertEqual(report_item2.get_iocs(), "Indicator, Indicator2")
        self.assertEqual(report_item2.get_CWEs(), ["306"])
        self.assertEqual(report_item2.get_cvss_number(), 4.0)
        self.assertEqual(get_cvss_severity(report_item2.get_cvss_number()), "Medium")
        self.assertEqual(
            report_item2.get_cvss_vector(),
            "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
        )
        self.assertEqual(len(report_item2.get_affected_systems()), 4)
        self.assertEqual(
            report_item2.get_affected_system(1),
            "*:Juniper Junos; >=21.1, <23.0; >=23.4, <24.0",
        )
        self.assertEqual(report_item2.get_affected_system(2), "*:Saturn Junos; >=3.1, <4.0")
        self.assertEqual(report_item2.get_affected_system(4), "Neptun Junos; >=0, <1.0")

    def test_report_item_versions(self):
        report_item = self.load_report().get_report_items()[0]
        report_item.item["attrs"]["affected_systems"] = [
            "Juniper Junos ;>=0",
            "  Apache    ;  >=0, <5.0",
            "*:Mentat ; >=1.2, <3.0; ==3.1  ",
            " debian: vim - vi improved ;  >=1.2, <1.2.3; >=2.0, <2.3, !=2.1; =3.0  ",
        ]
        # No need to get rid of the double spaces, HTML will do it.
        self.assertEqual(report_item.get_formatted_versions(1), ">=0")
        self.assertEqual(report_item.get_product_display(1), "Juniper Junos")
        self.assertEqual(report_item.get_formatted_versions(2), ">=0 AND  <5.0")
        self.assertEqual(report_item.get_product_display(2), "Apache")
        self.assertEqual(report_item.get_formatted_versions(3), "(>=1.2 AND  <3.0) OR (==3.1)")
        self.assertEqual(report_item.get_product_display(3), "Mentat")
        self.assertEqual(
            report_item.get_formatted_versions(4),
            "(>=1.2 AND  <1.2.3) OR (>=2.0 AND  <2.3 AND  !=2.1) OR (=3.0)",
        )
        self.assertEqual(report_item.get_product_display(4), "vim - vi improved (debian)")

    def test_cwe(self):
        report_item = self.load_report().get_report_items()[1]
        name, description = report_item.get_cwe_name_and_description(1)
        self.assertEqual(name, "Missing Authentication for Critical Function")
        self.assertEqual(
            description,
            "The product does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources.",
        )

        report_item.item["attrs"]["cwe"][0] = "15"
        name, description = report_item.get_cwe_name_and_description(1)
        self.assertEqual(name, "External Control of System or Configuration Setting")
        self.assertEqual(
            description,
            "One or more system settings or configuration elements can be externally controlled by a user.",
        )

        report_item.item["attrs"]["cwe"][0] = "79"
        name, description = report_item.get_cwe_name_and_description(1)
        self.assertEqual(
            name,
            "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        )
        self.assertEqual(
            description,
            "The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
        )

    def test_get_reports(self):
        """
        Tests that the reports do not include example files.
        """
        for filename, _ in get_report_files(config.reports_dir()):
            self.assertNotEqual(filename, "example.json")
            self.assertNotEqual(filename, "example_cz.json")


if __name__ == "__main__":
    unittest.main()
