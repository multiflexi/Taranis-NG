# pylint: disable=missing-function-docstring,missing-class-docstring,protected-access

import json
import unittest
from pathlib import Path
from shutil import rmtree
from typing import Any

from lib import TEST_DIR
from lib.event import Events
from lib.event.idea import IDEAEvent, IPv4, IPv6
from lib.event.sner import SnerSearcher
from lib.logger import get_logger
from lib.report.vulnerability_report import VulnerabilityReport


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not Path.exists(TEST_DIR / "test_files"):
            Path.mkdir(TEST_DIR / "test_files")

    @classmethod
    def tearDownClass(cls):
        if Path.exists(TEST_DIR / "test_files"):
            rmtree(TEST_DIR / "test_files")

    @staticmethod
    def get_example_result(ips: set[str]) -> list[dict[str, Any]]:
        return [
            {
                "22222/tcp": {
                    "extra": {},
                    "host_addresses": ips,
                    "host_hostname": "armor.grid.cesnet.cz",
                    "product": "openbsd openssh",
                    "service_port": 22222,
                    "service_proto": "tcp",
                    "version": "6.7p1",
                    "items": {1, 2},
                }
            }
        ]

    @staticmethod
    def load_report() -> VulnerabilityReport:
        return VulnerabilityReport(TEST_DIR / "report_test.json")

    def test_IDEA_event(self) -> None:
        results = self.get_example_result({"78.128.216.110", "2001:718:ff05:202::110"})
        event = IDEAEvent(results[0].values(), report=self.load_report())
        self.assertEqual(
            event.get_all_hosts(),
            ({"78.128.216.110", "2001:718:ff05:202::110"}, {"armor.grid.cesnet.cz"}),
        )
        with Path.open(TEST_DIR / "expected_idea.json", encoding="utf-8") as f:
            expected = json.load(f)

        event.save(TEST_DIR / "test_files")
        event_path = TEST_DIR / "test_files" / f"{event.get_dict()['ID']}.idea.json"
        with Path.open(event_path, encoding="utf-8") as f:
            saved = json.load(f)

        for created in (json.loads(event.get_json()), event.get_dict(), saved):
            # Check if the time string is in the correct format.
            self.assertRegex(created["DetectTime"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
            # Assume that the detection time and ID is correct.
            created["DetectTime"] = expected["DetectTime"]
            created["ID"] = expected["ID"]
            # We do not care if they are sorted, but it matters for the equality check.
            created["Source"][0]["Ref"] = sorted(created["Source"][0]["Ref"])
            expected["Source"][0]["Ref"] = sorted(expected["Source"][0]["Ref"])
            self.assertEqual(created, expected)

    def test_get_ip_type(self) -> None:
        self.assertEqual(IDEAEvent._get_ip_type("78.128.216.110"), IPv4)
        self.assertEqual(IDEAEvent._get_ip_type("0.0.0.1"), IPv4)
        self.assertEqual(IDEAEvent._get_ip_type("2001:718:ff05:202::110"), IPv6)
        self.assertEqual(IDEAEvent._get_ip_type("1c33:bae9:e95e::"), IPv6)
        self.assertEqual(IDEAEvent._get_ip_type("1..2.3"), None)
        self.assertEqual(IDEAEvent._get_ip_type("256.1.1.1"), None)

    def test_process_results(self):
        results = [
            {
                "extra": {},
                "host_address": "7.128.25.115",
                "host_hostname": "argon.cesnet.cz",
                "product": "openbsd openssh",
                "service_port": 12345,
                "service_proto": "tcp",
                "version": "6.7p1",
            },
            {
                "extra": {},
                "host_address": "2001:728:fg05:202::110",
                "host_hostname": "armor.cesnet.cz",
                "product": "openbsd openssh",
                "service_port": 1984,
                "service_proto": "tcp",
                "version": "6.7p1",
            },
            {
                "extra": {},
                "host_address": "7.128.216.110",
                "host_hostname": "armor.cesnet.cz",
                "product": "openbsd openssh",
                "service_port": 1984,
                "service_proto": "tcp",
                "version": "6.7p1",
            },
        ]

        processed = {}
        Events._process_results(processed, results, 1)

        self.assertIn("argon.cesnet.cz", processed)
        self.assertIn("armor.cesnet.cz", processed)
        self.assertEqual(len(processed), 2)

        argon = processed.get("argon.cesnet.cz")
        self.assertIn("12345/tcp", argon)
        results[0]["items"] = {1}
        del results[0]["host_address"]
        results[0]["host_addresses"] = {"7.128.25.115"}
        self.assertEqual(results[0], argon.get("12345/tcp"))

        armor = processed.get("armor.cesnet.cz")
        self.assertIn("1984/tcp", armor)
        results[2]["items"] = {1}
        del results[2]["host_address"]
        results[2]["host_addresses"] = {"7.128.216.110", "2001:728:fg05:202::110"}
        self.assertEqual(results[2], armor.get("1984/tcp"))

    def test_os_spec(self):
        searcher = SnerSearcher()
        # Test basic specification.
        self.assertTrue(searcher._satisfies_os_spec("debian", "debian"))
        self.assertFalse(searcher._satisfies_os_spec("debian", "ubuntu"))
        self.assertFalse(searcher._satisfies_os_spec("ubuntu", "debian"))
        self.assertFalse(searcher._satisfies_os_spec(None, "ubuntu"))

        # Test multiple part specification.
        self.assertTrue(searcher._satisfies_os_spec("debian", "debian,ubuntu"))
        self.assertTrue(searcher._satisfies_os_spec("debian", "ubuntu,debian"))
        self.assertTrue(searcher._satisfies_os_spec("ubuntu", "debian,ubuntu"))
        self.assertFalse(searcher._satisfies_os_spec("centos", "ubuntu,debian"))
        self.assertFalse(searcher._satisfies_os_spec("windows", "ubuntu,debian"))
        self.assertFalse(searcher._satisfies_os_spec(None, "ubuntu,debian"))

        # Test empty (vanilla) specification.
        self.assertTrue(searcher._satisfies_os_spec("windows", ""))
        self.assertTrue(searcher._satisfies_os_spec(None, ""))
        self.assertFalse(searcher._satisfies_os_spec("ubuntu", ""))
        self.assertFalse(searcher._satisfies_os_spec("debian", ""))
        self.assertFalse(searcher._satisfies_os_spec("centos", ""))

        # Test get OS helper method.
        self.assertEqual(searcher._get_OS_from_result({"extra": {"os": "debian"}}), "debian")
        self.assertEqual(
            searcher._get_OS_from_result({"version": "9.2p1 Debian 2+deb12u3"}),
            "debian",
        )

    def sner_searcher(self):
        """
        This test will not be run in CI/CD because it needs key to
        Sner's API. You can enable it locally by adding "test_" to
        the name of this testing method.
        """
        searcher = SnerSearcher(get_logger("incoming"))
        # Check host search.
        result = searcher.host_search("2001:718:ff05:10c::203")
        self.assertEqual(result["hostname"], "va2am.vm.cesnet.cz")
        for check in ["Apache httpd", "Linux", "Ubuntu", "hostname: va2am.cesnet.cz"]:
            self.assertTrue(any(check in service["info"] for service in result["services"] if "info" in service))

        # Check guess_host_OS method.
        self.assertEqual(searcher.guess_host_OS("78.128.248.203"), "ubuntu")
        self.assertEqual(searcher.guess_host_OS("78.128.211.127"), "debian")

        # Check version search.
        for result in searcher.version_search("squid", ">5.0"):
            self.assertTrue(any(check in result["product"] for check in ["squid-cache squid", "squid http proxy"]))

        for result in searcher.version_search("mod_wsgi", "=4.7.1", "almalinux"):
            self.assertTrue("almalinux" in result["extra"]["os"].lower())
            self.assertTrue("mod_wsgi" in result["product"].lower())
            self.assertTrue("4.7.1" in result["version"])


if __name__ == "__main__":
    unittest.main()
