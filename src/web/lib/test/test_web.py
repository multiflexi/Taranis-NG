# pylint: disable=missing-function-docstring,missing-class-docstring,protected-access
# ruff: noqa: E501

import unittest

from flask import url_for

from lib import TEST_DIR
from lib.report.vulnerability_report import VulnerabilityReport
from lib.web import (
    transform_link_references,
    translate,
)
from lib.web.app import app
from lib.web.routes import _get_rss_description, _remove_link_references


class Test(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.app.config["SERVER_NAME"] = "127.0.0.1"

    def load_report(self):
        return VulnerabilityReport(TEST_DIR / "report_test.json")

    def test_translate(self):
        report = self.load_report()
        self.assertEqual(translate(report, "published"), "Publikované")
        self.assertEqual(translate(report, "more_info"), "Viac informácií")
        self.assertEqual(translate(report, "links"), "Odkazy")
        self.assertEqual(
            translate(report, "vulnerability_exposed"),
            "Zraniteľnosť bola verejne oznámená",
        )

        report.report["product"]["user"]["name"] = {"Petr Pavel"}
        self.assertEqual(translate(report, "published"), "Publikováno")
        self.assertEqual(translate(report, "more_info"), "Více informací")
        self.assertEqual(translate(report, "links"), "Odkazy")
        self.assertEqual(
            translate(report, "vulnerability_exposed"),
            "Zranitelnost byla veřejně oznámena",
        )

    def test_link_transformation(self):
        text = "This is an example statement [1][2]. As [2] pointed out..."
        links = ["https://cesnet.cz", "https://nukib.cz"]
        result = transform_link_references(text, links)
        expected_result = "This is an example statement <a href='https://cesnet.cz' style='text-decoration: none;'>[1]</a><a href='https://nukib.cz' style='text-decoration: none;'>[2]</a>. As <a href='https://nukib.cz' style='text-decoration: none;'>[2]</a> pointed out..."
        self.assertEqual(result, expected_result)

        result = _remove_link_references(text, links)
        expected_result = "This is an example statement. As pointed out..."
        self.assertEqual(result, expected_result)

    def test_web_return_values(self):
        with self.app.test_client() as client, self.app.app_context():
            self.assertEqual(
                client.get(url_for("reports.show", report_id="example")).status_code,
                200,
            )
            self.assertEqual(
                client.get(url_for("reports.show", report_id="example_cz")).status_code,
                200,
            )
            self.assertEqual(client.get(url_for("reports.home")).status_code, 200)
            # Only alphabetical characters and '_' are allowed as report_id, not '.'
            self.assertEqual(
                client.get(url_for("reports.show", report_id="..example")).status_code,
                400,
            )
            # Invalid URL
            self.assertEqual(client.get("/repor").status_code, 404)

    def test_feedback_view(self):
        with self.app.test_client() as client, self.app.app_context():
            # Empty request.
            result = client.post(url_for("reports.feedback", report_id="example_cz"), data={})
            self.assertEqual(result.status_code, 400)
            # Invalid answer.
            result = client.post(
                url_for("reports.feedback", report_id="example_cz"),
                data={"feedback-question1": "yes", "feedback-question2": "no"},
            )
            self.assertEqual(result.status_code, 400)
            # Missing a mandatory question.
            result = client.post(
                url_for("reports.feedback", report_id="example_cz"),
                data={"feedback-question2": "ne", "feedback-question3": "ne"},
            )
            self.assertEqual(result.status_code, 400)
            # Invalid report id, '.' is not allowed.
            result = client.post(
                url_for("reports.feedback", report_id="..example_cz"),
                data={"feedback-question1": "ano", "feedback-question2": "ne"},
            )
            self.assertEqual(result.status_code, 400)

            result = client.post(
                url_for("reports.feedback", report_id="example_cz"),
                data={"feedback-question1": "ano", "feedback-question2": "ne"},
            )
            self.assertEqual(result.status_code, 200)
            result = client.post(
                url_for("reports.feedback", report_id="example_cz"),
                data={
                    "feedback-question1": "ano",
                    "feedback-question2": "ne",
                    "feedback-question3": "ne",
                    "feedback-comment": "Dobrá práca",
                },
            )
            self.assertEqual(result.status_code, 200)

    def test_report_content_sk(self):
        with self.app.test_client() as client, self.app.app_context():
            result = client.get(url_for("reports.show", report_id="example"))
            self.assertIn(b"TLP:", result.data)
            self.assertIn(b"CVE-", result.data)
            self.assertIn(b"CVSS", result.data)
            self.assertIn(b"Viac inform", result.data)
            self.assertIn(b"Zranite", result.data)
            self.assertIn(b"v produkt", result.data)
            self.assertIn(b"vo verz", result.data)
            self.assertIn(b"bola verejne ozn", result.data)
            self.assertIn(b"Naposledy bol tento report", result.data)

    def test_report_content_cz(self):
        with self.app.test_client() as client, self.app.app_context():
            result = client.get(url_for("reports.show", report_id="example_cz"))
            self.assertEqual(result.status_code, 200)
            self.assertIn(b"TLP:", result.data)
            self.assertIn(b"CVE-", result.data)
            self.assertIn(b"CVSS", result.data)
            self.assertIn(b"ce informac", result.data)
            self.assertIn(b"Zranitelnost", result.data)
            self.assertIn(b"v produkt", result.data)
            self.assertIn(b"ve verz", result.data)
            self.assertIn(b"byla ve", result.data)
            self.assertIn(b"Naposledy byl tento report", result.data)
            self.assertIn(b"dne", result.data)

    def test_rss_feed(self):
        report = self.load_report()
        self.assertEqual(
            _get_rss_description(report),
            "Zneužitím všetkých zraniteľností je možné vykonať vzdialené spúšťanie kódu a zvýšiť tak dopad na kritický.\n\nZraniteľnosti:\nJunosOS 1 (CVE-2023-36844, CVE-2023-36845, CVSS 7.5),\nJuniper Junos - autorizácia (CVSS 4.0)",
        )
        with self.app.test_client() as client, self.app.app_context():
            result = client.get("/feed")
            self.assertEqual(result.status_code, 200)
            self.assertIn(b"rss", result.data)
            self.assertIn(b"version", result.data)
            self.assertIn(b"CESNET", result.data)
            self.assertIn(b"python-feedgen", result.data)
            self.assertIn(b"http://www.rssboard.org/rss-specification", result.data)
            self.assertIn(b"lastBuildDate", result.data)
            self.assertIn(b"channel", result.data)
            self.assertIn(b"title", result.data)
            self.assertIn(b"description", result.data)
            self.assertIn(b"link", result.data)


if __name__ == "__main__":
    unittest.main()
