# pylint: disable=missing-function-docstring,missing-class-docstring,protected-access
# ruff: noqa: ERA001
"""
This file can be used for testing (e.g. the events module).
"""

from pathlib import Path

from lib.event import Events, SnerSearcher
from lib.report.vulnerability_report import VulnerabilityReport

REPORT = VulnerabilityReport(Path("reports/example_cz.json"))


def try_event_gen():
    events = Events(REPORT)
    events.print()
    print(events.get_all_IDs_as_mentat_links())
    # print(events.send_to_warden())


def try_sner_searcher():
    searcher = SnerSearcher()
    print(
        searcher.version_search(
            product="openssh",
            version_spec=">=4.3,<4.3.3",
            os_spec="*",
        )
    )


# try_event_gen()
try_sner_searcher()
