# pylint: disable=missing-function-docstring,missing-class-docstring,protected-access

import unittest
from pathlib import Path

from lib import TEST_DIR
from lib.event.history import EventHistory


class Test(unittest.TestCase):
    HISTORY_FILE = TEST_DIR / "history"

    def tearDown(self):
        if Path.exists(self.HISTORY_FILE):
            self.HISTORY_FILE.unlink()

    def test_invalid_state(self) -> None:
        history = EventHistory(self.HISTORY_FILE)
        self.assertRaises(ValueError, history.print_all)
        self.assertRaises(ValueError, history.get_all)
        self.assertRaises(ValueError, history.print_all)
        with self.assertRaises(ValueError):
            history.get_report_history("12")
        with self.assertRaises(ValueError):
            history.print_report_history("12")
        with self.assertRaises(ValueError):
            history.remove_report_history("12")

    def test_simple_modification(self):
        with EventHistory(self.HISTORY_FILE) as history:
            report_history = history.get_report_history("11", initialize=True)
            report_history.add("1.1.1.1")
            report_history.add("2.2.2.2")
            report_history.add("3.3.3.3")
            report_history.remove("2.2.2.2")
            self.assertEqual(report_history, history.get_report_history("11"))
            self.assertEqual(history.get_all(), {"11": {"1.1.1.1", "3.3.3.3"}})

            history.get_report_history("10", initialize=True)
            self.assertIn("10", history.get_all().keys())
            history.remove_report_history("10")
            self.assertNotIn("10", history.get_all().keys())


if __name__ == "__main__":
    unittest.main()
