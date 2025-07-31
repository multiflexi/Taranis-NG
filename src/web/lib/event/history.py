import shelve
from argparse import ArgumentParser
from pathlib import Path
from shelve import Shelf
from typing import Any, Optional

from lib import config


class EventHistory:
    """
    This class loads the event history file and provides
    methods to read and change it.

    Recommended use of this class is using 'with' syntax:
    with EventHistory() as history:
        ...
    """

    DEFAULT_PATH = config.archive_dir() / "history"

    def __init__(self, path: Path = DEFAULT_PATH) -> None:
        self._path = path
        self._history: Optional[Shelf] = None

    def close(self) -> None:
        """
        Closes the history file.
        """
        if self._history:
            self._history.close()

    def open(self) -> None:
        """
        Opens the history file.
        """
        if not self._history:
            self._history = shelve.open(self._path, writeback=True)  # noqa: SIM115, S301

    # These two methods are here so this class can be used using 'with' syntax.
    def __enter__(self) -> "EventHistory":
        self.open()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback) -> None:  # type: ignore
        self.close()

    def print_all(self) -> None:
        """
        Prints history each report on a new line.
        """
        if self._history is None:
            raise ValueError("History is not open!")
        for key in self._history:
            print(f"{key}: {self._history[key]}")

    def get_all(self) -> dict[str, Any]:
        """
        Returns the whole history as a dictionary.
        """
        if self._history is None:
            raise ValueError("History is not open!")
        return dict(self._history)

    def get_report_history(self, report_id: str, initialize: bool = False) -> set[str]:
        """
        Returns the history for the report with given report_id.
        If the initialize argument is set to True, initialize
        the history for this report.
        """
        if self._history is None:
            raise ValueError("History is not open!")
        if initialize:
            self._history.setdefault(report_id, set())
        return self._history.get(report_id, {})

    def print_report_history(self, report_id: str) -> None:
        """
        Prints history for a specific report.
        """
        if self._history is None:
            raise ValueError("History is not open!")
        print(f"{report_id}: {self._history.get(report_id)}")

    def remove_report_history(self, report_id: str) -> None:
        """
        Removes the report history for the given report.
        Should be used with caution!
        """
        if self._history is None:
            raise ValueError("History is not open!")
        if report_id in self._history:
            del self._history[report_id]


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument(
        "--print",
        help="print the history for the given report",
    )
    parser.add_argument(
        "--print-all",
        action="store_true",
        help="print the history for all reports",
    )
    parser.add_argument(
        "-d",
        "--delete",
        help="delete the history for the given report item",
    )

    args = parser.parse_args()
    with EventHistory() as history:
        if args.print_all:
            history.print_all()
        if args.print:
            history.print_report_history(args.print)
        if args.delete:
            history.remove_report_history(args.delete)
