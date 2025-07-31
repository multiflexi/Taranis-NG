import re
from pathlib import Path
from typing import Optional


class MissingFieldError(TypeError):
    """
    This Exception is raised if a mandatory field is missing.
    """

    def __init__(self, field: str, report_type: object) -> None:
        super().__init__(f"Mandatory report field {field} is missing in {type(report_type)} JSON!")


def format_date(date: dict[str, int]) -> str:
    """
    Input is a dictionary with keys 'day', 'month' and 'year'.
    Returns the date formatted into 'DD. MM. YYYY' format (but without
    leading zeroes) or None if the input is invalid.
    """
    if not date or "day" not in date or "month" not in date or "year" not in date:
        raise ValueError(f"Wrong date input: {date}. It must have day, month and year keys.")
    return f"{date['day']}. {date['month']}. {date['year']}"


def reformat_date(date: str) -> str:
    """
    Input date is in 'YYYY.MM.DD' format.
    Returns the date formatted into 'DD. MM. YYYY' format (but without
    leading zeroes).
    """
    if date is None or len(date.split(".")) != 3:
        raise ValueError(f"Wrong date format: {date}. It must be in YYYY.MM.DD.")
    year, month, date = date.strip().split(".")
    return f"{int(date)}. {int(month)}. {year}"


def capitalize_and_fix_spaces(string: str) -> str:
    """
    Capitalizes only the first word. This is needed because string.capitalize()
    in Python makes all other letters lowercase, which is not an expected behavior.

    A report from Taranis can contain double spaces, which is always not wanted.
    So this function also removes them.
    """
    if len(string) == 0:
        return string
    capitalized = string[0].upper() + string[1:]
    return re.sub(" +", " ", capitalized).strip()


def get_cvss_severity(score: Optional[float]) -> Optional[str]:
    """
    Returns the severity of the CVSS score based on:
    https://www.first.org/cvss/specification-document,
    or None if the CVSS score is missing.
    """
    if score is None:
        return None
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


def get_report_files(directory: Path) -> list[tuple[str, Path]]:
    """
    Finds all report files saved in the directory from the 'directory'
    argument and returns their filename and path.
    """
    reports = []
    for file in Path.iterdir(directory):
        # Ignore hidden files and example reports.
        if not file.name.startswith(".") and file.is_file() and "example" not in file.name:
            reports.append((file.name, file))  # noqa: PERF401
    return reports
