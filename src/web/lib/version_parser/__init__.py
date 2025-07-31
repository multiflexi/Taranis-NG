import re

from packaging.specifiers import InvalidSpecifier, SpecifierSet


class InvalidFormatException(Exception):
    """
    This exception is thrown when the format is invalid.
    """


def parse(versions_input: str) -> list[SpecifierSet]:
    """
    Parses the input, which should have the following format:
    "versions_specifier1; versions_specifier2; ..."

    Supported operators for version specifiers are:
    '==' ('=' also works), '>', '>=', '<', '<=', '!='

    If you use ';' as a separator (e.g. ">=4.0; ==2.0"), then
    at least one of the specifiers must be met.
    But if you use ',' as a separator (e.g. ">=3.0, <4.0"), then
    all the version specifications in this section must be met.
    So if the specification is ">=3.0, <4.0; ==5.0", then the version
    must either be in range <3.0, 4.0), or it must be equal to 5.0.

    Returns a tuple of product and version specification, which have
    a form of a list of SpecifierSets from packaging library.
    """
    version_specifiers = []
    for original_spec in versions_input.split(";"):
        # Recommended reading to understand this regex:
        # https://docs.python.org/3.8/library/re.html#index-23
        # https://docs.python.org/3.8/library/re.html#index-21
        #
        # If '=' is not surrounded by '=', '<', '>', '!' or '~' on
        # the left side, or by '=' on the right side, replace
        # it with '==' so it can be parsed using SpecifierSet.
        spec = re.sub("(?<![!=<>~])=(?![=])", "==", original_spec)
        try:
            version_specifiers.append(SpecifierSet(spec))
        except InvalidSpecifier as e:
            raise InvalidFormatException(f'Invalid format: version specifier "{spec}" ' f"does not meet the format criteria.") from e

    return version_specifiers


def is_in_version_range(version: str, specifiers: list[SpecifierSet]) -> bool:
    """
    Checks if the version is in the range specified by a list of SpecifierSets.
    If at least one of the specifiers matches the version, then the result
    is True, otherwise it is False.
    """
    # Recommended reading to understand this regex:
    # https://docs.python.org/3.8/library/re.html#index-22
    # https://docs.python.org/3.8/library/re.html#index-20
    #
    # Replaces the 'p' with '.' if 'p' is surrounded by 0-9 from both sides.
    # Then it can be parsed correctly. This is often the case with
    # Debian patches fixing a vulnerability in an older version.
    version = re.sub("(?<=[0-9])p(?=[0-9])", ".", version)
    # Forget everything after the first space. (unnecessary details)
    # e.g.: '7.9p1 Debian 10+deb10u2' -> '7.9p1' -> '7.9.1'
    version_without_spaces = version.split(" ")[0]

    return any(version_without_spaces in specifier for specifier in specifiers)
