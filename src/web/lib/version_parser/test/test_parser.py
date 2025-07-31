# pylint: disable=missing-function-docstring,missing-class-docstring,protected-access

import unittest

from lib.version_parser import InvalidFormatException, is_in_version_range, parse


class Test(unittest.TestCase):
    def test_invalid_version(self) -> None:
        with self.assertRaises(InvalidFormatException):
            parse("3.0")
        with self.assertRaises(InvalidFormatException):
            parse("!3.0")
        with self.assertRaises(InvalidFormatException):
            parse("p3.0")
        # These should be parsed without an Exception:
        parse("!=3.0")
        parse("==3.0")
        parse("  =3.0")
        parse("=3.0")
        parse(" =3.0    ;  =4.0")
        parse(">=3.0")
        parse("   >3.0")
        parse(" <=3.0 ")
        parse("<3.0")

    def test_is_in_version_range(self) -> None:
        version_spec = parse(">=3.0 ,  <4.0; =5.0 ")
        self.assertFalse(is_in_version_range("5.1", version_spec))
        self.assertFalse(is_in_version_range("4.0", version_spec))
        self.assertFalse(is_in_version_range("2.3", version_spec))
        self.assertTrue(is_in_version_range("5.0", version_spec))
        self.assertTrue(is_in_version_range("3.0", version_spec))
        self.assertTrue(is_in_version_range("3.8", version_spec))
        self.assertTrue(is_in_version_range("3.3.3", version_spec))

        version_spec = parse("  >=3.0, <3.3; >=5.0.0")
        self.assertTrue(is_in_version_range("3.0", version_spec))
        self.assertTrue(is_in_version_range("3.1.3", version_spec))
        self.assertTrue(is_in_version_range("3.2.5", version_spec))
        self.assertTrue(is_in_version_range("5.0.1", version_spec))
        self.assertTrue(is_in_version_range("7.1.0", version_spec))
        self.assertFalse(is_in_version_range("3.3", version_spec))
        self.assertFalse(is_in_version_range("3.4", version_spec))
        self.assertFalse(is_in_version_range("2.0", version_spec))
        self.assertFalse(is_in_version_range("1.3.5", version_spec))
        self.assertFalse(is_in_version_range("4.2", version_spec))

        # Debian patches.
        version_spec = parse(">4.0")
        self.assertTrue(is_in_version_range("4.0p1", version_spec))
        self.assertTrue(is_in_version_range("4.0p1 Debianblablabla", version_spec))
        self.assertFalse(is_in_version_range("4.0", version_spec))
