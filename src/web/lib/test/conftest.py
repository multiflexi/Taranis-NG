# pylint: disable=missing-function-docstring,unused-argument

import pytest

from lib.web.app import app as application


@pytest.fixture()
def app():
    application.config["SERVER_NAME"] = "127.0.0.1"
    yield application
