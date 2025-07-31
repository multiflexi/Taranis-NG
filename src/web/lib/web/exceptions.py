from datetime import UTC, datetime
from traceback import TracebackException

from flask import (
    Flask,
    render_template,
    request,
)
from werkzeug.exceptions import HTTPException

from lib import (
    config,
    send_mail,
)


def register_error_handlers(app: Flask) -> None:
    """
    Registers all error handlers for the Flask application.
    """

    @app.errorhandler(400)
    @app.errorhandler(404)
    @app.errorhandler(405)
    def HTTPExceptions_not_mailed(e: HTTPException) -> tuple[str, int]:
        """
        Handles codes and Exceptions that should not be mailed.
        """
        return (
            render_template("error.html", code=e.code, name=e.name, desc=e.description),
            e.code or 400,
        )

    @app.errorhandler(Exception)
    def internal_server_error(e: Exception) -> tuple[str, int]:
        """
        Handles error codes and Exceptions that occurred in the application.
        A custom web page is shown to the user (error template).
        Exceptions are also mailed to admins.
        """
        code = e.code if (hasattr(e, "code") and e.code is not None) else 500
        traceback = "".join(TracebackException.from_exception(e).format())
        send_mail(
            f"Unexpected Exception (HTTP {code}) occurred on the VA2AM "
            f"web at {datetime.now(UTC)} UTC."
            f"\n\nRequest: {request.full_path}\n\nTraceback: {traceback}",
            "[VA2AM] Internal server error",
            recipients=config.admin_mail(),
        )
        name = e.name if hasattr(e, "name") else None
        description = e.description if hasattr(e, "description") else None
        return (
            render_template("error.html", code=code, name=name, desc=description),
            code,
        )
