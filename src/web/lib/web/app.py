from flask import (
    Flask,
    request,
)

from lib import config
from lib.report import get_cvss_severity
from lib.web import do_clean, transform_link_references, translate
from lib.web.exceptions import register_error_handlers
from lib.web.routes import reports_bp

# Flask application definition and the definition of jinja functions.
app = Flask(__name__)
app.jinja_env.filters["clean"] = do_clean
app.jinja_env.globals.update(
    hostname=config.website_hostname(),
    translate=translate,
    transform_link_references=transform_link_references,
    get_cvss_severity=get_cvss_severity,
)

register_error_handlers(app)

# Blueprints
app.register_blueprint(reports_bp)


@app.context_processor
def inject_url() -> dict[str, str]:
    """
    Inject current URL to the Jinja templates.
    """
    return {"current_url": request.url}


if __name__ == "__main__":
    app.run(debug=not config.is_production())
