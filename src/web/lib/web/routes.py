import json
import math
from typing import Optional

from feedgen.feed import FeedGenerator
from flask import (
    Blueprint,
    Response,
    abort,
    make_response,
    render_template,
    request,
    url_for,
)

from lib import (
    config,
    send_mail,
)
from lib.logger import get_logger
from lib.report.vulnerability_report import VulnerabilityReport
from lib.web import translate
from lib.web.cache import WebCache

MAXIMUM_LIMIT_HOMEPAGE = config.max_reports_homepage()

feedback_logger = get_logger("feedback", silent=True)
cache = WebCache()


reports_bp = Blueprint("reports", __name__)


def _remove_link_references(text: str, links: list[Optional[str]]) -> str:
    """
    Removes references ([1], [2]...) from text.
    """
    for i, _ in enumerate(links, start=1):
        text = text.replace(f" [{i}]", "").replace(f"[{i}]", "")
    return text


def _get_rss_description(report: VulnerabilityReport) -> str:
    """
    Returns the RSS description for this vulnerability report. (in escaped HTML)
    """
    result = report.get_one_description()
    if len(report.items) > 0:
        result += f"\n\n{translate(report, 'vulnerabilities')}:\n"
    for i, item in enumerate(report.items):
        item_description = item.get_name().strip()
        if item_description[-1] == ")" and item.get_cvss_number() is not None:
            item_description = item_description[:-1] + f", CVSS {item.get_cvss_number()})"
        elif item.get_cvss_number() is not None:
            item_description += f" (CVSS {item.get_cvss_number()})"
        result += item_description
        if i < len(report.items) - 1:
            result += ",\n"
    return _remove_link_references(result, report.get_links())


@reports_bp.route("/", endpoint="home")
def homepage() -> str:
    """
    Endpoint for homepage rendering. The homepage consists of
    a list of reports. There is a limit of reports per page,
    this limit can be set in the configuration file (config.ini).
    Reports can also be filtered using a keyword.
    """
    search_arg = request.args.get("search")
    try:
        page = int(request.args.get("page") or 1)
    except ValueError:
        abort(400)

    reports = cache.get_all_reports()
    if search_arg:
        # Filter per keyword search from arguments.
        reports = [report for report in reports if report.matches_keyword(search_arg)]

    pages = math.ceil(len(reports) / MAXIMUM_LIMIT_HOMEPAGE)
    upper_report_index = MAXIMUM_LIMIT_HOMEPAGE * page
    lower_report_index = upper_report_index - MAXIMUM_LIMIT_HOMEPAGE
    return render_template(
        "homepage.html",
        reports=reports[lower_report_index:upper_report_index],
        search_arg=search_arg,
        page=page,
        pages=pages,
        warning_seen=request.cookies.get("warning-seen"),
    )


@reports_bp.route("/rss", endpoint="rss")
@reports_bp.route("/feed", endpoint="feed")
def rss() -> Response:
    """
    Endpoint for rendering an RSS feed.
    """
    if response := cache.get_rss_response():
        return response

    fg = FeedGenerator()
    fg.title("CESNET Vulnerability Reports")
    fg.description("CESNET reporty o zranitelnostech.")
    fg.link(href=config.website_hostname())

    reports = cache.get_all_reports()

    # If the maximum limit is 20, only 20 latest items should be kept.
    item_count = min(config.max_reports_rss(), len(reports))

    # add_entry() adds items in a reverse order (the first added item will be
    # the last in the feed), that's why reversed() is needed.
    for report in reversed(reports[:item_count]):
        report_link = config.website_hostname() + url_for("reports.show", report_id=report.get_id())
        fe = fg.add_entry()
        fe.title(report.get_formatted_tlp(with_space=True) + report.get_title())
        fe.link(href=report_link)
        fe.description(_get_rss_description(report))
        fe.guid(report_link, permalink=True)

    response = make_response(fg.rss_str())
    response.headers.set("Content-Type", "application/xml")

    cache.cache_rss_response(response)
    return response


@reports_bp.route("/reports/<report_id>", endpoint="show")
def report_view(report_id: str) -> str:
    """
    Endpoint for displaying a vulnerability report.
    """
    # Check if all the characters of the report_id are alphanumerical or _ (example_cz).
    for char in report_id:
        if not char.isalnum() and char != "_":
            abort(400)
    try:
        report = VulnerabilityReport(f"{config.reports_dir()}/{report_id}.json")
        items_arg = request.args.get("items")
        items = list(map(int, items_arg.split(","))) if items_arg else []
        return render_template(
            "report.html",
            report=report,
            items=items,
            feedback_q=config.feedback_questions(),
            warning_seen=request.cookies.get("warning-seen"),
        )
    except FileNotFoundError:
        abort(404)
    except UnicodeEncodeError:
        abort(400)


@reports_bp.route("/reports/<report_id>/feedback", endpoint="feedback", methods=["POST"])
def feedback_view(report_id: str) -> tuple[str, int, dict[str, str]]:
    """
    Endpoint for sending a feedback about a report based on the form data.
    """
    # Basic validation of form values.
    for question, is_mandatory in [
        ("feedback-question1", True),
        ("feedback-question2", True),
        ("feedback-question3", False),
    ]:
        if is_mandatory and question not in request.form:
            abort(400)
        if question in request.form and request.form.get(question, "").lower() not in [
            "ano",
            "ne",
        ]:
            abort(400)
    questions = config.feedback_questions()

    # Check if all the characters of the report_id are alphanumerical or _ (example_cz).
    for char in report_id:
        if not char.isalnum() and char != "_":
            abort(400)
    report = VulnerabilityReport(f"{config.reports_dir()}/{report_id}.json")

    body = f'''Ve VA2AM byl odeslán feedback k reportu {report.get_title()}
({config.website_hostname()}{url_for("reports.show", report_id=report_id)}).

{questions["question1"]} "{request.form.get("feedback-question1", "---")}"
{questions["question2"]} "{request.form.get("feedback-question2", "---")}"
{questions["question3"]} "{request.form.get("feedback-question3", "---")}"
{questions["comment"]} "{request.form.get("feedback-comment", "-")}"'''

    feedback_logger.info(
        "Feedback for report with ID %s will be sent through e-mail:\n%s.",
        report_id,
        body,
    )
    send_mail(
        body,
        f"[VA2AM] Feedback k reportu (report ID {report_id})",
        recipients=config.info_mail(),
        logger=feedback_logger,
    )

    return (json.dumps({"success": True}), 200, {"ContentType": "application/json"})
