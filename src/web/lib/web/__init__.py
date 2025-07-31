from bleach import clean, css_sanitizer
from markupsafe import Markup

from lib import config
from lib.report.vulnerability_report import VulnerabilityReport


def translate(report: VulnerabilityReport, key: str) -> str:
    """
    Gets the correct phrase for the given key from language.json file
    in the language based on the author of the report.
    Default is Czech, and Slovak authors must be specified
    in the application configuration (config.ini).
    """
    language = "cs"
    author_identifiers = [report.get_author(), report.get_author_username()]
    if any(item in config.slovak_authors() for item in author_identifiers):
        language = "sk"
    return config.get_translations(language).get(key.lower())


def transform_link_references(text: str, links: list[str]) -> str:
    """
    Transforms references to links ([1], [2]...) to <a>...</a>.
    """
    for i, link in enumerate(links, start=1):
        text = text.replace(f"[{i}]", f"<a href='{link}' style='text-decoration: none;'>[{i}]</a>")
    return text


def do_clean(text: str) -> Markup:
    """
    Cleans the text from HTML elements other than <a> to prevent XSS,
    because the description is from external source (Taranis).
    CSS sanitizer is needed because we need to allow style attribute.
    """
    sanitizer = css_sanitizer.CSSSanitizer(allowed_css_properties=["text-decoration"])
    return Markup(clean(text, tags=["a"], attributes=["href", "style"], css_sanitizer=sanitizer))
