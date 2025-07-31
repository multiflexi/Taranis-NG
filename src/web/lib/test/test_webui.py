# pylint: disable=missing-function-docstring,unused-argument

from flask import url_for
from playwright.sync_api import Page, expect
from pytest_flask.live_server import LiveServer

BOGUS_INPUT = "bwefijnbEwfeEWFE"


def test_va2am_homepage_and_cookies(live_server: LiveServer, page: Page) -> None:
    page.goto(url_for("reports.home", _external=True))
    expect(page.get_by_role("heading", name="CESNET")).to_be_visible()
    assert page.title() == "Reporty - VA2AM"
    expect(page.locator("link[rel='icon']")).to_have_count(1)  # favicon

    # Check that the warning about CESNET service is present and no cookie is set.
    WARNING_TEXT = "Bezpečnostní služby poskytované organizací CESNET"
    expect(page.get_by_text(WARNING_TEXT)).to_be_visible()
    assert not any(cookie["name"] == "warning-seen" for cookie in page.context.cookies())

    # Click on the close button and check again (it should change).
    page.click("#services-warning-close")
    page.reload()
    expect(page.get_by_text(WARNING_TEXT)).not_to_be_visible()
    assert any(cookie["name"] == "warning-seen" for cookie in page.context.cookies())


def test_va2am_homepage_links(live_server: LiveServer, page: Page) -> None:
    page.goto(url_for("reports.home", _external=True))
    page.get_by_role("link", name="RSS").click()
    expect(page).to_have_url(url_for("reports.feed", _external=True))

    page.go_back()
    image = page.get_by_alt_text("CESNET CERTS Logo")
    expect(image).to_be_visible()

    # Check if the link opens a new window with the correct URL
    with page.expect_popup() as new_page_info:
        page.get_by_role("link").filter(has=image).click()
        new_page = new_page_info.value
        new_page.wait_for_load_state("domcontentloaded")
        expect(new_page).to_have_url("https://csirt.cesnet.cz/cs/index")


def test_homepage_search(live_server: LiveServer, page: Page) -> None:
    page.goto(url_for("reports.home", _external=True))

    # Check if a warning about empty search will be there
    page.get_by_role("textbox").fill(BOGUS_INPUT)
    page.locator("[type=submit]").click()
    expect(page.get_by_label("Warning:")).to_be_visible()
    expect(page).to_have_url(url_for("reports.home", _external=True) + "?search=" + BOGUS_INPUT)

    input2 = "Medium"
    page.get_by_role("textbox").fill(input2)
    page.locator("[type=submit]").click()
    expect(page).to_have_url(url_for("reports.home", _external=True) + "?search=" + input2)


def test_404_page(live_server: LiveServer, page: Page) -> None:
    page.goto(f"{url_for('reports.home', _external=True)}/{BOGUS_INPUT}")
    expect(page.get_by_role("heading", name="404")).to_be_visible()
    expect(page.get_by_text("Not Found")).to_be_visible()
    page.get_by_role("link").click()
    expect(page).to_have_url(url_for("reports.home", _external=True))


def test_report_page(live_server: LiveServer, page: Page) -> None:
    # Slovak report
    page.goto(url_for("reports.show", report_id="example", _external=True))
    expect(page.get_by_role("heading", name="[TLP:CLEAR] Juniper")).to_be_visible()
    expect(page.get_by_role("heading", name="Odkazy")).to_be_visible()
    expect(page.get_by_label("Warning:")).to_be_visible()
    expect(page.get_by_text("Zraniteľnosť").nth(0)).to_be_visible()
    expect(page.get_by_text("Viac informácií").nth(0)).to_be_visible()

    # Czech report
    page.goto(url_for("reports.show", report_id="example_cz", _external=True))
    expect(page.get_by_label("Warning:")).to_be_visible()
    expect(page.get_by_text("Zranitelnost").nth(0)).to_be_visible()
    expect(page.get_by_text("Více informací").nth(0)).to_be_visible()

    page.get_by_role("link", name="Home").click()
    expect(page).to_have_url(url_for("reports.home", _external=True))


def test_report_400(live_server: LiveServer, page: Page) -> None:
    # Report ID can only be alphanumerical or '_', '.' is not allowed
    page.goto(url_for("reports.show", report_id="..reports", _external=True))
    expect(page.get_by_role("heading", name="400")).to_be_visible()
    expect(page.get_by_text("Bad Request")).to_be_visible()
    page.get_by_role("link").click()
    expect(page).to_have_url(url_for("reports.home", _external=True))


def test_report_feedback(live_server: LiveServer, page: Page) -> None:
    page.goto(url_for("reports.show", report_id="example", _external=True))
    page.get_by_role("button", name="Dát zpětnou vazbu").click()
    expect(page.get_by_role("heading", name="Zpětná vazba")).to_be_visible()
    page.locator("#question1-yes").click()
    page.locator("#question2-no").click()
    page.locator("textarea#feedback-comment").fill("Dobrý report!")
    page.get_by_role("button", name="Odeslat").click()
    expect(page.get_by_text("Zpětná vazba úspěšne odeslána.")).to_be_visible()
