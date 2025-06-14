"""Module for Web collector."""

import copy
import datetime
import hashlib
import os
import re
import selenium
import subprocess
import time
import urllib.request
import uuid
from .base_collector import BaseCollector, not_modified
from dateutil.parser import parse
from shared.log_manager import logger
from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from shared.common import ignore_exceptions, read_int_parameter, smart_truncate
from shared.config_collector import ConfigCollector
from shared.schema.news_item import NewsItemData, NewsItemAttribute
from urllib.parse import urlparse


class WebCollector(BaseCollector):
    """Collector for gathering data from web page.

    Attributes:
        type (str): The type of the collector.
        name (str): The name of the collector.
        description (str): The description of the collector.
        parameters (list): The list of parameters for the collector.
        auth_username (str): The username for web page authentication.
        auth_password (str): The password for web page authentication.
        web_url (str): The URL of the web page.
        interpret_as (str): The type of the URL (uri or directory).
        user_agent (str): The user agent for the web page.
        tor_service (str): The Tor service status.
        pagination_limit (int): The maximum number of pages to visit.
        links_limit (int): The maximum number of article links to process.
        word_limit (int): The limit for the article body.
        selectors (dict): The dictionary of selectors for the web page.
        web_driver_type (str): The type of the web driver.
        client_cert_directory (str): The directory with client's certificates.
        proxy (str): The proxy server.
        proxy_port (int): The proxy port.
        proxy_proto (str): The proxy protocol.
        proxy_host (str): The proxy
    """

    type = "WEB_COLLECTOR"
    config = ConfigCollector().get_config_by_type(type)
    name = config.name
    description = config.description
    parameters = config.parameters
    logger.debug(f"{name}: Selenium version: {selenium.__version__}")

    SELECTOR_MAP = {
        "id": By.ID,
        "name": By.NAME,
        "xpath": By.XPATH,
        "tag_name": By.TAG_NAME,
        "tag": By.TAG_NAME,
        "class_name": By.CLASS_NAME,
        "class": By.CLASS_NAME,
        "css_selector": By.CSS_SELECTOR,
        "css": By.CSS_SELECTOR,
    }

    @staticmethod
    def __get_prefix_and_selector(element_selector):
        """Extract the prefix and selector from the given element_selector.

        Parameters:
            element_selector (str): The element selector in the format "prefix: selector".
        Returns:
            tuple: A tuple containing the prefix and selector as separate strings.
        """
        selector_split = element_selector.split(":", 1)
        if len(selector_split) != 2:
            return "", ""
        prefix = selector_split[0].strip().lower()
        selector = selector_split[1].lstrip()
        return prefix, selector

    @classmethod
    def __get_element_locator(cls, element_selector):
        """Extract a single element from the headless browser by selector.

        Parameters:
            element_selector (str): The selector used to locate the element.
        Returns:
            locator (tuple): A tuple containing the locator type and the selector.
        """
        prefix, selector = cls.__get_prefix_and_selector(element_selector)

        by = cls.SELECTOR_MAP.get(prefix)
        if by and selector:
            return (by, selector)
        return None

    @classmethod
    def __find_element_by(cls, driver, element_selector):
        """Extract single element from the headless browser by selector.

        Parameters:
            driver: The headless browser driver.
            element_selector: The selector used to locate the element.
        Returns:
            The extracted element.
        """
        prefix, selector = cls.__get_prefix_and_selector(element_selector)

        by = cls.SELECTOR_MAP.get(prefix)
        if by and selector:
            try:
                return driver.find_element(by, selector)
            except NoSuchElementException:
                return None
        return None

    @classmethod
    def __find_element_text_by(cls, driver, element_selector, return_none=False):
        """Find the text of an element identified by the given selector using the provided driver.

        Parameters:
            driver: The driver object used to interact with the web page.
            element_selector: The selector used to locate the element.
            return_none (bool): A boolean indicating whether to return None if the element is not found.
                         If set to False, an empty string will be returned instead.
                         Defaults to False.
        Returns:
            The text of the element if found, otherwise None or an empty string based on the value of return_none.
        """
        if return_none:
            failure_retval = None
        else:
            failure_retval = ""

        try:
            if element_selector:
                ret = cls.__find_element_by(driver, element_selector)
                return ret.text if ret else failure_retval
            else:
                return failure_retval
        except NoSuchElementException as e:  # noqa F841
            return failure_retval

    @classmethod
    def __find_elements_by(cls, driver, element_selector):
        """Extract list of elements from the headless browser by selector.

        Parameters:
            driver: The headless browser driver.
            element_selector: The selector used to locate the elements.
        Returns:
            A list of elements found using the given selector.
        """
        prefix, selector = cls.__get_prefix_and_selector(element_selector)

        by = cls.SELECTOR_MAP.get(prefix)
        if by and selector:
            try:
                return driver.find_elements(by, selector)
            except NoSuchElementException:
                return []
        return []

    @classmethod
    def __safe_find_elements_by(cls, driver, element_selector):
        """Safely find elements by the given element selector using the provided driver.

        Parameters:
            driver: The driver object used to interact with the web page.
            element_selector: The selector used to locate the elements.
        Returns:
            A list of elements matching the given selector, or None if no elements are found.
        """
        try:
            elements = cls.__find_elements_by(driver, element_selector)
            return elements if elements else None
        except NoSuchElementException as error:  # noqa F841
            return None

    @classmethod
    def __wait_for_new_tab(cls, browser, timeout, current_tab):
        """Wait for a new tab to open in the browser.

        Parameters:
            browser (WebDriver): The browser instance.
            timeout (int): The maximum time to wait for a new tab to open, in seconds.
            current_tab (str): The current tab handle.
        Raises:
            TimeoutException: If a new tab does not open within the specified timeout.
        """
        yield
        WebDriverWait(browser, timeout).until(lambda browser: len(browser.window_handles) != 1)
        for tab in browser.window_handles:
            if tab != current_tab:
                browser.switch_to.window(tab)
                return

    def __close_other_tabs(self, browser, handle_to_keep, fallback_url):
        """Close all browser tabs except for the specified handle.

        Parameters:
            browser (WebDriver): The browser instance.
            handle_to_keep (str): The handle of the tab to keep open.
            fallback_url (str): The URL to load if tab restoration fails.
        Returns:
            (bool): True if the tab restoration is successful and the current window handle matches the handle_to_keep, False otherwise.
        """
        try:
            handles_to_close = copy.copy(browser.window_handles)
            for handle_to_close in handles_to_close:
                if handle_to_close != handle_to_keep:
                    browser.switch_to.window(handle_to_close)
                    browser.close()
                    # time.sleep(1)
                if len(browser.window_handles) == 1:
                    break
            browser.switch_to.window(handle_to_keep)
        except Exception as error:
            self.source.logger.exception(f"Browser tab restoration failed, reloading the title page: {error}")
            try:
                # last resort - at least try to reopen the original page
                browser.get(fallback_url)
                return True
            except Exception as error:
                self.source.logger.exception(f"Fallback to the original page failed: {error}")
                return False
        return browser.current_window_handle == handle_to_keep

    def __parse_settings(self):
        """Load the collector settings to instance variables.

        Returns:
            bool: True if the settings were successfully loaded, False otherwise.
        """
        self.auth_username = self.source.param_key_values["AUTH_USERNAME"]
        self.auth_password = self.source.param_key_values["AUTH_PASSWORD"]

        # parse the URL
        web_url = self.source.param_key_values["WEB_URL"]
        if not web_url:
            self.source.logger.error("Web URL is not set. Skipping collection.")
            return False

        if web_url.lower().startswith("file://"):
            file_part = web_url[7:]
            if os.path.isfile(file_part):
                self.interpret_as = "uri"
                self.source.url = "file://" + file_part
            elif os.path.isdir(file_part):
                self.interpret_as = "directory"
                self.source.url = file_part
            else:
                self.source.logger.error(f"Missing file {web_url}")
                return False

        elif re.search(r"^[a-z0-9]+://", web_url.lower()):
            self.interpret_as = "uri"
            self.source.url = web_url
        elif os.path.isfile(web_url):
            self.interpret_as = "uri"
            self.source.url = f"file://{web_url}"
        elif os.path.isdir(web_url):
            self.interpret_as = "directory"
            self.source.url = web_url
        else:
            self.interpret_as = "uri"
            self.source.url = f"https://{web_url}"

        if self.interpret_as == "uri" and self.auth_username and self.auth_password:
            parsed_url = urlparse(self.source.url)
            self.source.url = f"{parsed_url.scheme}://{self.auth_username}:{self.auth_password}@{parsed_url.netloc}{parsed_url.path}"

        # parse other arguments
        self.source.user_agent = self.source.param_key_values["USER_AGENT"]
        self.tor_service = self.source.param_key_values["TOR"]
        self.pagination_limit = read_int_parameter("PAGINATION_LIMIT", 1, self.source)
        self.links_limit = read_int_parameter("LINKS_LIMIT", 0, self.source)
        self.word_limit = read_int_parameter("WORD_LIMIT", 0, self.source)

        self.selectors = {}

        self.selectors["popup_close"] = self.source.param_key_values["POPUP_CLOSE_SELECTOR"]
        self.selectors["next_page"] = self.source.param_key_values["NEXT_BUTTON_SELECTOR"]
        self.selectors["load_more"] = self.source.param_key_values["LOAD_MORE_BUTTON_SELECTOR"]
        self.selectors["single_article_link"] = self.source.param_key_values["SINGLE_ARTICLE_LINK_SELECTOR"]

        self.selectors["title"] = self.source.param_key_values["TITLE_SELECTOR"]
        self.selectors["article_description"] = self.source.param_key_values["ARTICLE_DESCRIPTION_SELECTOR"]
        self.selectors["article_full_text"] = self.source.param_key_values["ARTICLE_FULL_TEXT_SELECTOR"]
        self.selectors["published"] = self.source.param_key_values["PUBLISHED_SELECTOR"]
        self.selectors["author"] = self.source.param_key_values["AUTHOR_SELECTOR"]
        self.selectors["attachment"] = self.source.param_key_values["ATTACHMENT_SELECTOR"]
        self.selectors["additional_id"] = self.source.param_key_values["ADDITIONAL_ID_SELECTOR"]

        self.web_driver_type = self.source.param_key_values["WEBDRIVER"]
        self.client_cert_directory = self.source.param_key_values["CLIENT_CERT_DIR"]

        self.source.last_collected

        # Use get_proxy_handler from BaseCollector
        self.source.proxy = self.source.param_key_values["PROXY_SERVER"]
        self.source.parsed_proxy = self.get_parsed_proxy()

        return True

    def __get_headless_driver_chrome(self):
        """Initialize and return Chrome driver.

        Returns:
            WebDriver: The initialized Chrome driver.
        """
        self.source.logger.debug("Initializing Chrome driver...")

        chrome_driver_executable = os.environ.get("SELENIUM_CHROME_DRIVER_PATH", "/usr/bin/chromedriver")

        chrome_options = ChromeOptions()
        chrome_options.page_load_strategy = "normal"  # .get() returns on document ready
        chrome_options.add_argument("start-maximized")
        chrome_options.add_argument("disable-infobars")
        chrome_options.add_argument("--disable-extensions")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--ignore-certificate-errors")
        chrome_options.add_argument("--incognito")
        if self.source.user_agent:
            chrome_options.add_argument("user-agent=" + self.source.user_agent)
        if self.tor_service.lower() == "yes":
            socks_proxy = "socks5://127.0.0.1:9050"
            chrome_options.add_argument(f"--proxy-server={socks_proxy}")
        elif self.source.parsed_proxy:
            chrome_options.add_argument(f"--proxy-server={self.source.parsed_proxy.geturl()}")

        chrome_service = ChromeService(executable_path=chrome_driver_executable)
        driver = webdriver.Chrome(service=chrome_service, options=chrome_options)
        self.source.logger.debug("Chrome driver initialized.")
        return driver

    def __get_headless_driver_firefox(self):
        """Initialize and return Firefox driver.

        Returns:
            WebDriver: The initialized Firefox driver.
        """
        self.source.logger.debug("Initializing Firefox driver...")

        firefox_driver_executable = os.environ.get("SELENIUM_FIREFOX_DRIVER_PATH", "/usr/local/bin/geckodriver")

        core_url = os.environ.get("TARANIS_NG_CORE_URL", "http://core")
        core_url_host = urlparse(core_url).hostname  # get only the hostname from URL

        firefox_options = FirefoxOptions()
        firefox_options.page_load_strategy = "normal"  # .get() returns on document ready
        firefox_options.add_argument("--headless")
        firefox_options.add_argument("--ignore-certificate-errors")
        firefox_options.add_argument("--incognito")

        if self.source.user_agent:
            firefox_options.add_argument(f"user-agent={self.source.user_agent}")

        if self.tor_service.lower() == "yes":
            firefox_options.set_preference("network.proxy.type", 1)  # manual proxy config
            firefox_options.set_preference("network.proxy.socks", "127.0.0.1")
            firefox_options.set_preference("network.proxy.socks_port", 9050)
            firefox_options.set_preference("network.proxy.no_proxies_on", f"localhost, ::1, 127.0.0.1, {core_url_host}, 127.0.0.0/8")

        elif self.source.parsed_proxy:
            firefox_options.set_preference("network.proxy.type", 1)  # manual proxy config
            firefox_options.set_preference("network.proxy.no_proxies_on", f"localhost, ::1, 127.0.0.1, {core_url_host}, 127.0.0.0/8")
            if self.source.parsed_proxy.scheme in ["http", "https"]:
                firefox_options.set_preference("network.proxy.http", self.source.parsed_proxy.hostname)
                firefox_options.set_preference("network.proxy.http_port", int(self.source.parsed_proxy.port))
                firefox_options.set_preference("network.proxy.ssl", self.source.parsed_proxy.hostname)
                firefox_options.set_preference("network.proxy.ssl_port", int(self.source.parsed_proxy.port))
            elif self.source.parsed_proxy.scheme in ["socks5", "socks4"]:
                firefox_options.set_preference("network.proxy.socks", self.source.parsed_proxy.hostname)
                firefox_options.set_preference("network.proxy.socks_port", int(self.source.parsed_proxy.port))
        else:
            firefox_options.set_preference("network.proxy.type", 0)  # no proxy

        firefox_service = FirefoxService(executable_path=firefox_driver_executable)
        driver = webdriver.Firefox(service=firefox_service, options=firefox_options)

        self.source.logger.debug("Firefox driver initialized.")
        return driver

    def __get_headless_driver(self):
        """Initialize and return a headless browser driver.

        Returns:
            browser: The headless browser driver
        """
        try:
            if self.web_driver_type.lower() == "firefox":
                browser = self.__get_headless_driver_firefox()
            else:
                browser = self.__get_headless_driver_chrome()
            browser.implicitly_wait(15)  # how long to wait for elements when selector doesn't match
            return browser
        except Exception as error:
            self.source.logger.exception(f"Get headless driver failed: {error}")
            return None

    def __dispose_of_headless_driver(self, driver):
        """Destroy the headless browser driver, and its browser.

        Parameters:
            driver: The headless browser driver to be disposed of.
        """
        try:
            driver.quit()
        except Exception as error:
            self.source.self.source.logger.exception(f"Could not quit the headless browser driver: {error}")

    def __run_tor(self):
        """Run The Onion Router service in a subprocess."""
        self.source.logger.info("Initializing TOR")
        subprocess.Popen(["tor"])
        time.sleep(3)

    @ignore_exceptions
    def collect(self):
        """Collect news items from this source (main function)."""
        if not self.__parse_settings():
            return
        self.news_items = []

        if self.tor_service.lower() == "yes":
            self.__run_tor()

        if self.source.parsed_proxy:
            proxy_handler = self.get_proxy_handler()
        else:
            proxy_handler = None
        self.source.opener = urllib.request.build_opener(proxy_handler).open if proxy_handler else urllib.request.urlopen
        url_not_modified = False
        if self.source.last_collected:
            if url_not_modified := not_modified(self.source):
                self.source.logger.info("Will not collect the feed because nothing has changed.")
                return

        if not url_not_modified:
            if self.interpret_as == "uri":
                total_failed_articles = self.__browse_title_page(self.source.url)

            elif self.interpret_as == "directory":
                self.source.logger.info(f"Searching for html files in {self.source.url}")
                for file_name in os.listdir(self.source.url):
                    if file_name.lower().endswith(".html"):
                        html_file = f"file://{self.source.url}/{file_name}"
                        total_failed_articles = self.__browse_title_page(html_file)

            if total_failed_articles > 0:
                self.source.logger.debug(f"{total_failed_articles} article(s) failed")
            self.publish(self.news_items)

    def __browse_title_page(self, index_url):
        """Spawn a browser, download the title page for parsing, call parser.

        Parameters:
            index_url (str): The URL of the title page.
        """
        browser = self.__get_headless_driver()
        if browser is None:
            self.source.logger.error("Error initializing the headless browser")
            return False, "Error initializing the headless browser", 0, 0

        self.source.logger.info(f"Requesting title page: {self.source.url}")
        try:
            browser.get(index_url)
        except Exception as error:
            self.source.logger.exception(f"Obtaining title page failed: {error}")
            self.__dispose_of_headless_driver(browser)
            return 0

        # if there is a popup selector, click on it!
        if self.selectors["popup_close"]:
            popup = None
            try:
                popup = WebDriverWait(browser, 10).until(
                    EC.presence_of_element_located(self.__get_element_locator(self.selectors["popup_close"]))
                )
            except Exception as error:
                self.source.logger.exception(f"Popup find failed: {error}")
            if popup is not None:
                try:
                    popup.click()
                except Exception as error:
                    self.source.logger.exception(f"Popup click failed: {error}")

        # if there is a "load more" selector, click on it!
        page = 1
        while self.selectors["load_more"] and page < self.pagination_limit:
            try:
                load_more = WebDriverWait(browser, 5).until(
                    EC.element_to_be_clickable(self.__get_element_locator(self.selectors["load_more"]))
                )
                # TODO: check for None

                try:
                    action = ActionChains(browser)
                    action.move_to_element(load_more)
                    load_more.click()
                except Exception:
                    browser.execute_script("arguments[0].scrollIntoView(true);", load_more)
                    load_more.click()

                try:
                    WebDriverWait(browser, 5).until(EC.staleness_of(load_more))
                except Exception:
                    pass

            except Exception:
                break
            page += 1

        title_page_handle = browser.current_window_handle
        total_failed_articles = 0
        while True:
            try:
                failed_articles = self.__process_title_page_articles(browser, title_page_handle, index_url)
                total_failed_articles += failed_articles

                # safety cleanup
                if not self.__close_other_tabs(browser, title_page_handle, fallback_url=index_url):
                    self.source.logger.error("Page crawl failed (after-crawl clean up)")
                    break
            except Exception as error:
                self.source.logger.exception(f"Page crawl failed: {error}")
                break

            if page >= self.pagination_limit or not self.selectors["next_page"]:
                if self.pagination_limit > 1:
                    self.source.logger.info("Page limit reached")
                break

            # visit next page of results
            page += 1
            self.source.logger.info("Clicking 'next page'")
            try:
                next_page = self.__find_element_by(browser, self.selectors["next_page"])
                # TODO: check for None
                ActionChains(browser).move_to_element(next_page).click(next_page).perform()
            except Exception:
                self.source.logger.info("This was the last page")
                break

        self.__dispose_of_headless_driver(browser)

        return total_failed_articles

    def __process_title_page_articles(self, browser, title_page_handle, index_url):
        """Parse the title page for articles.

        Parameters:
            browser (WebDriver): The browser instance.
            title_page_handle (str): The handle of the title page tab.
            index_url (str): The URL of the title page.
        Returns:
            failed_articles (int): A number of failed articles.
        """
        failed_articles = 0
        article_items = self.__safe_find_elements_by(browser, self.selectors["single_article_link"])
        if article_items is None:
            self.source.logger.warning("Invalid page or incorrect selector for article items")
            return 1

        index_url_just_before_click = browser.current_url

        # print(browser.page_source, flush=True)
        for count, item in enumerate(article_items, 1):
            # try:
            #     print("H: {0} {1:.200}".format(count, item.get_attribute('outerHTML')), flush=True)
            # except Exception as ex:
            #     pass
            # if first item works but next items have problems - it's because this:
            # https://www.selenium.dev/documentation/webdriver/troubleshooting/errors/#stale-element-reference-exception
            link = item.get_attribute("href")
            try:
                if link:
                    scope = browser
                    self.source.logger.info(f"Visiting article {count}/{len(article_items)}: {link}")
                    click_method = 1  # TODO: some day, make this user-configurable with tri-state enum
                    if click_method == 1:
                        browser.switch_to.new_window("tab")
                        browser.get(link)
                    elif click_method == 2:
                        browser.move_to_element(item)
                        ActionChains(browser).key_down(Keys.CONTROL).click(item).key_up(Keys.CONTROL).perform()
                        self.__wait_for_new_tab(browser, 15, title_page_handle)
                    elif click_method == 3:
                        browser.move_to_element(item)
                        item.send_keys(Keys.CONTROL + Keys.RETURN)
                        self.__wait_for_new_tab(browser, 15, title_page_handle)
                    time.sleep(1)
                else:
                    self.source.logger.info(f"Visiting article {count}/{len(article_items)} on single page")
                    scope = item

            except Exception as error:
                failed_articles += 1
                self.source.logger.exception(f"Failed to get link for article {count}/{len(article_items)}: {error}")
                continue

            try:
                news_item = self.__process_article_page(browser, scope)
                if news_item:
                    news_item.print_news_item(self.source.logger)
                    self.news_items.append(news_item)
                else:
                    failed_articles += 1
                    self.source.logger.warning("Parsing an article failed")
            except Exception as error:
                failed_articles += 1
                self.source.logger.exception(f"Parsing an article failed: {error}")

            if len(browser.window_handles) == 1:
                back_clicks = 1
                while browser.current_url != index_url_just_before_click:
                    browser.back()
                    back_clicks += 1
                    if back_clicks > 3:
                        self.source.logger.warning("Error during page crawl (cannot restore window after crawl)")
            elif not self.__close_other_tabs(browser, title_page_handle, fallback_url=index_url):
                self.source.logger.warning("Error during page crawl (after-crawl clean up)")
                break
            if self.links_limit > 0 and count >= self.links_limit:
                self.source.logger.debug(f"Limit for article links reached ({self.links_limit})")
                break

        return failed_articles

    def __process_article_page(self, browser, scope):
        """Parse a single article.

        Parameters:
            browser (WebDriver): The browser instance.
        Returns:
            news_item (NewsItemData): The parsed news item.
        """
        current_url = browser.current_url

        # self.source.logger.warning(scope.get_attribute("outerHTML"))

        title = self.__find_element_text_by(scope, self.selectors["title"])

        content = self.__find_element_text_by(scope, self.selectors["article_full_text"])
        if self.word_limit > 0:
            content = " ".join(re.compile(r"\s+").split(content)[: self.word_limit])

        if self.selectors["article_description"]:
            review = self.__find_element_text_by(scope, self.selectors["article_description"])
        else:
            review = ""
        if self.word_limit > 0:
            review = " ".join(re.compile(r"\s+").split(review)[: self.word_limit])
        if not review:
            review = content

        title = smart_truncate(title, 200)
        review = smart_truncate(review)

        extracted_date = None
        published_str = self.__find_element_text_by(scope, self.selectors["published"])
        if published_str:
            extracted_date = parse(published_str, fuzzy=True)
        now = datetime.datetime.now()
        if extracted_date:
            published_str = extracted_date.strftime("%d.%m.%Y - %H:%M")
        else:
            published_str = now.strftime("%d.%m.%Y - %H:%M")

        link = current_url

        author = self.__find_element_text_by(scope, self.selectors["author"])

        for_hash = author + title + review
        news_item = NewsItemData(
            uuid.uuid4(),
            hashlib.sha256(for_hash.encode()).hexdigest(),
            title,
            review,
            self.source.url,
            link,
            published_str,
            author,
            now,
            content,
            self.source.id,
            [],
        )

        if self.selectors["additional_id"]:
            value = self.__find_element_text_by(browser, self.selectors["additional_id"])
            if value:
                key = "Additional_ID"
                binary_mime_type = ""
                binary_value = ""
                attribute = NewsItemAttribute(key, value, binary_mime_type, binary_value)
                news_item.attributes.append(attribute)
        return news_item
