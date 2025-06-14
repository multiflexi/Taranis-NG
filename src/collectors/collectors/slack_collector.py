"""Module for Slack collector."""

import datetime
import hashlib
import uuid
import time
import socket

from slack import WebClient

from .base_collector import BaseCollector
from shared.common import ignore_exceptions, smart_truncate
from shared.config_collector import ConfigCollector
from shared.schema.news_item import NewsItemData


# the slackclient project is in maintenance mode now, "slack_sdk" is successor: https://pypi.org/project/slack-sdk/
class SlackCollector(BaseCollector):
    """Collector for gathering data from Slack.

    Attributes:
        type (str): Type of the collector.
        name (str): Name of the collector.
        description (str): Description of the collector.
        parameters (list): List of parameters required for the collector.
    Methods:
        collect(): Collects data from Slack source.
    """

    type = "SLACK_COLLECTOR"
    config = ConfigCollector().get_config_by_type(type)
    name = config.name
    description = config.description
    parameters = config.parameters

    @ignore_exceptions
    def collect(self):
        """Collect data from Slack source."""
        news_items = []
        proxy_server = self.source.param_key_values["PROXY_SERVER"]

        if proxy_server:

            server = "https://slack.com"
            port = 443

            server_proxy = proxy_server.rsplit(":", 1)[0]
            server_proxy_port = proxy_server.rsplit(":", 1)[-1]

            try:
                proxy = (str(server_proxy), int(server_proxy_port))
                connection = f"CONNECT {server}:{port} HTTP/1.0\r\nConnection: close\r\n\r\n"

                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(proxy)
                s.send(str.encode(connection))
                s.recv(4096)
            except Exception:
                self.source.logger.exception("Proxy connection failed")

        ids = self.source.param_key_values["WORKSPACE_CHANNELS_ID"].replace(" ", "")
        channels_list = ids.split(",")

        slack_client = WebClient(self.source.param_key_values["SLACK_API_TOKEN"])

        try:
            for channel_id in channels_list:
                self.source.logger.info(f"Channel: {channel_id}")
                channel_info = slack_client.conversations_info(channel=channel_id)
                channel_name = channel_info["channel"]["name"]

                # in future we can use parameter "oldest" - Only messages after this Unix timestamp will be included in results
                data = slack_client.conversations_history(channel=channel_id, limit=30)
                for count, message in enumerate(data["messages"], 1):
                    self.source.logger.debug(f"Message: {count}")
                    published = time.ctime(float(message["ts"]))
                    content = message["text"]
                    review = smart_truncate(content)

                    user_id = message["user"]
                    user_name = slack_client.users_profile_get(user=user_id)
                    author = user_name["profile"]["real_name"]

                    team_id = message.get("team", "")
                    if team_id:
                        team_info = slack_client.team_info(team=team_id)
                        team_name = team_info["team"]["name"]
                    else:
                        team_name = ""

                    title = f"Slack post from channel {channel_name}"
                    if team_name:
                        title += f" ({team_name})"
                    link = ""
                    url = ""
                    for_hash = user_id + channel_id + content

                    self.source.logger.debug(f"... Title    : {title}")
                    self.source.logger.debug(f"... Content  : {content.replace('\r', '').replace('\n', ' ').strip()[:100]}")
                    self.source.logger.debug(f"... Author   : {author}")
                    self.source.logger.debug(f"... Published: {published}")

                    news_item = NewsItemData(
                        uuid.uuid4(),
                        hashlib.sha256(for_hash.encode()).hexdigest(),
                        title,
                        review,
                        url,
                        link,
                        published,
                        author,
                        datetime.datetime.now(),
                        content,
                        self.source.id,
                        [],
                    )
                    news_items.append(news_item)

            self.publish(news_items)

        except Exception as error:
            self.source.logger.exception(f"Collection failed: {error}")
