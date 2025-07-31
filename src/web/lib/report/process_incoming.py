from pathlib import Path
from shutil import copy2

from lib import (
    config,
    get_script_argument_parser,
    handle_exception,
    send_mail,
)
from lib.event import Events
from lib.logger import get_logger
from lib.report import get_report_files
from lib.report.report_item import EventsGeneration
from lib.report.vulnerability_report import VulnerabilityReport


def process_incoming(debug: bool = False, silent: bool = False) -> None:
    """
    This function processes incoming reports from Taranis.
    1. Checks if it is a valid report item, and logs it if it is not
       The file will be moved to archive directory in both cases
       to successful or unsuccessful subdirectory.
    2. Generates IDEA messages using Events class and send them to Warden.
    3. Renames the file to {id}.json and moves it to the given directory for web view.

    If report publication fails, an email is sent to all info addresses.
    """
    logger = get_logger("incoming", debug, silent)
    reports_dir = config.reports_dir()
    archive_dir = config.archive_dir()

    successful, unsuccessful = 0, 0
    for filename, path in get_report_files(config.incoming_dir()):
        try:
            report = VulnerabilityReport(path)
            report.validate_versions(logger)

            copy_file_name = f"ID_{report.get_id()}--{filename.split('.')[0]}.json"
            copy2(
                path,
                config.archive_dir() / "successful" / copy_file_name,
            )
            Path.rename(path, reports_dir / f"{report.get_id()}.json")

            logger.info("Successfully parsed and saved a report with ID %s.", report.get_id())
            send_mail(
                f"Report '{report.get_title()}' with ID {report.get_id()} "
                f"is now published on the VA2AM website.\n\nYou can look at it "
                f"at {config.website_hostname()}/reports/{report.get_id()}.",
                f"[VA2AM] {report.get_title()} (ID {report.get_id()})",
                recipients=config.info_mail(),
                logger=logger,
            )
        except Exception:  # pylint: disable=locally-disabled, broad-exception-caught
            unsuccessful += 1
            Path.rename(path, archive_dir / "unsuccessful" / filename)
            handle_exception(
                f"Report {filename} could not be parsed.",
                "[VA2AM] New report publication failed",
                logger,
            )
        else:
            successful += 1
            if report.should_generate_events() != EventsGeneration.DISABLED:
                Events(report, logger).send_to_warden()

    logger.debug(
        "Processing the incoming reports done. Processed %d " "reports successfully and %d reports unsuccessfully.",
        successful,
        unsuccessful,
    )


if __name__ == "__main__":
    parser = get_script_argument_parser()
    args = parser.parse_args()
    process_incoming(debug=bool(args.debug), silent=args.silent)
