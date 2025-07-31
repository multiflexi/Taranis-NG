from lib import config, get_script_argument_parser
from lib.event import Events
from lib.logger import get_logger
from lib.report import get_report_files
from lib.report.report_item import EventsGeneration
from lib.report.vulnerability_report import VulnerabilityReport


def rescan(debug: bool = False, silent: bool = False) -> None:
    """
    This function rescans Sner for new vulnerable hosts with vulnerabilities
    from all old reports located in reports_dir set in config.ini.
    IDEA event is generated only once for every IP, so if the new scan finds
    a vulnerable service in an IP that was already notified, nothing happens.
    """
    logger = get_logger("rescan", debug, silent)
    logger.info("Rescanning has started.")
    for filename, path in get_report_files(config.reports_dir()):
        logger.info("Started rescanning for report %s.", filename)
        report = VulnerabilityReport(path)
        if report.should_generate_events() != EventsGeneration.DISABLED:
            Events(report, logger).send_to_warden(is_rescan=True)
    logger.info("Rescanning has been completed.")


if __name__ == "__main__":
    parser = get_script_argument_parser()
    args = parser.parse_args()
    rescan(debug=bool(args.debug), silent=args.silent)
