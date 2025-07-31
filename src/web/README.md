# Vulnerability Assessment to Asset Management integration (VA2AM)
- finds vulnerable versions of SW in Sner based on reports from Taranis
- generates IDEA messages that can be sent to Warden
- includes a nice web view of the reports from Taranis (RSS included)


## Code structure
- `lib/event` – classes for generating IDEA messages and sending them to Warden
- `lib/report` – classes for working with Taranis reports
- `lib/test` – unit and integration test (for all modules except version_parser)
- `lib/version_parser` – functions for working with version specifications
- `lib/web` – Flask application consisting of endpoints and templates
- `lib/__init__.py` – common functions (for sending emails, loading data from conf/config.ini...)

There is also a subdirectory `lib/warden` (Warden client), which is only a library used by
`lib/event`. It is not a dependency managed by poetry, because the Warden Client is not on PyPy.

You can also use `lib/playground.py` to test something from this project.


## Development
When you want to start developing this project, you should:
1. install [Poetry](https://python-poetry.org/docs/#installation)
2. install all dependencies using `make deps-all`
3. create a basic directory structure using `make dirs`

You can then start programming.
- Use `make web-launch` to run the web interface in debug mode.
- Use `make process-incoming` to process all reports located in the incoming directory.
- Use `make test` to run all unit tests.
- Use `make lint` to check all Python code with ruff, pylint and mypy, and all Jinja templates with djlint.

When you are done, do not forget to commit and push the code. Make sure all tests pass
and linters do not show any problems before pushing the code.


## Deployment
If you want to install this tool on a server, you should create the virtual environment
and install all necessary dependencies as described in the 'Development' part of this README
(but you don't need `make deps-all`, as `make deps` should be enough).
Then you should setup the web using Apache with mod_wsgi. If you put this project in `/opt/va2am`
directory, you can use the WSGI script located in `lib/web/app.wsgi`. Otherwise, you should
change the paths in that script.

If you want to process new reports periodically, it is recommended to setup a cron that
will call the `process-incoming.sh` script periodically. The same applies for rescanning,
where you can use the `rescan.sh` script.

If you want to download the new version of this tool, you can modify the `make upgrade`
command according to your needs. This tool does not have any packages and the best
way to deploy it is simply by using git.

### Registering a Warden client
If you also want to register a Warden client to send events to Warden, you should
follow the procedure described on the Warden website (https://warden.cesnet.cz/en/participation).

Then you can use the `warden_apply.sh` script (in conf subdirectory) to get the
certificate. You should also change the values in the file `conf/warden_client.cfg`
accordingly.


## Configuration
You can find the configuration file in the `conf` subdirectory.

These are the main configuration parameters:
- *production*: True/False. If False, no e-mails will be sent and all IDEA Messages will have Test category.
- *send_to_warden*: True/False. If False, no events are sent to Warden.
- *mail_addresses_info*: mail addresses of the people that should receive VA2AM info emails (about new published reports, events sent to Mentat...)
- *mail_addresses_admins*: mail addresses of the VA2AM admins (they will receive emails in case of errors etc.)
- *sner_apikey*: API key for access to SNER
- *special_os*: list of special operating systems such as debian

These parameters can be set for the directory paths:
- *reports_dir*: the path to the directory where processed reports will be stored
- *incoming_dir*: the path to the directory with incoming reports from Taranis
- *archive_dir*: the path to the archive directory
- *log_dir*: the path to the directory with logs (from process_incoming and rescan scripts)

These parameters can be set for the web:
- *max_reports_homepage*: maximum number of reports that can be displayed on one page on the homepage
- *max_reports_rss*: maximum number of reports to be displayed in the RSS feed
- *slovak_authors*: names of the authors that write reports in Slovak language (for them, the reports will be displayed in Slovak, and for others, reports will be in Czech)
- *hostname*: hostname of the server

These parameters can be set for the feedback form:
- *question1*: wording of the first (mandatory) question
- *question2*: wording of the second (mandatory) question
- *question3*: wording of the third (optional) question
- *comment*: wording of the free comment field
