# Quick project reference

- Source code: [github.com/SK-CERT/Taranis-NG](https://github.com/SK-CERT/Taranis-NG)
- Docker images: [hub.docker.com/u/skcert](https://hub.docker.com/u/skcert)
- Maintained by: [SK-CERT](https://www.sk-cert.sk)
- Project web page: [taranis.ng](https://taranis.ng)
- Where to file issues (no vulnerability reports please): [GitHub issues page](https://github.com/SK-CERT/Taranis-NG/issues)
- Where to send security issues and vulnerability reports: [incident@nbu.gov.sk](mailto:incident@nbu.gov.sk)

## About Taranis NG

Taranis NG is an OSINT gathering and analysis tool for CSIRT teams and
organisations. It allows osint gathering, analysis and reporting; team-to-team
collaboration; and contains a user portal for simple self asset management.

Taranis crawls various **data sources** such as web sites or tweets to gather
unstructured **news items**. These are processed by analysts to create
structured **report items**, which are used to create **products** such as PDF
files, which are finally **published**.

Taranis supports **team-to-team collaboration**, and includes a light weight
**self service asset management** which automatically links to the advisories
that mention vulnerabilities in the software.

# Deploying Taranis NG with docker-compose

Taranis NG supports deployment in Docker containers. [The docker/ folder on
GitHub repository](https://github.com/SK-CERT/Taranis-NG/tree/main/docker)
contains a sample
[docker-compose.yml](https://raw.githubusercontent.com/SK-CERT/Taranis-NG/main/docker/docker-compose.yml)
file which runs the whole application in one stack.

The same folder also contains additional support files for the creation of the
Docker containers. These include start and pre-start scripts, the application
entrypoint, and the [gunicorn](https://gunicorn.org/) configuration file.

## Prerequisites

- [Docker](https://docs.docker.com/engine/install/)
- [docker-compose](https://docs.docker.com/compose/install/) >= 1.27.0 (In July 2023, Compose V1 has been deprecated)

or

- [Compose V2](https://docs.docker.com/compose/migrate/), which is part of standard Docker Engine installation
- (Optional) [Vim](https://www.vim.org/) or other text editor - for configuration and development

Please note it is important to use the abovementioned version of
`docker-compose` or newer, otherwise the build and deploy will fail.

## Quickly build and run Taranis NG using `docker-compose` or `docker compose`

_First_, you need to clone the source code repository:

```bash
git clone https://github.com/SK-CERT/Taranis-NG.git
cd Taranis-NG
```

_Then_, remove `.example` extension from file `docker/.env.example` and files in `docker/secrets`. Use your favorite text editor and change default passwords. Taranis NG uses [Docker secrets](https://docs.docker.com/compose/use-secrets/) to store sensitive data. (Saving passwords in variables defined in `docker/.env` is not advised and you will need to modify Docker compose YAML files to make it work correctly.

```bash
vim docker/.env
```

*_Optionally:_ you may modify other settings in the `docker/.env` and `docker/docker-compose.yml` files to your liking.  More information on container configuration can be found [here](#configuration).*

_Finally_, either deploy the ready-made images from Docker hub with:

```bash
docker-compose -f docker/docker-compose.yml pull
docker-compose -f docker/docker-compose.yml up --no-build
```
or
```bash
docker compose -f docker/docker-compose.yml pull
docker compose -f docker/docker-compose.yml up --no-build
```

or, alternatively, build and run the containers with:

```bash
TARANIS_NG_TAG=build docker-compose -f docker/docker-compose.yml build --pull
TARANIS_NG_TAG=build docker-compose -f docker/docker-compose.yml up
```
or
```bash
TARANIS_NG_TAG=build docker compose -f docker/docker-compose.yml build --pull
TARANIS_NG_TAG=build docker compose -f docker/docker-compose.yml up
```
(`--pull` updates the base images)

**Voila, Taranis NG is up and running. Visit your instance by navigating to
[https://localhost:4443/](https://localhost:4443/) using your web browser**.

Your Taranis NG instance now needs to be configured.  Continue
[here](https://github.com/SK-CERT/Taranis-NG#connecting-to-collectors-presenters-and-publishers).

**The default credentials are `user` / `user` and `admin` / `admin`.**


## Advanced build methods

### Individually build the containers

To build the Docker images individually, you need to clone the source code repository.

```bash
git clone https://github.com/SK-CERT/Taranis-NG.git
```

Afterwards go to the cloned repository and launch the `docker build` command for the specific container image, like so:

```bash
cd Taranis-NG
docker build -t taranis-ng-bots . -f ./docker/Dockerfile.bots
docker build -t taranis-ng-collectors . -f ./docker/Dockerfile.collectors
docker build -t taranis-ng-core . -f ./docker/Dockerfile.core
docker build -t taranis-ng-gui . -f ./docker/Dockerfile.gui
docker build -t taranis-ng-presenters . -f ./docker/Dockerfile.presenters
docker build -t taranis-ng-publishers . -f ./docker/Dockerfile.publishers
```

There are several Dockerfiles and each of them builds a different component of the system. These Dockerfiles exist:

- [Dockerfile.bots](Dockerfile.bots)
- [Dockerfile.collectors](Dockerfile.collectors)
- [Dockerfile.core](Dockerfile.core)
- [Dockerfile.gui](Dockerfile.gui)
- [Dockerfile.presenters](Dockerfile.presenters)
- [Dockerfile.publishers](Dockerfile.publishers)

# Configuration

## Container variables

### `redis`
Any configuration options are available at [https://hub.docker.com/_/redis](https://hub.docker.com/_/redis).

### `database`
Any configuration options are available at [https://hub.docker.com/_/postgres](https://hub.docker.com/_/postgres).

### `core`

| Environment variable        | Description | Example |
|-----------------------------|-------------|----------|
| `REDIS_URL`                 | Redis database URL. Used for SSE events. | `redis://redis` |
| `DB_URL`                    | PostgreSQL database URL. | `127.0.0.1` |
| `DB_DATABASE`               | PostgreSQL database name. | `taranis-ng` |
| `DB_USER`                   | PostgreSQL database user. | `taranis-ng` |
| `DB_POOL_SIZE`              | SQLAlchemy QueuePool number of active connections to the database. | `100` |
| `DB_POOL_RECYCLE`           | SQLAlchemy QueuePool maximum connection age. | `300` |
| `DB_POOL_TIMEOUT`           | SQLAlchemy QueuePool connection timeout. | `5` |
| `OPENID_LOGOUT_URL`         | Keycloak logout URL. | `https://example.com/realms/master/protocol/openid-connect/logout` |
| `WORKERS_PER_CORE`          | Number of gunicorn worker threads to spawn per CPU core. | `4` |

| Secrets file                | Description | Example |
|-----------------------------|-------------|----------|
| `postgres_password`         | PostgreSQL database password. | `supersecret` |
| `jwt_secret_key`            | JWT token secret key. | `supersecret` |


Taranis NG can use [connection pooling](https://docs.sqlalchemy.org/en/14/core/pooling.html) to maintain multiple active connections to the database server. Connection pooling is required when your deployment serves hundreds of customers from one instance. To enable connection pooling, set the `DB_POOL_SIZE`, `DB_POOL_RECYCLE`, and `DB_POOL_TIMEOUT` environment variables.

### `bots`, `collectors`, `presenters`, `publishers`

| Environment variable        | Description | Example |
|-----------------------------|-------------|----------|
| `TARANIS_NG_CORE_URL`       | URL of the Taranis NG core API. | `http://127.0.0.1:8080/api/v1` |
| `WORKERS_PER_CORE`          | Number of gunicorn worker threads to spawn per CPU core. | `4` |

| Secrets file                | Description | Example |
|-----------------------------|-------------|----------|
| `api_key`            | Shared API key. | `cuBG/4H9lGTeo47F9X6DUg` |


### `gui`

| Environment variable          | Description | Example |
|-------------------------------|-------------|----------|
| `VUE_APP_TARANIS_NG_CORE_API` | URL of the Taranis NG core API. | `http://127.0.0.1:8080/api/v1` |
| `VUE_APP_TARANIS_NG_CORE_SSE` | URL of the Taranis NG SSE endpoint. | `http://127.0.0.1:8080/sse` |
| `VUE_APP_TARANIS_NG_URL`      | URL of the Taranis NG frontend. | `http://127.0.0.1` |
| `VUE_APP_TARANIS_NG_LOCALE`   | Application locale. | `en` |
| `NGINX_WORKERS`               | Number of NginX worker threads to spawn. | `4` |
| `NGINX_CONNECTIONS`           | Maximum number of allowed connections per one worker thread. | `16` |

## Note
If you see in logs this message:
```
redis-1       | 1:C 07 Jan 2025 08:35:21.560 # WARNING Memory overcommit must be enabled! Without it, a background save or replication may fail under low memory condition. Being disabled, it can also cause failures without low memory condition, see https://github.com/jemalloc/jemalloc/issues/1328. To fix this issue add 'vm.overcommit_memory = 1' to /etc/sysctl.conf and then reboot or run the command 'sysctl vm.overcommit_memory=1' for this to take effect.
```
Run following in your host OS:
```bash
sysctl -w vm.overcommit_memory=1
```

## Management script how-to

Taranis NG core container comes with a simple management script that may be used to set up and configure the instance without manual interaction with the database.

To run the management script, launch a shell inside of the docker container for the core component with this command:

```bash
docker exec -it [CONTAINER] python manage.py [COMMAND] [PARAMETERS]
```

Currently, you may manage the following:

| Command     | Description | Parameters |
|-------------|-------------|------------|
| `account`     | (WIP) List, create, edit and delete user accounts. | `--list`, `-l` : list all user accounts<br /> `--create`, `-c` : create a new user account<br /> `--edit`, `-e` : edit an existing user account<br /> `--delete`, `-d` : delete a user account<br /> `--username` : specify the username<br /> `--name` : specify the user's name<br /> `--password` : specify the user's password<br /> `--roles` : specify a list of roles, divided by a comma (`,`), that the user belongs to |
| `role`     | (WIP) List, create, edit and delete user roles. | `--list`, `-l` : list all roles<br /> `--filter`, `-f` : filter roles by their name or description<br /> `--create`, `-c` : create a new role<br /> `--edit`, `-e` : edit an existing role<br /> `--delete`, `-d` : delete a role<br /> `--id` : specify the role id (in combination with `--edit` or `--delete`)<br /> `--name` : specify the role name<br /> `--description` : specify the role description (default is `""`)<br /> `--permissions` : specify a list of permissions, divided with a comma (`,`), that the role would allow |
| `collector, bot`     | (WIP) List, create, edit, delete and update nodes. | `--list`, `-l` : list all nodes<br /> `--create`, `-c` : create a new node<br /> `--edit`, `-e` : edit an existing node<br /> `--delete`, `-d` : delete a node<br /> `--update`, `-u` : re-initialize node<br /> `--all`, `-a` : update all nodes (in combination with `--update`)<br /> `--show-api-key` : show API key in plaintext (in combination with `--list`)<br /> `--id` : specify the node id (in combination with `--edit`, `--delete` or `--update`)<br /> `--name` : specify the node name<br /> `--description` : specify the collector description (default is `""`)<br /> `--api-url` : specify the collector node API url<br /> `--api-key` : specify the collector node API key |
| `dictionary`     | Update CPE, CWE and CVE dictionaries. | `--upload-cpe` : upload the CPE dictionary (expected on STDIN in XML format) to the path indicated by `CPE_UPDATE_FILE` environment variable, and update the database from that file.<br /> `--upload-cve` : upload the CVE dictionary (expected on STDIN in XML format) to the path indicated by `CVE_UPDATE_FILE` environment variable, and update the database from that file.<br /> `--upload-cwe` : upload the CWE dictionary (expected on STDIN in XML format) to the path indicated by `CWE_UPDATE_FILE` environment variable, and update the database from that file. |
| `apikey`     | List, create and delete apikeys. | `--list`, `-l` : list all apikeys<br /> `--create`, `-c` : create a new apikey<br /> `--delete`, `-d` : delete a apikey<br /> `--name` : specify the apikey name<br /> `--user` : specify the user's name<br /> `--expires` : specify the apikey expiration datetime |


#### Example usage

##### Create a new role with a set of permissions

```bash
manage.py role \
    --create \
    --name "Custom role 1" \
    --description "Custom role with analysis and assessment access" \
    --permissions "ANALYZE_ACCESS, ANALYZE_CREATE, ANALYZE_UPDATE, \
    ANALYZE_DELETE, ASSESS_ACCESS, ASSESS_CREATE, ASSESS_UPDATE, \
    ASSESS_DELETE, MY_ASSETS_ACCESS, MY_ASSETS_CREATE"
```

Command output:

```
Role 'Custom role 1' with id 3 created.
```

##### Role filter

```bash
manage.py role \
    --list \
    --filter "Custom role 1"
```

Command output:

```
Id: 3
	Name: Custom role 1
	Description: Custom role with analysis and assessment access
	Permissions: ['ANALYZE_ACCESS', 'ANALYZE_CREATE', 'ANALYZE_UPDATE', 'ANALYZE_DELETE', 'ASSESS_ACCESS', 'ASSESS_CREATE', 'ASSESS_UPDATE', 'ASSESS_DELETE', 'MY_ASSETS_ACCESS', 'MY_ASSETS_CREATE']
```

##### Create a new [collector, bot] node

```bash
manage.py [collector, bot] \
    --create \
    --name "Docker [collector, bot]" \
    --description "A simple [collector, bot] hosted in a Docker container" \
    --api-url "http://[collectors, bots]" \
    --api-key "supersecret"
```

Command output:

```
[Collector, Bot] node 'Docker [collector, bot]' with id 1 created.
```

##### Re-initialize a [collector, bot] node

```bash
manage.py [collector, bot] \
    --update \
    --name "Docker"
```

Command output:

```
[Collector, Bot] node 1 updated.
[Collector, Bot] node 2 updated.
Unable to update [collector, bot] node 3.
    Response: [401] ""
```

##### Create a new user account

```bash
manage.py account \
    --create \
    --name "John Doe" \
    --username "test_user" \
    --password "supersecret" \
    --roles 3
```

Command output:

```
User 'test_user' created.
```

##### Upload a CPE dictionary

```bash
zcat official-cpe-dictionary_v2.3.xml.gz | manage.py dictionary --upload-cpe
```

Command output:

```
Processed CPE items: 1000
Processed CPE items: 2000
...
...
Processed CPE items: 789000
Processed CPE items: 789704
Dictionary was uploaded.
```

##### Create new ApiKey

```bash
manage.py apikey \
    --create \
    --name "My ApiKey"
```

##### Create a new API key for a user with an expiration date

```bash
manage.py apikey \
    --create \
    --name "My ApiKey" \
    --user "test_user" \
    --expire "2022-12-31 16:55"
```

Command output:

```
ApiKey 'My ApiKey' with id 3 created.
```
