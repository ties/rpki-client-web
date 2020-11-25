This repository contains a utility that exposes the results of [rpki-client](https://www.rpki-client.org/)
via a HTTP API.

Changes
=======

2020-11-25 v0.4.1:
  * Change container so command can be picked up from command line, e.g. `docker run --rm [image name] s6-setuidgid daemon python3 -m rpkiclientweb -c /config/config.yml -v -v`

2020-11-24 v0.4:
  * Parse `rpki-client` output for warnings and add these as metrics.

2020-09-04 v0.3.1:

  * Add index http endpoint.
  * Fix the `/result` endpoint.

2020-07-27 v0.3.0:

  * Metric names start with `rpkiclient` instead of `rpki_client`.

Usage
=====

Create a `config.yml` file and run the utility with `python -m rpki_client -v -c [config_file_name]`.
Note that the default config only contains the RIPE NCC tal for ease of use during testing

Or run a docker container:
```
# edit ./config.yml and put in ./config/config.yml
docker run \
  -p 8888:8888 \
  --detach \
  --name rpki-client-web \
  -v ./config:/config \
  tiesdekock/rpki-client-web
```

Endpoints
=========

```
/config             - output the current config
/result             - exit code, stdout, and stderr of last rpki-client run
/metrics            - prometheus metrics
/validated/objects  - validated RPKI objects
```

Installation
============

For now, clone the repository and run `pipenv install` to install the dependencies.
Afterwards you can run the project if you are in the correct python environment
or by using pipenv (`pipenv run python -m rpki_client -v -c ./config.yml`).

Fedora packages needed:
  * rpki-client
  * python-devel
  * git
  * python-pipenv
  * gcc

Metrics
=======

There is a prometheus endpoint available on `/metrics`. The easiest way to check
that `rpki-client` exited successfully is to monitor the exit codes. When the
process is killed due to a timeout the exit code is -9. You could create an
alert for either the existence of non-zero exit codes or for the recent
occurrence of one.

```
# HELP rpkiclient_update_total Number of rpki-client updates
# TYPE rpkiclient_update_total counter
rpkiclient_update_total{returncode="-9"} 1.0
# HELP rpkiclient_update_created Number of rpki-client updates
# TYPE rpkiclient_update_created gauge
rpkiclient_update_created{returncode="-9"} 1.5911933945483255e+09
```
