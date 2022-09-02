This repository contains a utility that exposes the results of [rpki-client](https://www.rpki-client.org/)
via a HTTP API.

Usage
=====

Create a `config.yml` file and run the utility with `python -m rpkiclientweb -v -c [config_file_name]`.
Note that the default config only contains the RIPE NCC tal for ease of use during testing

Or run a docker container:
```
# edit ./config.yml and put in ./config/config.yml
docker run \
  -p 8888:8888 \
  --detach \
  --name rpki-client-web \
  -v ./config:/config \
  ghcr.io/ties/rpki-client-web:dev
```

Optionally you can add `--tmpfs [configured cache_dir]` to save on IO
(recommended when running at a cloud provided with very limited IOPS).

Endpoints
=========

```
/config             - output the current config
/result             - exit code, stdout, and stderr of last rpki-client run
/metrics            - prometheus metrics
/objects/validated  - validated RPKI objects
```

Changes
=======

dev:
**Includes rpki-client 7.9 in the container**

  * aiohttp 3.8.1, prometheus-async 22.2.0
  * track rrdp serial decrease in metric
  * track repository not modified message
  * track rrdp bad message digest error (mostly caused by incorrect state on
    disk)
  * improve output of rsync_timeout
  * **Behavioural change**: use rpki-client `-s` timeout set to the kill timeout.
  * Track more messages for errors during manifest parsing
  * Track assertion errors and other warnings from rpki-client

2022-04-13 0.10.0:
**Includes rpki-client 7.8 in the container, raising the object size limit**

  * Add `rrdp_parse_aborted` and `rrdp_parse_error_file_too_big` to `rpkiclient_fetch_status_total` metric.
    Fixes #48.
  * Update interval to 1200s in the sample config
  * Add new `.metadata` keys from the json, and use buildtime in a separate metric.
  * Return HTTP 503 Service Unavailable when JSON output does not exist.
  * Include console output in web index page
  * "fallback to cache" is included in the metrics
  * "no valid mft available" warning is included in the metrics
  * "missing SIA" warning is included in the metrics.
  * Track "tls certificate verification failed" errors for RRDP

2021-11-14 0.9.1:

**Includes rpki-client 7.5 in the container**

  * Fedora 35 as base image

2021-10-12 0.9.0:

**Includes rpki-client 7.3 in the container**

  * Log rpki-client output line-by line
  * Add a metric for router certificates
  * Improve message when rejecting a metric update to prevent confusion.

2021-08-24 0.8.1:

**Includes rpki-client 7.2 in the container**

  * Add a metric for the number of VRPs per trust anchor locator.
  * Rename `rpkiclient_fetch_error` metric to `rpkiclient_fetch_status` since it
    includes non-error statuses (fixes #26).
  * aiohttp >= 3.7.4.
  * more resilient rejection of intertwined lines.
  * Only build `:development` container for dev branch

2021-06-24 v0.8.0:
  * rpki-client 7 support
  * rrdp, rsync fallback, rsync error metrics
  * container based on tini
  * Update readme to refer to `rpkiclientweb` module instead of `rpki_client`.
  * Patches to make it run on Python 3.7.x

2021-03-05 v0.7.2:
  * Ignore lines with intertwined output, prevents `rpki-client: pulling ...`
    (and similar) from being parsed as URLs.
  * Updated s6 version

2021-02-08 v0.7.1:
  * Hotfix: Exception on path being hit.

2021-02-08 v0.7.0:
  * Track vanished files and directory count.
  * Track the number of no longer referenced repositories.
  * Track the number of revoked certificate lines.

2021-01-21 v0.6.2:
  * Start webserver/prometheus endpoint immediately when waiting for delay

2021-01-06 v0.6.1:
  * Start with a random delay of up to 600s when non-interactive

2021-01-06 v0.6.0:
  * Start with a random delay of up to 300s when non-interactive

2020-12-19 v0.5.1:
  * Fix: Crash when files removed line is missing due to unsuccessful run.

2020-12-17 v0.5.0:
  * Track overclaiming ROAs
  * Track number of deleted files

2020-12-1 v0.4.6:
  * Track repositories pulled from

2020-11-30 v0.4.5:
  * Set missing labels to 0.

2020-11-26 v0.4.4:
  * Fix label removal bug --- old labels should now be removed.

2020-11-26 v0.4.3:
  * Parse 'bad message digest' warnings.

2020-11-25 v0.4.2:
  * Attempt to remove non-existent labels in a different way.

2020-11-25 v0.4.1:
  * Change container so command can be picked up from command line, e.g. `docker run --rm [image name] s6-setuidgid daemon python3 -m rpkiclientweb -c /config/config.yml -v -v`

2020-11-24 v0.4:
  * Parse `rpki-client` output for warnings and add these as metrics.

2020-09-04 v0.3.1:

  * Add index http endpoint.
  * Fix the `/result` endpoint.

2020-07-27 v0.3.0:

  * Metric names start with `rpkiclient` instead of `rpki_client`.

Installation
============

For now, clone the repository and run `pipenv install` to install the dependencies.
Afterwards you can run the project if you are in the correct python environment
or by using pipenv (`pipenv run python -m rpkiclientweb -v -c ./config.yml`).

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

#### Important metrics
  * `rpkiclient_removed_unreferenced`: The number of repositories that are no
    longer referenced from a trust anchor.
  * `rpkiclient_warnings{hostname="<repo hostname",type="<type of error>"}`:
    Tracks specific types of error per repository when they happen. For a healthy
    repository, no warnings should exist.
  * `rpki_objects{type="<type>"}`: Object count by type, both regular ("number of ROAs") and extraordinary ("number of rejected certificates") metrics.
