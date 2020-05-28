This repository contains a utility that exposes the results of [rpki-client](https://www.rpki-client.org/)
via a HTTP API.

Usage
=====

Create a `config.yml` file and run the utility with `python -m rpki_client -v -c [config_file_name]`.
Note that the default config only contains the RIPE NCC tal for ease of use during testing

Or run a docker container:
```
# edit ./config.yml
docker run \
  -p 8888:8888 \
  --detach \
  --name rpki-client-web \
  -v `pwd`/config.yml:/opt/rpkiclientweb/config.yml \
  tiesdekock/rpki-client-web
```

Endpoints
=========

```
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
