"""Tests for config."""
import tempfile
from pathlib import Path
from typing import Dict

import pytest
from yaml import Loader, dump, load

from rpkiclientweb.config import Configuration
from rpkiclientweb.rpki_client import RpkiClient
from rpkiclientweb.util import json_dumps, load_yaml


def load_sample_conf() -> Dict:
    path = Path(__file__).parent / "sample.yml"

    return load_yaml(path.open("r"))


def test_config_checks_cache_dir():
    conf = load_sample_conf()

    with tempfile.TemporaryDirectory() as dir_name:
        conf["output_dir"] = dir_name
        conf["cache_dir"] = ".well-known-missing"

        with pytest.raises(ValueError):
            Configuration(conf)


def test_config_checks_output_dir():
    conf = load_sample_conf()

    with tempfile.TemporaryDirectory() as dir_name:
        conf["cache_dir"] = dir_name
        conf["output_dir"] = ".well-known-missing"

        with pytest.raises(ValueError):
            Configuration(conf)


def test_config_accepts_when_both_exist():
    conf = load_sample_conf()

    with tempfile.TemporaryDirectory() as dir_name:
        with tempfile.TemporaryDirectory() as another_dir_name:
            conf["cache_dir"] = dir_name
            conf["output_dir"] = another_dir_name

            client = RpkiClient(Configuration(conf))
            client.args


def test_requires_rpki_client_present():
    conf = load_sample_conf()

    conf["rpki_client"] = "/bin/bash"

    client = RpkiClient(Configuration(conf))
    client.args

    with pytest.raises(ValueError):
        conf["rpki_client"] = "/.well-known-missing"
        client = RpkiClient(Configuration(conf))
        client.args


def test_config_adds_defaults():
    config_content = load_sample_conf()
    conf = Configuration(config_content)

    # Attribute that is not in the config, but has a default
    assert conf.deadline == -1


def test_json_serialize():
    config_content = load_sample_conf()
    conf = Configuration(config_content)

    json = json_dumps(conf)
    assert "deadline" in json
