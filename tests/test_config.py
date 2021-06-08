"""Tests for config."""
import tempfile
from pathlib import Path
import pytest

from typing import Dict
from yaml import Loader, dump, load

from rpkiclientweb.rpki_client import RpkiClient
from rpkiclientweb.config import Configuration
from rpkiclientweb.util import load_yaml


def load_sample_conf() -> Dict:
    path = Path(__file__).parent / "sample.yml"

    return load_yaml(path.open('r'))


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
