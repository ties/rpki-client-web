import os.path
import tempfile
import pytest

from typing import Dict
from yaml import Loader, dump, load

from rpkiclientweb.rpki_client import RpkiClient


def load_sample_conf() -> Dict:
    path = os.path.join(os.path.dirname(__file__), "sample.yml")

    conf = load(open(path, "r"), Loader=Loader)
    conf.pop("interval")
    conf.pop("host")
    conf.pop("port")

    return conf


def test_config_checks_cache_dir():
    conf = load_sample_conf()

    with tempfile.TemporaryDirectory() as dir_name:
        conf["output_dir"] = dir_name
        conf["cache_dir"] = ".well-known-missing"

        with pytest.raises(ValueError):
            client = RpkiClient(**conf)
            client.args

def test_config_checks_output_dir():
    conf = load_sample_conf()

    with tempfile.TemporaryDirectory() as dir_name:
        conf["cache_dir"] = dir_name
        conf["output_dir"] = ".well-known-missing"

        with pytest.raises(ValueError):
            client = RpkiClient(**conf)
            client.args

def test_config_accepts_when_both_exist():
    conf = load_sample_conf()

    with tempfile.TemporaryDirectory() as dir_name:
        with tempfile.TemporaryDirectory() as another_dir_name:
            conf["cache_dir"] = dir_name
            conf["output_dir"] = another_dir_name

            client = RpkiClient(**conf)
            client.args

def test_requires_rpki_client_present():
    conf = load_sample_conf()

    conf["rpki_client"] = "/bin/bash"

    client = RpkiClient(**conf)
    client.args

    with pytest.raises(ValueError):
        conf["rpki_client"] = "/.well-known-missing"
        client = RpkiClient(**conf)
        client.args
