import os.path
import tempfile
from typing import Dict
from unittest import TestCase

from yaml import Loader, dump, load

from rpkiclientweb.rpki_client import RpkiClient


def load_sample_conf() -> Dict:
    path = os.path.join(os.path.dirname(__file__), "sample.yml")

    conf = load(open(path, "r"), Loader=Loader)
    conf.pop("interval")
    conf.pop("host")
    conf.pop("port")

    return conf


class ConfigTests(TestCase):
    def test_config_checks_cache_dir(self):
        conf = load_sample_conf()

        with tempfile.TemporaryDirectory() as dir_name:
            conf["output_dir"] = dir_name
            conf["cache_dir"] = ".well-known-missing"

            with self.assertRaises(AssertionError):
                client = RpkiClient(**conf)
                client.args

    def test_config_checks_output_dir(self):
        conf = load_sample_conf()

        with tempfile.TemporaryDirectory() as dir_name:
            conf["cache_dir"] = dir_name
            conf["output_dir"] = ".well-known-missing"

            with self.assertRaises(AssertionError):
                client = RpkiClient(**conf)
                client.args

    def test_config_accepts_when_both_exist(self):
        conf = load_sample_conf()

        with tempfile.TemporaryDirectory() as dir_name:
            with tempfile.TemporaryDirectory() as another_dir_name:
                conf["cache_dir"] = dir_name
                conf["output_dir"] = another_dir_name

                client = RpkiClient(**conf)
                client.args

    def test_requires_rpki_client_present(self):
        conf = load_sample_conf()

        conf["rpki_client"] = "/bin/bash"

        client = RpkiClient(**conf)
        client.args

        with self.assertRaises(AssertionError):
            conf["rpki_client"] = "/.well-known-missing"
            client = RpkiClient(**conf)
            client.args
