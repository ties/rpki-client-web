"""Tests for the output parser."""
import os
import pytest

from rpkiclientweb.outputparser import (
    parse_rpki_client_output, statistics_by_host,
    MissingFileWarning, ExpiredManifestWarning, WarningSummary
)


def test_parse_sample_stderr_missing_files():
    with open("tests/sample_stderr_missing_files.txt", "r") as f:
        res = list(parse_rpki_client_output(f.read()))

        assert MissingFileWarning(uri='rpki.ripe.net/repository/DEFAULT/7f/6e81a1-5dda-44bd-8782-7f8c9c84462f/1/W4U1RKZjqFeblc2Ux7dyauj6bVQ.mft') in res


def test_parse_sample_stderr_regular():
    with open("tests/sample_stderr_regular.txt", "r") as f:
        res = list(parse_rpki_client_output(f.read()))

        assert any(map(lambda r: isinstance(r, ExpiredManifestWarning), res))


def test_statistics_sample_stderr_missing_files():
    with open("tests/sample_stderr_missing_files.txt", "r") as f:
        res = list(parse_rpki_client_output(f.read()))

        stats = list(statistics_by_host(res))

        assert WarningSummary('rpkica.mckay.com', 'expired_manifest', 1) in stats
        assert WarningSummary('ca.rg.net', 'missing_file', 1) in stats
