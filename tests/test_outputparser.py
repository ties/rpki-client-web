"""Tests for the output parser."""
import os
import pytest
from typing import List

from rpkiclientweb.outputparser import (
    OutputParser,
    missing_labels,
    LabelWarning,
    ExpirationWarning,
    WarningSummary,
    RPKIClientWarning,
    ManifestObjectWarning,
    MissingLabel
)


def parse_output_file(name: str) -> OutputParser:
    with open(name, "r") as f:
        return OutputParser(f.read())


def test_parse_sample_stderr_missing_files():
    parser = parse_output_file("tests/sample_stderr_regular.txt")

    assert (
        LabelWarning(
            warning_type="missing_file",
            uri="ca.rg.net/rpki/RGnet-OU/ovsCA/IOUcOeBGM_Tb4dwfvswY4bnNZYY.mft",
        )
        in parser.warnings
    )
    assert any(map(lambda r: isinstance(r, ExpirationWarning), parser.warnings))


def test_parse_sample_aggregated():
    """
    Parse output aggregated from multiple rpki-client runs, to make sure all
    types of warnings are accepted.

    Gathered with `docker logs rpki-client-web | sed -e 's/\\n/\n/g' | grep -E "^rpki-client:" | sort | uniq`
    """
    parser = parse_output_file("tests/sample_aggregated_output.txt")

    assert (
        LabelWarning(
            warning_type="missing_file",
            uri="ca.rg.net/rpki/RGnet-OU/ovsCA/IOUcOeBGM_Tb4dwfvswY4bnNZYY.mft",
        )
        in parser.warnings
    )
    assert any(map(lambda r: isinstance(r, ExpirationWarning), parser.warnings))
    # partial read
    assert (
        ManifestObjectWarning(
            warning_type="bad_message_digest",
            uri="rpki.ripe.net/repository/DEFAULT/d6/43d2c6-e4fa-4c39-ac0f-024e649261ec/1/cIb-UuM7FI_P9rrA0UYvDGnIJTQ.mft",
            object_name="cIb-UuM7FI_P9rrA0UYvDGnIJTQ.crl",
        )
        in parser.warnings
    )

def test_pulling_lines():
    """Test that the correct pulling lines are listed."""
    parser = parse_output_file("tests/sample_stderr_regular.txt")

    assert 'rpki.ripe.net/ta' in parser.pulling
    assert 'rpki.ripe.net/repository' in parser.pulling

    assert 'rpki.ripe.net/ta' in parser.pulled
    assert 'rpki.ripe.net/repository' in parser.pulled

def test_statistics_by_host():
    """Test the grouping of warnings by host."""
    parser = parse_output_file("tests/sample_aggregated_output.txt")

    stats = parser.statistics_by_host()

    assert WarningSummary("expired_manifest", "rpkica.mckay.com", 1) in stats
    assert WarningSummary("missing_file", "ca.rg.net", 1) in stats
    # Caused by an inconsistent read due to update
    assert WarningSummary("bad_message_digest", "rpki.ripe.net", 1) in stats


def test_missing_labels():
    """Test the diffing of sets of labels."""
    after = parse_output_file("tests/sample_stderr_regular.txt").statistics_by_host()
    before = parse_output_file("tests/sample_aggregated_output.txt").statistics_by_host()

    assert missing_labels(before, after) == frozenset(
        [
            MissingLabel("missing_file", "rpki1.terratransit.de"),
            MissingLabel("bad_message_digest", "rpki.ripe.net"),
        ]
    )

    assert missing_labels(after, before) == frozenset()
