"""Tests for the output parser."""
import os
from typing import List

import pytest

from rpkiclientweb.outputparser import (
    ExpirationWarning,
    FetchStatus,
    LabelWarning,
    ManifestObjectWarning,
    MissingLabel,
    OutputParser,
    RPKIClientWarning,
    WarningSummary,
    missing_labels,
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
    #  rpki-client: nostromo.heficed.net/repo: load from network failed, fallback to cache
    assert FetchStatus("nostromo.heficed.net/repo", "sync_fallback_to_cache") in list(
        parser.fetch_status
    )


def test_twnic_revoked_objects():
    """
    Parse the output on 2021-2-3 that contains revoked objects.
    """
    parser = parse_output_file("tests/20210206_sample_twnic_during.txt")

    assert (
        LabelWarning(
            warning_type="revoked_certificate",
            uri="rpkica.twnic.tw/rpki/TWNICCA/OPENRICH/mlhIJnN1dfbOEvjGTcE83FLq17Q.roa",
        )
        in parser.warnings
    )


def test_intertwined_lines():
    """
    Parse a file that contains lines that have mixed output.

    Multiple processes write to the same file descriptor, so a line can contain
    output from multiple processes.
    """
    parser = parse_output_file(
        "tests/20210304_sample_idnic_multiple_processes_write_to_same_fd.txt"
    )

    for line in parser.pulling:
        assert "rpki-client:" not in line
        assert len(line) < 35

    for line in parser.pulled:
        assert "rpki-client:" not in line
        assert len(line) < 35
        assert len(line) < 35


def test_overclaiming_line():
    parser = OutputParser(
        "rpki-client: ca.rg.net/rpki/RGnet-OU/_XrQ8TKGekuqYxq7Ev1ZflcIsWM.roa: RFC 3779 resource not subset of parent's resources"
    )

    assert (
        LabelWarning(
            warning_type="overclaiming",
            uri="ca.rg.net/rpki/RGnet-OU/_XrQ8TKGekuqYxq7Ev1ZflcIsWM.roa",
        )
        in parser.warnings
    )


def test_pulling_lines():
    """Test that the correct pulling lines are listed."""
    parser = parse_output_file("tests/sample_stderr_regular.txt")

    assert "rpki.ripe.net/ta" in parser.pulling
    assert "rpki.ripe.net/repository" in parser.pulling

    assert "rpki.ripe.net/ta" in parser.pulled
    assert "rpki.ripe.net/repository" in parser.pulled


def test_vanished_lines():
    """Test that the vanished file lines are detected."""
    parser = parse_output_file("tests/20210206_sample_twnic_pre_incident_missing.txt")

    files = parser.vanished_files
    directories = parser.vanished_directories

    # Two random samples
    assert "/89f26fb8-72c4-49d9-9cbe-8226397271a2" in directories
    assert (
        "/48f39bd4-cdac-41cf-8858-d7410f64d155/0/323430353a316534303a3a2f34382d3438203d3e203538343735.roa"
        in files
    )
    # Test that is is above lower bound
    assert len(files) > 850 and len(files) < 900
    assert len(directories) > 190 and len(directories) < 210


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
    before = parse_output_file(
        "tests/sample_aggregated_output.txt"
    ).statistics_by_host()

    assert missing_labels(before, after) == frozenset(
        [
            MissingLabel("missing_file", "rpki1.terratransit.de"),
            MissingLabel("bad_message_digest", "rpki.ripe.net"),
        ]
    )

    assert missing_labels(after, before) == frozenset()


def test_rpki_object_no_valid_mft_available():
    """No valid manifest available errors."""
    res = parse_output_file("tests/20220223_no_valid_mft_available.txt")

    assert (
        LabelWarning(
            warning_type="no_valid_mft_available",
            uri="0.sb/repo/sb/30/F8CE54A4C62E61B125423FA90CA3F9D8350C7D3D.mft",
        )
        in res.warnings
    )


def test_rpki_object_missing_sia():
    """No valid manifest available errors."""
    res = parse_output_file("tests/20220122_missing_sia.txt")

    assert (
        LabelWarning(
            warning_type="missing_sia",
            uri="rrdp/436fc6bd7b32853e42fce5fd95b31d5e3ec1c32c46b7518c2067d568e7eac119/chloe.sobornost.net/rpki/RIPE-nljobsnijders/voibVdC3Nzl9dcSfSFuFj6mK0R8.cer",
        )
        in res.warnings
    )


def test_rsync_errors():
    """Test a situation with many rsync errors."""
    res = parse_output_file("tests/20210610_sample_rsync_errors.txt")

    assert FetchStatus("rsync://rpki.cnnic.cn/rpki", "rsync_load_failed", 1) in list(
        res.fetch_status
    )


def test_rsync_fallback():
    """Test a situation with rsync fallback (from RRDP)."""
    res = parse_output_file("tests/20210610_rsync_fallback.txt")

    assert FetchStatus(
        "https://rrdp.ripe.net/notification.xml", "rrdp_rsync_fallback"
    ) in list(res.fetch_status)


def test_rrdp_tls_cert_expired():
    """TLS certificate has expired."""
    res = parse_output_file("tests/20220311_tls_handshake_cert_expired.txt")

    assert FetchStatus(
        "https://rpki.blade.sh/rrdp/notification.xml", "rrdp_tls_certificate_verification_failed"
    ) in list(res.fetch_status)


def test_rrdp_not_modified():
    """Test a situation with rsync fallback (from RRDP)."""
    res = parse_output_file("tests/20210610_sample_deltas.txt")
    print(list(res.fetch_status))

    assert (
        FetchStatus(
            "https://rrdp.lacnic.net/rrdp/notification.xml",
            "rrdp_notification_not_modified",
            1,
        )
        in list(res.fetch_status)
    )


def test_rrdp_snapshots():
    """Test a situation with rsync fallback (from RRDP)."""
    res = parse_output_file("tests/20210610_sample_snapshot_dl.txt")

    assert FetchStatus(
        "https://rrdp.afrinic.net/notification.xml", "rrdp_snapshot", 1
    ) in list(res.fetch_status)
    assert FetchStatus(
        "https://rrdp.apnic.net/notification.xml", "rrdp_snapshot", 1
    ) in list(res.fetch_status)


def test_rrdp_deltas():
    """Test a situation with rsync fallback (from RRDP)."""
    res = parse_output_file("tests/20210610_sample_deltas.txt")

    assert FetchStatus(
        "https://rrdp.apnic.net/notification.xml", "rrdp_delta", 7
    ) in list(res.fetch_status)
    assert FetchStatus(
        "https://rpki-repo.registro.br/rrdp/notification.xml", "rrdp_delta", 13
    ) in list(res.fetch_status)


def test_rrdp_parse_aborted():
    """Test a situation where parsing is aborted for rsync."""
    res = parse_output_file("tests/20220311_sample_rrdp_rejected_file_too_large.txt")
    fetch_status = list(res.fetch_status)

    assert (
        FetchStatus("https://rrdp.example.org/notification.xml", "rrdp_parse_aborted")
        in fetch_status
    )

    assert FetchStatus("<unknown>", "rrdp_parse_error_file_too_big") in fetch_status


def test_rsync_fallback():
    """Test a situation with rsync fallback (from RRDP)."""
    res = parse_output_file("tests/20210610_rsync_fallback.txt")

    assert FetchStatus(
        "https://rrdp.ripe.net/notification.xml", "rrdp_rsync_fallback"
    ) in list(res.fetch_status)


def test_fallback_to_cache():
    """Test the situation where a repo falls back to cache."""
    parser = parse_output_file("tests/sample_aggregated_output.txt")

    #  rpki-client: nostromo.heficed.net/repo: load from network failed, fallback to cache
    assert FetchStatus("nostromo.heficed.net/repo", "sync_fallback_to_cache") in list(
        parser.fetch_status
    )


def test_intertwined_rrdp_lines_20210614():
    """Parse a file that contains lines that have mixed output for RRDP."""
    res = parse_output_file("tests/20210614_sample_rrdp_joined_line.txt")

    for status in res.fetch_status:
        assert "rpki-client:" not in status.uri
        assert "rpki-client:" not in status.type


def test_intertwined_rrdp_lines_20210712():
    """Parse a string that contains mixed output for RRDP."""
    res = OutputParser(
        "rpki-client: https://rpki.multacom.com/rrdp/notification.xml: notification file not modifiedrpki-client: https://rrdp.rpki.nlnetlabs.nl/rrdp/notification.xml: loaded from network"
    )

    for line in res.pulled:
        assert "rpki-client:" not in line


def test_rrdp_parse_failed():
    """Parse a string that contains the output on an invalid RRDP repo."""
    res = OutputParser(
        "rpki-client: parse failed - serial mismatch\n"
        "rpki-client: https://host.example.org/notification.xml: parse error at line 1: parsing aborted\n"
        "rpki-client: https://host.example.org/notification.xml: load from network failed, fallback to rsync\n"
    )

    assert FetchStatus("https://host.example.org/notification.xml", "rrdp_parse_aborted") in list(
        res.fetch_status
    )


def test_rrdp_repository_not_modified():
    """Parse a string that contains the output on an repository that did not change."""
    res = OutputParser(
        "rpki-client: https://rrdp.example.org/rrdp/notification.xml: pulling from network\n"
        "rpki-client: https://rrdp.example.org/rrdp/notification.xml: repository not modified\n"
        "rpki-client: https://rrdp.example.org/rrdp/notification.xml: loaded from network\n"
    )

    assert (
        FetchStatus(
            "https://rrdp.example.org/rrdp/notification.xml",
            "rrdp_repository_not_modified",
            1,
        )
        in list(res.fetch_status)
    )


def test_rrdp_serial_decreated():
    """Parse a string that contains the output when RRDP serial reverts for same serial."""
    res = OutputParser(
        "rpki-client: https://rrdp.example.org/rrdp/notification.xml: serial number decreased from 42 to 10\n"
    )

    assert (
        FetchStatus(
            "https://rrdp.example.org/rrdp/notification.xml",
            "rrdp_serial_decreased",
            42-10,
        )
        in list(res.fetch_status)
    )

