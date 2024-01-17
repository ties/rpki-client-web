"""
Tests for the output parser.

Contains test cases that not _only_ path related, or nor _only_ fetching related. For example, test cases that parse a complete log file and check it for multiple types of situations.
"""
# pylint: disable=missing-function-docstring
from collections import Counter

from rpkiclientweb.models import (
    ExpirationWarning,
    FetchStatus,
    LabelWarning,
    ManifestObjectWarning,
    MissingLabel,
    RpkiClientError,
    WarningSummary,
)
from rpkiclientweb.outputparser import OutputParser, missing_labels
from rpkiclientweb.util import parse_host

from .util import count_fetch_status, parse_output_file


def test_parse_sample_stderr_missing_files() -> None:
    parser = parse_output_file("inputs/sample_stderr_regular.txt")

    assert (
        LabelWarning(
            warning_type="missing_file",
            uri="ca.rg.net/rpki/RGnet-OU/ovsCA/IOUcOeBGM_Tb4dwfvswY4bnNZYY.mft",
        )
        in parser.warnings
    )
    assert any(map(lambda r: isinstance(r, ExpirationWarning), parser.warnings))


def test_parse_sample_aggregated() -> None:
    """
    Parse output aggregated from multiple rpki-client runs, to make sure all
    types of warnings are accepted.

    Gathered with `docker logs rpki-client-web | sed -e 's/\\n/\n/g' | grep -E "^rpki-client:" | sort | uniq`
    """
    parser = parse_output_file("inputs/sample_aggregated_output.txt")

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


def test_parse_failed_fetch() -> None:
    """Track failed fetch that falls back to previous serial."""
    parser = parse_output_file("inputs/20240117_failed_fetch.txt")
    warnings = list(parser.warnings)

    assert (
        ManifestObjectWarning(
            warning_type="bad_message_digest",
            uri=".rsync/chloe.sobornost.net/rpki/uplift/IBfMWA0nPFS6MGTNLNavObgEuIc.mft#1486",
            object_name="T2ll0jOGuS7ODxpWNmwS1yOtzRM.roa",
        )
        in warnings
    )

    assert (
        LabelWarning(
            warning_type="mft_failed_fetch",
            uri="chloe.sobornost.net/rpki/uplift/IBfMWA0nPFS6MGTNLNavObgEuIc.mft",
        )
        in warnings
    )


def test_intertwined_lines() -> None:
    """
    Parse a file that contains lines that have mixed output.

    Multiple processes write to the same file descriptor, so a line can contain
    output from multiple processes.
    """
    parser = parse_output_file(
        "inputs/20210304_sample_idnic_multiple_processes_write_to_same_fd.txt"
    )

    for line in parser.pulling:
        assert "rpki-client:" not in line
        assert len(line) < 35

    for line in parser.pulled:
        assert "rpki-client:" not in line
        assert len(line) < 35
        assert len(line) < 35


def test_pulling_lines() -> None:
    """Test that the correct pulling lines are listed."""
    parser = parse_output_file("inputs/sample_stderr_regular.txt")

    assert "rpki.ripe.net/ta" in parser.pulling
    assert "rpki.ripe.net/repository" in parser.pulling

    assert "rpki.ripe.net/ta" in parser.pulled
    assert "rpki.ripe.net/repository" in parser.pulled


def test_vanished_lines() -> None:
    """Test that the vanished file lines are detected."""
    parser = parse_output_file("inputs/20210206_sample_twnic_pre_incident_missing.txt")

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


def test_statistics_by_host() -> None:
    """Test the grouping of warnings by host."""
    parser = parse_output_file("inputs/sample_aggregated_output.txt")

    stats = parser.statistics_by_host()

    assert WarningSummary("expired_manifest", "rpkica.mckay.com", 1) in stats
    assert WarningSummary("missing_file", "ca.rg.net", 1) in stats
    # Caused by an inconsistent read due to update
    assert WarningSummary("bad_message_digest", "rpki.ripe.net", 1) in stats


def test_missing_labels() -> None:
    """Test the diffing of sets of labels."""
    after = parse_output_file("inputs/sample_stderr_regular.txt").statistics_by_host()
    before = parse_output_file(
        "inputs/sample_aggregated_output.txt"
    ).statistics_by_host()

    assert missing_labels(before, after) == frozenset(
        [
            MissingLabel("missing_file", "rpki1.terratransit.de"),
            MissingLabel("bad_message_digest", "rpki.ripe.net"),
        ]
    )

    assert missing_labels(after, before) == frozenset()


def test_intertwined_rrdp_lines_20210614() -> None:
    """Parse a file that contains lines that have mixed output for RRDP."""
    res = parse_output_file("inputs/20210614_sample_rrdp_joined_line.txt")

    for status in res.fetch_status:
        assert "rpki-client:" not in status.uri
        assert "rpki-client:" not in status.type


def test_intertwined_rrdp_lines_20210712() -> None:
    """Parse a string that contains mixed output for RRDP."""
    res = OutputParser(
        "rpki-client: https://rpki.multacom.com/rrdp/notification.xml: notification file not modifiedrpki-client: https://rrdp.rpki.nlnetlabs.nl/rrdp/notification.xml: loaded from network"
    )

    for line in res.pulled:
        assert "rpki-client:" not in line


def test_rpki_client_warnings() -> None:
    """Parse a file that contains lines with warnings from rpki-client itself."""
    res = parse_output_file("inputs/20220901_http_chunked_assertion_error.txt")
    # rpki-client: http.c:715: http_done: Assertion `conn->bufpos == 0' failed.
    # rpki-client: https://rrdp.example.org/notification.xml: bad message digest
    # rpki-client: http terminated signal 6
    # rpki-client: not all files processed, giving up

    warnings = list(res.rpki_client_errors)

    assert RpkiClientError("http_terminated") in warnings
    assert RpkiClientError("not_all_files_processed") in warnings
    assert RpkiClientError("assertion_failed") in warnings

    assert FetchStatus(
        "https://rrdp.example.org/notification.xml", "bad_message_digest"
    ) in list(res.fetch_status)


def test_rpki_client_failed_download_digest_warnings() -> None:
    """Parse a file that contains lines with warnings from rpki-client itself."""
    res = parse_output_file("inputs/20220902_message_digest_failed_download.txt")

    c = count_fetch_status(res)

    assert c[("sync_bad_file_digest", "https://rrdp.example.org/notification.xml")] > 10


def test_roa_certificate_not_valid() -> None:
    """
    Warnings for ROA that certificates are not in a valid state.

    cases:
      * not yet valid
      * revoked
      * expired
    """
    res = parse_output_file(
        "inputs/20220903_certificate_not_yet_valid_tls_read_error.txt"
    )

    c = Counter((c.warning_type, parse_host(c.uri)) for c in res.warnings)

    assert c[("ee_certificate_expired", "rpki.example.org")] > 0
    assert c[("ee_certificate_not_yet_valid", "rpki.example.org")] > 0
    assert c[("ee_certificate_revoked", "rpki.example.org")] > 0
