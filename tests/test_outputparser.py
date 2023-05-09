"""Tests for the output parser."""
from collections import Counter
from pathlib import Path

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


def count_fetch_status(res: OutputParser) -> Counter:  # Tuple[str, str]
    return Counter((s.type, s.uri) for s in res.fetch_status)


def parse_output_file(name: str) -> OutputParser:
    p = Path(__file__).parent
    input_file = p / name

    with input_file.open("r") as f:
        return OutputParser(f.read())


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


def test_twnic_revoked_objects() -> None:
    """
    Parse the output on 2021-2-3 that contains revoked objects.
    """
    parser = parse_output_file("inputs/20210206_sample_twnic_during.txt")

    assert (
        LabelWarning(
            warning_type="ee_certificate_revoked",
            uri="rpkica.twnic.tw/rpki/TWNICCA/OPENRICH/mlhIJnN1dfbOEvjGTcE83FLq17Q.roa",
        )
        in parser.warnings
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


def test_overclaiming_line() -> None:
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


def test_rpki_object_no_valid_mft_available() -> None:
    """No valid manifest available errors."""
    res = parse_output_file("inputs/20220223_no_valid_mft_available.txt")

    assert (
        LabelWarning(
            warning_type="no_valid_mft_available",
            uri="0.sb/repo/sb/30/F8CE54A4C62E61B125423FA90CA3F9D8350C7D3D.mft",
        )
        in res.warnings
    )


def test_rpki_object_missing_sia() -> None:
    """No valid manifest available errors."""
    res = parse_output_file("inputs/20220122_missing_sia.txt")

    assert (
        LabelWarning(
            warning_type="missing_sia",
            uri="rrdp/436fc6bd7b32853e42fce5fd95b31d5e3ec1c32c46b7518c2067d568e7eac119/chloe.sobornost.net/rpki/RIPE-nljobsnijders/voibVdC3Nzl9dcSfSFuFj6mK0R8.cer",
        )
        in res.warnings
    )


def test_crl_has_expired_error() -> None:
    """Test parse 'crl has expired' errors #97"""
    res = parse_output_file("inputs/20230509_crl_has_expired.txt")
    assert (
        LabelWarning(
            warning_type="mft_crl_expired",
            uri="rpki-repo.registro.br/repo/2qosEFHVQbeQvy8iktdNzpWNHKcB1zeV4mSd6F1ea1WN/0/028B43AD112899168CE5212FE3FB097B8D664FD2.mft",
        )
        in res.warnings
    )


def test_rsync_errors() -> None:
    """Test a situation with many rsync errors."""
    res = parse_output_file("inputs/20210610_sample_rsync_errors.txt")

    assert FetchStatus("rsync://rpki.cnnic.cn/rpki", "rsync_load_failed", 1) in list(
        res.fetch_status
    )


def test_rsync_fallback() -> None:
    """Test a situation with rsync fallback (from RRDP)."""
    res = parse_output_file("inputs/20210610_rsync_fallback.txt")

    assert FetchStatus(
        "https://rrdp.ripe.net/notification.xml", "rrdp_rsync_fallback"
    ) in list(res.fetch_status)


def test_rrdp_tls_cert_expired() -> None:
    """TLS certificate has expired."""
    res = parse_output_file("inputs/20220311_tls_handshake_cert_expired.txt")

    assert FetchStatus(
        "https://rpki.blade.sh/rrdp/notification.xml",
        "rrdp_tls_certificate_verification_failed",
    ) in list(res.fetch_status)


def test_rrdp_not_modified() -> None:
    """Test a situation with rsync fallback (from RRDP)."""
    res = parse_output_file("inputs/20210610_sample_deltas.txt")

    assert FetchStatus(
        "https://rrdp.lacnic.net/rrdp/notification.xml",
        "rrdp_notification_not_modified",
        1,
    ) in list(res.fetch_status)


def test_rrdp_snapshots() -> None:
    """Test a situation with rsync fallback (from RRDP)."""
    res = parse_output_file("inputs/20210610_sample_snapshot_dl.txt")

    assert FetchStatus(
        "https://rrdp.afrinic.net/notification.xml", "rrdp_snapshot", 1
    ) in list(res.fetch_status)
    assert FetchStatus(
        "https://rrdp.apnic.net/notification.xml", "rrdp_snapshot", 1
    ) in list(res.fetch_status)


def test_rrdp_deltas() -> None:
    """Test a situation with rsync fallback (from RRDP)."""
    res = parse_output_file("inputs/20210610_sample_deltas.txt")

    assert FetchStatus(
        "https://rrdp.apnic.net/notification.xml", "rrdp_delta", 7
    ) in list(res.fetch_status)
    assert FetchStatus(
        "https://rpki-repo.registro.br/rrdp/notification.xml", "rrdp_delta", 13
    ) in list(res.fetch_status)


def test_rrdp_parse_aborted() -> None:
    """Test a situation where parsing is aborted for rsync."""
    res = parse_output_file("inputs/20220311_sample_rrdp_rejected_file_too_large.txt")
    fetch_status = list(res.fetch_status)

    assert (
        FetchStatus("https://rrdp.example.org/notification.xml", "rrdp_parse_aborted")
        in fetch_status
    )

    assert FetchStatus("<unknown>", "rrdp_parse_error_file_too_big") in fetch_status


def test_fallback_to_cache() -> None:
    """Test the situation where a repo falls back to cache."""
    parser = parse_output_file("inputs/sample_aggregated_output.txt")

    #  rpki-client: nostromo.heficed.net/repo: load from network failed, fallback to cache
    assert FetchStatus("nostromo.heficed.net/repo", "sync_fallback_to_cache") in list(
        parser.fetch_status
    )


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


def test_rrdp_parse_failed() -> None:
    """Parse a string that contains the output on an invalid RRDP repo."""
    res = OutputParser(
        "rpki-client: parse failed - serial mismatch\n"
        "rpki-client: https://host.example.org/notification.xml: parse error at line 1: parsing aborted\n"
        "rpki-client: https://host.example.org/notification.xml: load from network failed, fallback to rsync\n"
    )

    assert FetchStatus(
        "https://host.example.org/notification.xml", "rrdp_parse_aborted"
    ) in list(res.fetch_status)


def test_rrdp_repository_not_modified() -> None:
    """Parse a string that contains the output on an repository that did not change."""
    res = OutputParser(
        "rpki-client: https://rrdp.example.org/rrdp/notification.xml: pulling from network\n"
        "rpki-client: https://rrdp.example.org/rrdp/notification.xml: repository not modified\n"
        "rpki-client: https://rrdp.example.org/rrdp/notification.xml: loaded from network\n"
    )

    assert FetchStatus(
        "https://rrdp.example.org/rrdp/notification.xml",
        "rrdp_repository_not_modified",
        1,
    ) in list(res.fetch_status)


def test_rrdp_serial_decreated() -> None:
    """Parse a string that contains the output when RRDP serial reverts for same serial."""
    res = OutputParser(
        "rpki-client: https://rrdp.example.org/rrdp/notification.xml: serial number decreased from 42 to 10\n"
    )

    assert FetchStatus(
        "https://rrdp.example.org/rrdp/notification.xml",
        "rrdp_serial_decreased",
        42 - 10,
    ) in list(res.fetch_status)


def test_rrdp_tls_failure() -> None:
    """Parse a string that contains a TLS failure."""
    res = OutputParser(
        "rpki-client: rrdp.example.org: TLS read: read failed: error:0A000126:SSL routines::unexpected eof while reading\n"
    )

    assert FetchStatus("rrdp.example.org", "tls_failure", 1) in list(res.fetch_status)

    res = parse_output_file(
        "inputs/20220903_certificate_not_yet_valid_tls_read_error.txt"
    )

    assert FetchStatus("rrdp.example.org", "tls_failure", 1) in res.fetch_status
    assert FetchStatus("rpki.example.org", "tls_failure", 1) in res.fetch_status


def test_unsupported_filetype() -> None:
    parser = OutputParser(
        "rpki-client: rrdp/198613f16d61d95b77329eb7acdb3e1f8d1f0ec2b75e9510a7f7eacc7c3ebe19/rpki-repo.registro.br/repo/CdwCiTUGWyooJPMS1kEENXCA3aBaR67C8gcsvCd5HFU1/0/CBC415E956186D9CC61972979D5AC7B197F563BB.mft: unsupported file type for 3137372e38352e3136342e302f32322d3234203d3e203532373433.inv\n"
    )

    assert ManifestObjectWarning(
        warning_type="unsupported_filetype",
        uri="rrdp/198613f16d61d95b77329eb7acdb3e1f8d1f0ec2b75e9510a7f7eacc7c3ebe19/rpki-repo.registro.br/repo/CdwCiTUGWyooJPMS1kEENXCA3aBaR67C8gcsvCd5HFU1/0/CBC415E956186D9CC61972979D5AC7B197F563BB.mft",
        object_name="3137372e38352e3136342e302f32322d3234203d3e203532373433.inv",
    ) in list(parser.warnings)


def test_parse_mft_warning() -> None:
    parser = OutputParser(
        "rpki-client: interop/misc-objects/6C76EDB2225D11E286C4BD8F7A2F2747.roa: RFC 6488: CMS has unexpected signed attribute 1.2.840.113549.1.9.15\n"
    )

    assert (
        LabelWarning(
            "unexpected_signed_cms_attribute",
            "interop/misc-objects/6C76EDB2225D11E286C4BD8F7A2F2747.roa",
        )
        in parser.warnings
    )


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

    assert (
        c[("sync_bad_message_digest", "https://rrdp.example.org/notification.xml")] > 10
    )


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


def test_fetch_error_no_ee_certificate_errorr() -> None:
    """Do not conflate TLS and EE certificate errors."""
    res = parse_output_file("inputs/20220905_tls_error_expired.txt")

    assert (
        FetchStatus(
            uri="https://rpkica.mckay.com/rrdp/notify.xml",
            type="rrdp_tls_certificate_verification_failed",
            count=1,
        )
        in res.fetch_status
    )
    # But no EE certificate warning:
    assert len(list(res.warnings)) != 0


def test_fetch_error_connect_errors() -> None:
    """Connection errors should be tracked."""
    res = parse_output_file("inputs/20220906_arin_rrdp.txt")

    assert (
        FetchStatus(uri="https://rrdp.arin.net/notification.xml", type="connect_error")
        in res.fetch_status
    )
    assert (
        FetchStatus(uri="https://rrdp.arin.net/arin-rpki-ta.cer", type="connect_error")
        in res.fetch_status
    )

    c = count_fetch_status(res)
    assert c[("connect_error", "https://rrdp.arin.net/notification.xml")] == 4
    assert c[("connect_error", "https://rrdp.arin.net/arin-rpki-ta.cer")] == 4


def test_fetch_error_rsync_issues() -> None:
    """The count of rsync errors should be tracked."""
    res = parse_output_file("inputs/20220906_arin_rsync.txt")

    assert (
        FetchStatus(
            uri="rsync://rpki.arin.net/repository",
            type="synchronisation_timeout",
            count=1,
        )
        in res.fetch_status
    )
    assert (
        FetchStatus(
            uri="rsync://rpki.arin.net/repository", type="rsync_load_failed", count=1
        )
        in res.fetch_status
    )


def test_fetch_error_404() -> None:
    """Parse a number of fetch errors due to 404s."""
    res = parse_output_file("inputs/20220912_404_delta.txt")

    assert FetchStatus(
        "https://rrdp.ripe.net/notification.xml", "rrdp_snapshot_fallback"
    ) in list(res.fetch_status)

    c = count_fetch_status(res)
    assert c[("http_404", "rrdp.ripe.net")] == 2
