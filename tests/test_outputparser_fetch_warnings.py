"""Tests for the fetching-related warnings."""
# pylint: disable=missing-function-docstring

from rpkiclientweb.models import FetchStatus
from rpkiclientweb.outputparser import OutputParser

from .util import count_fetch_status, parse_output_file


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
