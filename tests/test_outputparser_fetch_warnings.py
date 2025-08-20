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


def test_fallback_to_cache() -> None:
    """Test the situation where a repo falls back to cache."""
    parser = parse_output_file("inputs/sample_aggregated_output.txt")

    #  rpki-client: nostromo.heficed.net/repo: load from network failed, fallback to cache
    assert FetchStatus("nostromo.heficed.net/repo", "sync_fallback_to_cache") in list(
        parser.fetch_status
    )


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


def test_rrdp_tls_failure_no_object_warning() -> None:
    res = OutputParser(
        "rpki-client: https://rpkica.mckay.com/rrdp/notify.xml (51.75.161.87): TLS handshake: certificate verification failed: certificate has expired"
    )

    assert len(list(res.fetch_status)) == 1
    assert len(list(res.warnings)) == 0


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
    assert len(list(res.warnings)) == 0


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

    # Old format logfile does not have the protocol in the log yet.
    c = count_fetch_status(res)
    assert c[("http_404", "rrdp.ripe.net")] == 2


def test_fetch_error_404_no_full_url_in_metric() -> None:
    """Parse an error where a snapshot is missing. The hostname should be in the metric not the url."""
    res = parse_output_file("inputs/20230828_404_snapshot_url.txt")
    status_errors = list(res.fetch_status)

    assert FetchStatus("https://rrdp.ripe.net", "http_404") in status_errors

    assert FetchStatus("https://magellan.ipxo.com", "http_521") in status_errors


def test_fetch_status_rpki_client_9_5_1() -> None:
    """Parse output from rpki-client 9.5.1"""
    res = parse_output_file("inputs/20250820_rpki_client_orig.txt")
    status_errors = list(res.fetch_status)

    for status in status_errors:
        assert (
            status.uri.startswith("https://") or status.uri.startswith("rsync://")
        ) or "://" not in status.uri

    status_types = {status.type for status in status_errors}
    # this is detailed, but less granular than the number of lines
    assert len(status_types) < 0.2 * len(status_errors)
