"""
Tests for the output parser.

Contains specific tests for RRDP.
"""

# pylint: disable=missing-function-docstring

from rpkiclientweb.models import FetchStatus
from rpkiclientweb.outputparser import OutputParser
from tests.util import parse_output_file

RRDP_APNIC = "https://rrdp.apnic.net/notification.xml"
RRDP_AFRINIC = "https://rrdp.afrinic.net/notification.xml"
RRDP_EXAMPLE_ORG = "https://rrdp.example.org/notification.xml"
RRDP_PAAS_EXAMPLE_ORG = "https://rrdp.paas.rpki.example.org/notification.xml"
RPKI_CA = "https://rpkica.mckay.com/rrdp/notify.xml"
RRDP_SOBORNOST = "https://chloe.sobornost.net/rpki/news.xml"
RRDP_AWS = "https://rpki-rrdp.us-east-2.amazonaws.com/rrdp/967a255c-d680-42d3-9ec3-ecb3f9da088c/notification.xml"


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

    assert FetchStatus(RRDP_APNIC, "rrdp_snapshot", 1) in res.fetch_status
    assert FetchStatus(RRDP_AFRINIC, "rrdp_snapshot", 1) in res.fetch_status

    parser = OutputParser(
        "rpki-client: https://rrdp.apnic.net/notification.xml: downloading snapshot (7ca10d7d-74c3-49de-aeb4-88e0634f081b#10201)"
    )
    assert FetchStatus(RRDP_APNIC, "rrdp_snapshot", 1) in parser.fetch_status


def test_rrdp_deltas() -> None:
    """Test a situation with rsync fallback (from RRDP)."""
    res = parse_output_file("inputs/20210610_sample_deltas.txt")

    assert FetchStatus(
        "https://rrdp.apnic.net/notification.xml", "rrdp_delta", 7
    ) in list(res.fetch_status)
    assert FetchStatus(
        "https://rpki-repo.registro.br/rrdp/notification.xml", "rrdp_delta", 13
    ) in list(res.fetch_status)


def test_rrdp_deltas_84() -> None:
    res = parse_output_file("inputs/20230509_full_output.txt")
    statuses = list(res.fetch_status)

    assert FetchStatus(RRDP_EXAMPLE_ORG, "rrdp_delta", 2) in statuses
    assert FetchStatus(RRDP_PAAS_EXAMPLE_ORG, "rrdp_delta", 1) in statuses
    assert FetchStatus(RRDP_PAAS_EXAMPLE_ORG, "sync_bad_file_digest", 1) in statuses
    assert FetchStatus(RRDP_PAAS_EXAMPLE_ORG, "rrdp_snapshot_fallback", 1) in statuses

    assert FetchStatus(RRDP_AWS, "rrdp_notification_not_modified", 1) in statuses

    assert FetchStatus(RPKI_CA, "rrdp_rsync_fallback", 1) in statuses
    assert (
        FetchStatus(RPKI_CA, "rrdp_tls_certificate_verification_failed", 1) in statuses
    )

    assert FetchStatus(RRDP_SOBORNOST, "connect_error", 1) in statuses
    assert FetchStatus(RRDP_SOBORNOST, "connect_timeout", 1) in statuses


def test_rrdp_parse_aborted() -> None:
    """Test a situation where parsing is aborted for rsync."""
    res = parse_output_file("inputs/20220311_sample_rrdp_rejected_file_too_large.txt")
    fetch_status = list(res.fetch_status)

    assert (
        FetchStatus("https://rrdp.example.org/notification.xml", "rrdp_parse_aborted")
        in fetch_status
    )

    assert FetchStatus("<unknown>", "rrdp_parse_error_file_too_big") in fetch_status


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


def test_rrdp_serial_decreassed() -> None:
    """Parse a string that contains the output when RRDP serial reverts for same serial."""
    res = OutputParser(
        "rpki-client: https://rrdp.example.org/rrdp/notification.xml: serial number decreased from 42 to 10\n"
    )

    assert FetchStatus(
        "https://rrdp.example.org/rrdp/notification.xml",
        "rrdp_serial_decreased",
        42 - 10,
    ) in list(res.fetch_status)


def test_rrdp_referenced_file_delted() -> None:
    """A file was withdrawn from RRDP while it was still referenced by other objects."""

    res = OutputParser(
        "rpki-client: rpki.example.org/repository/DEFAULT/0f/331bcf-8e29-45bd-ab6c-f52b30e01820/1/BaYSj14pZXCsabRKG-pJ7HoYDvM.roa: referenced file supposed to be deleted"
    )

    assert FetchStatus(
        "rpki.example.org",
        "rrdp_referenced_file_deleted",
        1,
    ) in list(res.fetch_status)


def test_parse_rrdp_delta_mutation_error() -> None:
    """Parse the warning when a historic RRDP hash changes."""
    parser = OutputParser(
        "rpki-client: https://rrdp.lacnic.net/rrdp/notification.xml: a5ea60b9-fd0d-4664-999a-7fcc801a6ae1#101 unexpected delta mutation (expected 7F894B30AEEC0048D2EE2311789737E57143FB16DF1BCECEA56ACA55BA9FEC0A, got EE89EE6581F48C358DE34EA04FED197778C333F09463BED53C670BCF4632E0CB)"
    )

    assert FetchStatus(
        "https://rrdp.lacnic.net/rrdp/notification.xml", "rrdp_delta_hash_mutation", 1
    ) in list(parser.fetch_status)
