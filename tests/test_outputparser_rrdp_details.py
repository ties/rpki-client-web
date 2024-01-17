"""
Tests for the output parser.

Contains specific tests for RRDP.
"""
# pylint: disable=missing-function-docstring

from rpkiclientweb.models import FetchStatus
from rpkiclientweb.outputparser import OutputParser


def test_parse_rrdp_delta_mutation_error() -> None:
    """Parse the warning when a historic RRDP hash changes."""
    parser = OutputParser(
        "rpki-client: https://rrdp.lacnic.net/rrdp/notification.xml: a5ea60b9-fd0d-4664-999a-7fcc801a6ae1#101 unexpected delta mutation (expected 7F894B30AEEC0048D2EE2311789737E57143FB16DF1BCECEA56ACA55BA9FEC0A, got EE89EE6581F48C358DE34EA04FED197778C333F09463BED53C670BCF4632E0CB)"
    )

    assert FetchStatus(
        "https://rrdp.lacnic.net/rrdp/notification.xml", "rrdp_delta_hash_mutation", 1
    ) in list(parser.fetch_status)
