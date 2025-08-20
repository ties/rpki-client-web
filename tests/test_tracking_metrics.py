from pathlib import Path

import pytest

from rpkiclientweb.config import Configuration
from rpkiclientweb.rpki_client import RpkiClient
from tests.test_config import load_sample_conf


@pytest.fixture
def sample_config() -> Configuration:
    return Configuration(load_sample_conf())


def test_add_remove_fetch_status(sample_config: Configuration) -> None:
    """Test the fetch status state tracked in the rpki-client object."""
    subject = RpkiClient(sample_config)

    with (Path(__file__).parent / "inputs/20250820_rpki_client_orig.txt").open(
        "r"
    ) as f:
        subject.update_warning_metrics(f.read(), True)

    fetch_uris = set(f[0] for f in subject.fetched)

    # Now read the file where some repositories have been removed
    with (
        Path(__file__).parent / "inputs/20250820_rpki_client_removed_fetches.txt"
    ).open("r") as f:
        subject.update_warning_metrics(f.read(), True)

    fetch_uris_after = set(f[0] for f in subject.fetched)

    # two were removed
    assert "https://rrdp.paas.rpki.ripe.net/notification.xml" in (
        fetch_uris - fetch_uris_after
    )
    assert "https://rpki.rand.apnic.net/rrdp/notification.xml" in (
        fetch_uris - fetch_uris_after
    )

    # And we added one
    assert "https://rpki.rand.renamed.apnic.net/rrdp/notification.xml" not in fetch_uris
    assert (
        "https://rpki.rand.renamed.apnic.net/rrdp/notification.xml" in fetch_uris_after
    )
