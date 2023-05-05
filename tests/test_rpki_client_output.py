import gzip
from pathlib import Path

from rpkiclientweb.rpki_client_output import JSONOutputParser, OpenmetricsOutputParser


def relative_path(relpath: str) -> Path:
    """Resolve relative path to this source file."""
    p = Path(__file__).parent
    return p / relpath


def test_json_parser():
    """Parse an example JSON output."""
    json_parser = JSONOutputParser()
    path = relative_path("inputs/outputs/json.gz")
    with gzip.open(path, "r") as f:
        json_parser.parse(f)


def test_openmetrics_parser():
    """Parse openmetrics output file."""
    openmeetrics_parser = OpenmetricsOutputParser()
    openmeetrics_parser.parse(relative_path("inputs/outputs/metrics"))
