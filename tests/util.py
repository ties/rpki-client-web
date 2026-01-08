from collections import Counter
from datetime import datetime
from pathlib import Path

from rpkiclientweb.outputparser import OutputParser


def count_fetch_status(res: OutputParser) -> Counter:  # Tuple[str, str]
    return Counter((s.type, s.uri) for s in res.fetch_status)


def string_to_timestamped_lines(text: str) -> list[tuple[datetime, str]]:
    """Convert a string to timestamped lines for testing."""
    dummy_ts = datetime(2024, 1, 1, 0, 0, 0)
    return [(dummy_ts, line) for line in text.split("\n")]


def parse_output_file(name: str) -> OutputParser:
    p = Path(__file__).parent
    input_file = p / name

    with input_file.open("r") as f:
        return OutputParser(string_to_timestamped_lines(f.read()))
