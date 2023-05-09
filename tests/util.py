from collections import Counter
from pathlib import Path

from rpkiclientweb.outputparser import OutputParser


def count_fetch_status(res: OutputParser) -> Counter:  # Tuple[str, str]
    return Counter((s.type, s.uri) for s in res.fetch_status)


def parse_output_file(name: str) -> OutputParser:
    p = Path(__file__).parent
    input_file = p / name

    with input_file.open("r") as f:
        return OutputParser(f.read())
