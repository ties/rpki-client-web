from collections import Counter
from dataclasses import dataclass
from datetime import datetime
import re
import urllib.parse

from typing import Generator, List, Union


MISSING_FILE_RE = re.compile(r"rpki-client: (?P<uri>.*): No such file or directory")
EXPIRED_MANIFEST_RE = re.compile(
    r"rpki-client: (?P<uri>.*): mft expired on (?P<expiry>.*)"
)


@dataclass
class MissingFileWarning:
    """rpki-client warning about a missing file."""

    uri: str
    label: str = "missing_file"


@dataclass
class ExpiredManifestWarning:
    """rpki-client warning about a expired manifest."""

    uri: str
    expiration: datetime
    label: str = "expired_manifest"


@dataclass
class WarningSummary:
    """Summary of warnings of a type for a host."""

    hostname: str
    warning_type: str
    count: int


RPKIClientWarning = Union[MissingFileWarning, ExpiredManifestWarning]


def parse_host(incomplete_uri: str) -> str:
    """Get netloc/host from incomplete uri."""
    # without // it is interpreted as relative
    return urllib.parse.urlparse(f"//{incomplete_uri}").netloc


def parse_rpki_client_output(
    stderr_output: str,
) -> Generator[RPKIClientWarning, None, None]:
    """Parse rpki-client output."""
    for line in stderr_output.split("\n"):
        missing_file = MISSING_FILE_RE.match(line)
        if missing_file:
            yield MissingFileWarning(missing_file.group("uri"))

        expired_manifest = EXPIRED_MANIFEST_RE.match(line)
        if expired_manifest:
            expiry = expired_manifest.group("expiry")
            yield ExpiredManifestWarning(
                expired_manifest.group("uri"),
                datetime.strptime(expiry, "%b %d %H:%M:%S %Y GMT"),
            )


def statistics_by_host(
    warnings: Generator[RPKIClientWarning, None, None]
) -> List[WarningSummary]:
    """Group the output by host by type."""
    c = Counter((warning.label, parse_host(warning.uri)) for warning in warnings)

    for (warning_type, host), count in c.items():
        yield WarningSummary(host, warning_type, count)
