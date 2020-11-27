from collections import Counter
from datetime import datetime
import re
import urllib.parse

from typing import NamedTuple, Generator, List, Union, Set


MISSING_FILE_RE = re.compile(r"rpki-client: (?P<uri>.*): No such file or directory")
EXPIRED_MANIFEST_RE = re.compile(
    r"rpki-client: (?P<uri>.*): mft expired on (?P<expiry>.*)"
)
BAD_MESSAGE_DIGEST_RE = re.compile(
    r"rpki-client: (?P<uri>.*): bad message digest for (?P<object>.*)"
)


class LabelWarning(NamedTuple):
    """rpki-client warning about a file."""

    warning_type: str
    uri: str


class ExpirationWarning(NamedTuple):
    """rpki-client warning about an expiration."""

    warning_type: str
    uri: str
    expiration: datetime


class ManifestObjectWarning(NamedTuple):
    """rpki-client warning about a file on a manifest."""

    warning_type: str
    uri: str
    object_name: str


class WarningSummary(NamedTuple):
    """Summary of warnings of a type for a host."""

    warning_type: str
    hostname: str
    count: int


class MissingLabel(NamedTuple):
    """A missing label."""
    warning_type: str
    hostname: str


RPKIClientWarning = Union[LabelWarning, ExpirationWarning, ManifestObjectWarning]


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
            yield LabelWarning("missing_file", missing_file.group("uri"))
            continue

        expired_manifest = EXPIRED_MANIFEST_RE.match(line)
        if expired_manifest:
            expiry = expired_manifest.group("expiry")
            yield ExpirationWarning(
                "expired_manifest",
                expired_manifest.group("uri"),
                datetime.strptime(expiry, "%b %d %H:%M:%S %Y GMT"),
            )
            continue

        # likely cause: A partial read, one object is updated while another
        # is not.
        bad_message_digest = BAD_MESSAGE_DIGEST_RE.match(line)
        if bad_message_digest:
            yield ManifestObjectWarning(
                "bad_message_digest",
                bad_message_digest.group("uri"),
                bad_message_digest.group("object"),
            )


def statistics_by_host(
    warnings: Generator[RPKIClientWarning, None, None]
) -> List[WarningSummary]:
    """Group the output by host by type."""
    c = Counter((warning.warning_type, parse_host(warning.uri)) for warning in warnings)

    return [
        WarningSummary(warning_type, host, count)
        for (warning_type, host), count in c.items()
    ]


def missing_labels(
    lhs: List[WarningSummary], rhs: List[WarningSummary]
) -> Set[MissingLabel]:
    """
    Gather the labels present in lhs that are not in rhs.

    Used to determine what labels are no longer present on the metrics.
    """
    l = frozenset(MissingLabel(w.warning_type, w.hostname) for w in lhs)
    r = frozenset(MissingLabel(w.warning_type, w.hostname) for w in rhs)

    return l - r
