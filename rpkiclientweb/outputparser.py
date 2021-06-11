import logging
import re
from collections import Counter
from datetime import datetime
from typing import FrozenSet, Generator, List, NamedTuple, Union

from rpkiclientweb.util import parse_host


LOG = logging.getLogger(__name__)

BAD_MESSAGE_DIGEST_RE = re.compile(
    r"rpki-client: (?P<path>.*): bad message digest for (?P<object>.*)"
)
EXPIRED_MANIFEST_RE = re.compile(
    r"rpki-client: (?P<path>.*): mft expired on (?P<expiry>.*)"
)
MISSING_FILE_RE = re.compile(
    r"rpki-client: (?!rpki-client:)(?P<path>.*): No such file or directory"
)
PULLING_RE = re.compile(
    r"rpki-client: (?!rpki-client:)(?P<uri>.*): pulling from network"
)
PULLED_RE = re.compile(r"rpki-client: (?!rpki-client:)(?P<uri>.*): loaded from network")

RSYNC_LOAD_FAILED = re.compile(r"rpki-client: rsync (?P<uri>.*) failed$")
RSYNC_FALLBACK = re.compile(
    r"rpki-client: (?P<uri>.*): load from network failed, fallback to rsync$"
)

RSYNC_RRDP_NOT_MODIFIED = re.compile(
    r"rpki-client: (?P<uri>.*): notification file not modified$"
)
RSYNC_RRDP_SNAPSHOT = re.compile(r"rpki-client: (?P<uri>.*): downloading snapshot$")
RSYNC_RRDP_DELTAS = re.compile(
    r"rpki-client: (?P<uri>.*): downloading (?P<count>\d+) deltas$"
)

RESOURCE_OVERCLAIMING = re.compile(
    r"rpki-client: (?P<path>.*): RFC 3779 resource not subset of parent's resources"
)
REVOKED_CERTIFICATE = re.compile(
    r"rpki-client: (?!rpki-client:)(?P<path>.*): certificate revoked"
)
VANISHED_FILE_RE = re.compile(r"file has vanished: \"(?P<path>.*)\" \(in repo\)")
VANISHED_DIRECTORY_RE = re.compile(
    r"directory has vanished: \"(?P<path>.*)\" \(in repo\)"
)


class FetchStatus(NamedTuple):
    """
    rpki-client fetch status for a repo.

    Can be both positive or negative.
    """

    uri: str
    type: str
    count: int = 1


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


def parse_maybe_warning_line(line) -> Generator[RPKIClientWarning, None, None]:
    """Parse a line for warnings - may be empty."""
    # LabelWarning (<type, file> tuples) first
    missing_file = MISSING_FILE_RE.match(line)
    if missing_file:
        yield LabelWarning("missing_file", missing_file.group("path"))

    overclaiming = RESOURCE_OVERCLAIMING.match(line)
    if overclaiming:
        yield LabelWarning("overclaiming", overclaiming.group("path"))

    revoked_cert = REVOKED_CERTIFICATE.match(line)
    if revoked_cert:
        yield LabelWarning("revoked_certificate", revoked_cert.group("path"))

    # Follow with more specific warnings

    expired_manifest = EXPIRED_MANIFEST_RE.match(line)
    if expired_manifest:
        expiry = expired_manifest.group("expiry")
        yield ExpirationWarning(
            "expired_manifest",
            expired_manifest.group("path"),
            datetime.strptime(expiry, "%b %d %H:%M:%S %Y GMT"),
        )

    # likely cause: A partial read, one object is updated while another
    # is not.
    bad_message_digest = BAD_MESSAGE_DIGEST_RE.match(line)
    if bad_message_digest:
        yield ManifestObjectWarning(
            "bad_message_digest",
            bad_message_digest.group("path"),
            bad_message_digest.group("object"),
        )


class OutputParser:
    """Parses rpki-client output."""

    lines: List[str]

    def __init__(self, stderr_output: str):
        self.lines = stderr_output.split("\n")

    @property
    def warnings(self) -> Generator[RPKIClientWarning, None, None]:
        for line in self.lines:
            # Catch exceptions when parsing lines
            try:
                yield from parse_maybe_warning_line(line)
            except (ValueError, IndexError) as e:
                LOG.info(f"Parse error in '{line}', {e}")

    @property
    def pulling(self) -> FrozenSet[str]:
        """The repositories a pull started from."""
        res = set()
        for line in self.lines:
            pulling = PULLING_RE.match(line)
            if pulling:
                res.add(pulling.group("uri"))

        return frozenset(res)

    @property
    def pulled(self) -> FrozenSet[str]:
        """The repositories pulled from."""
        res = set()
        for line in self.lines:
            pulling = PULLED_RE.match(line)
            if pulling:
                res.add(pulling.group("uri"))

        return frozenset(res)

    @property
    def fetch_status(self) -> Generator[FetchStatus, None, None]:
        """Get the fetch errors from the log."""
        for line in self.lines:
            try:
                fallback = RSYNC_FALLBACK.match(line)
                if fallback:
                    yield FetchStatus(fallback.group("uri"), "rrdp_rsync_fallback", 1)
                    continue
                load_failed = RSYNC_LOAD_FAILED.match(line)
                if load_failed:
                    yield FetchStatus(load_failed.group("uri"), "rsync_load_failed", 1)
                    continue
                not_modified = RSYNC_RRDP_NOT_MODIFIED.match(line)
                if not_modified:
                    yield FetchStatus(
                        not_modified.group("uri"), "rrdp_notification_not_modified", 1
                    )
                    continue
                snapshot = RSYNC_RRDP_SNAPSHOT.match(line)
                if snapshot:
                    yield FetchStatus(snapshot.group("uri"), "rrdp_snapshot", 1)
                    continue
                deltas = RSYNC_RRDP_DELTAS.match(line)
                if deltas:
                    yield FetchStatus(
                        deltas.group("uri"), "rrdp_delta", int(deltas.group("count"))
                    )
                    continue
            except Exception:
                LOG.exception("Exception while parsing lines.")

    @property
    def vanished_directories(self) -> FrozenSet[str]:
        """The vanished directories."""
        res = set()
        for line in self.lines:
            vanished_dir = VANISHED_DIRECTORY_RE.match(line)
            if vanished_dir:
                res.add(vanished_dir.group("path"))

        return res

    @property
    def vanished_files(self) -> FrozenSet[str]:
        """The vanished files."""
        res = set()
        for line in self.lines:
            vanished_file = VANISHED_FILE_RE.match(line)
            if vanished_file:
                res.add(vanished_file.group("path"))

        return res

    def statistics_by_host(self) -> List[WarningSummary]:
        """Group the output by host by type."""
        c = Counter(
            (warning.warning_type, parse_host(warning.uri)) for warning in self.warnings
        )

        return [
            WarningSummary(warning_type, host, count)
            for (warning_type, host), count in c.items()
        ]


def missing_labels(
    lhs: List[WarningSummary], rhs: List[WarningSummary]
) -> FrozenSet[MissingLabel]:
    """
    Gather the labels present in lhs that are not in rhs.

    Used to determine what labels are no longer present on the metrics.
    """
    left = frozenset(MissingLabel(w.warning_type, w.hostname) for w in lhs)
    right = frozenset(MissingLabel(w.warning_type, w.hostname) for w in rhs)

    return left - right
