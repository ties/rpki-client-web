import re
import urllib.parse
from collections import Counter
from datetime import datetime
from typing import FrozenSet, Generator, List, NamedTuple, Union

BAD_MESSAGE_DIGEST_RE = re.compile(
    r"rpki-client: (?P<uri>.*): bad message digest for (?P<object>.*)"
)
EXPIRED_MANIFEST_RE = re.compile(
    r"rpki-client: (?P<uri>.*): mft expired on (?P<expiry>.*)"
)
FILES_REMOVED = re.compile(r"rpki-client: Files removed: (?P<files_removed>[0-9]+)")
MISSING_FILE_RE = re.compile(r"rpki-client: (?P<uri>.*): No such file or directory")
PULLING_RE = re.compile(r"rpki-client: (?P<uri>.*): pulling from network")
PULLED_RE = re.compile(r"rpki-client: (?P<uri>.*): loaded from network")
RESOURCE_OVERCLAIMING = re.compile(
    r"rpki-client: (?P<uri>.*): RFC 3779 resource not subset of parent's resources"
)
REVOKED_CERTIFICATE = re.compile(r"rpki-client: (?P<uri>.*): certificate revoked")
VANISHED_FILE_RE = re.compile(r"file has vanished: \"(?P<path>.*)\" \(in repo\)")
VANISHED_DIRECTORY_RE = re.compile(r"directory has vanished: \"(?P<path>.*)\" \(in repo\)")


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


class OutputParser:
    """Parses rpki-client output."""

    lines: List[str]

    def __init__(self, stderr_output: str):
        self.lines = stderr_output.split("\n")

    @property
    def warnings(self) -> Generator[RPKIClientWarning, None, None]:
        for line in self.lines:
            # LabelWarning (<type, file> tuples) first
            missing_file = MISSING_FILE_RE.match(line)
            if missing_file:
                yield LabelWarning("missing_file", missing_file.group("uri"))
                continue

            overclaiming = RESOURCE_OVERCLAIMING.match(line)
            if overclaiming:
                yield LabelWarning("overclaiming", overclaiming.group("uri"))
                continue

            revoked_cert = REVOKED_CERTIFICATE.match(line)
            if revoked_cert:
                yield LabelWarning("revoked_certificate", revoked_cert.group("uri"))
                continue

            # Follow with more specific warnings

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

    @property
    def files_removed(self) -> int:
        """Number of files removed during rpki-client run"""
        for line in self.lines:
            removed = FILES_REMOVED.match(line)
            if removed:
                return int(removed.group("files_removed"))

        return 0

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
