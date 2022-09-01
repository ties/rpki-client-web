import logging
import re
from collections import Counter
from typing import FrozenSet, Generator, List

from rpkiclientweb.metrics import RPKI_CLIENT_WEB_PARSE_ERROR
from rpkiclientweb.models import (
    ExpirationWarning,
    FetchStatus,
    LabelWarning,
    ManifestObjectWarning,
    MissingLabel,
    RPKIClientWarning,
    WarningSummary,
)
from rpkiclientweb.parsing import parse_fetch_status, parse_maybe_warning_line
from rpkiclientweb.util import parse_host

LOG = logging.getLogger(__name__)


PULLING_RE = re.compile(r"rpki-client: (?P<uri>.*): pulling from network")
PULLED_RE = re.compile(r"rpki-client: (?P<uri>.*): loaded from network")

VANISHED_FILE_RE = re.compile(r"file has vanished: \"(?P<path>.*)\" \(in repo\)")
VANISHED_DIRECTORY_RE = re.compile(
    r"directory has vanished: \"(?P<path>.*)\" \(in repo\)"
)

#
# Keep in mind that `rpki-client:` can be written from multiple processes
# (without flush) so any message that starts with a capture group needs to
# reject those 'intertwined' lines (e.g. use `(?!rpki-client:)`).
#
# The lines are like:
# `rpki-client: rpki-client: https://cc.rg.net/rrdp/notify.xml: downloading 1 deltas`
#
INTERTWINED_LINE_RE = re.compile(r"^rpki-client: .*rpki-client: .*$")


class OutputParser:
    """Parses rpki-client output."""

    lines: List[str]

    def __init__(self, stderr_output: str):
        """Skip unparseable intertwined lines."""
        self.lines = [
            line
            for line in stderr_output.split("\n")
            if not INTERTWINED_LINE_RE.match(line)
        ]

    @property
    def warnings(self) -> Generator[RPKIClientWarning, None, None]:
        for line in self.lines:
            # Catch exceptions when parsing lines
            try:
                yield from parse_maybe_warning_line(line)
            except (ValueError, IndexError) as e:
                LOG.info("Parse error in '%s', %s", line, e)
                RPKI_CLIENT_WEB_PARSE_ERROR.labels(type="parse_warnings").inc()

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
                yield from parse_fetch_status(line)
            except Exception:
                LOG.exception("Exception while parsing lines.")
                RPKI_CLIENT_WEB_PARSE_ERROR.labels(type="parse_fetch_status").inc()

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
