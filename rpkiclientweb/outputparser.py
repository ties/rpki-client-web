import logging
import re
from collections import Counter
from datetime import datetime
from typing import FrozenSet, Generator, List

from rpkiclientweb.metrics import RPKI_CLIENT_WEB_PARSE_ERROR
from rpkiclientweb.models import (FetchStatus, LabelWarning, ExpirationWarning, ManifestObjectWarning, WarningSummary, MissingLabel, RPKIClientWarning)
from rpkiclientweb.util import parse_host

LOG = logging.getLogger(__name__)

#
# Regular expressions matching log lines.
# for manifest warnings: https://github.com/rpki-client/rpki-client-openbsd/blob/5c54a1817a8e31c3ce857d6fe04bdd0fc35691b6/src/usr.sbin/rpki-client/filemode.c
#
FILE_BAD_MESSAGE_DIGEST_RE = re.compile(
    r"rpki-client: (?P<path>.*): bad message digest for (?P<object>.*)"
)
FILE_UNSUPPORTED_FILETYPE_RE = re.compile(
    r"rpki-client: (?P<path>.*): unsupported file type for (?P<object>.*)"
)
FILE_EXPIRED_MANIFEST_RE = re.compile(
    r"rpki-client: (?P<path>.*): mft expired on (?P<expiry>.*)"
)
FILE_NO_MANIFEST_AVAILABLE_RE = re.compile(
    r"rpki-client: (?P<path>.*): no valid mft available"
)
FILE_NOT_YET_VALID_RE = re.compile(
    r"rpki-client: (?P<path>.*): mft not yet valid (?P<expiry>.*)"
)
FILE_BAD_UPDATE_INTERVAL_RE = re.compile(
    r"rpki-client: (?P<path>.*): bad update interval.*"
)
FILE_MISSING_FILE_RE = re.compile(r"rpki-client: (?P<path>.*): No such file or directory")

PULLING_RE = re.compile(r"rpki-client: (?P<uri>.*): pulling from network")
PULLED_RE = re.compile(r"rpki-client: (?P<uri>.*): loaded from network")

SYNC_RSYNC_LOAD_FAILED = re.compile(r"rpki-client: rsync (?P<uri>.*) failed$")
SYNC_RSYNC_FALLBACK = re.compile(
    r"rpki-client: (?P<uri>.*): load from network failed, fallback to rsync$"
)
SYNC_CACHE_FALLBACK = re.compile(
    r"rpki-client: (?P<uri>.*): load from network failed, fallback to cache$"
)

SYNC_RSYNC_RRDP_NOT_MODIFIED = re.compile(
    r"rpki-client: (?P<uri>.*): notification file not modified$"
)
SYNC_RRDP_REPOSITORY_NOT_MODIFIED = re.compile(
    r"rpki-client: (?P<uri>.*): repository not modified$"
)

SYNC_RSYNC_RRDP_SNAPSHOT = re.compile(
    r"rpki-client: (?P<uri>.*): downloading snapshot$"
)
SYNC_RSYNC_RRDP_DELTAS = re.compile(
    r"rpki-client: (?P<uri>.*): downloading (?P<count>\d+) deltas$"
)
SYNC_RRDP_PARSE_ABORTED = re.compile(
    r"rpki-client: (?P<uri>.*): parse error at line [0-9]+: parsing aborted"
)
SYNC_RRDP_SERIAL_DECREASED = re.compile(
    r"rpki-client: (?P<uri>.*): serial number decreased from (?P<previous>[0-9]+) to (?P<current>[0-9]+)"
)
SYNC_RRDP_TLS_CERTIFICATE_VERIFICATION_FAILED = re.compile(
    r"rpki-client: (?P<uri>.*): TLS handshake: certificate verification failed:.*"
)
SYNC_RRDP_CONTENT_TOO_BIG = re.compile(r"rpki-client: parse failed - content too big")

FILE_MISSING_SIA_RE = re.compile(
    r"rpki-client: (?P<path>.*): RFC 6487 section 4.8.8: missing SIA"
)
FILE_RESOURCE_OVERCLAIMING_RE = re.compile(
    r"rpki-client: (?P<path>.*): RFC 3779 resource not subset of parent's resources"
)
FILE_REVOKED_CERTIFICATE_RE = re.compile(
    r"rpki-client: (?P<path>.*): certificate revoked"
)

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


def parse_maybe_warning_line(line) -> Generator[RPKIClientWarning, None, None]:
    """Parse a line for warnings - may be empty."""
    # LabelWarning (<type, file> tuples) first
    missing_file = FILE_MISSING_FILE_RE.match(line)
    if missing_file:
        yield LabelWarning("missing_file", missing_file.group("path"))

    overclaiming = FILE_RESOURCE_OVERCLAIMING_RE.match(line)
    if overclaiming:
        yield LabelWarning("overclaiming", overclaiming.group("path"))

    revoked_cert = FILE_REVOKED_CERTIFICATE_RE.match(line)
    if revoked_cert:
        yield LabelWarning("revoked_certificate", revoked_cert.group("path"))

    unsupported_filetype = FILE_UNSUPPORTED_FILETYPE_RE.match(line)
    if unsupported_filetype:
        yield ManifestObjectWarning("unsupported_filetype", unsupported_filetype.group("path"), unsupported_filetype.group("object"))


    no_valid_mft = FILE_NO_MANIFEST_AVAILABLE_RE.match(line)
    if no_valid_mft:
        yield LabelWarning("no_valid_mft_available", no_valid_mft.group("path"))

    missing_sia = FILE_MISSING_SIA_RE.match(line)
    if missing_sia:
        yield LabelWarning("missing_sia", missing_sia.group("path"))

    # manifest time-related checks
    bad_update_interval = FILE_BAD_UPDATE_INTERVAL_RE.match(line)
    if bad_update_interval:
        yield Labelwarning(
            "bad_manifest_update_interval",
            bad_message_digest.group("path")
        )

    expired_manifest = FILE_EXPIRED_MANIFEST_RE.match(line)
    if expired_manifest:
        expiry = expired_manifest.group("expiry")
        yield ExpirationWarning(
            "expired_manifest",
            expired_manifest.group("path"),
            datetime.strptime(expiry, "%b %d %H:%M:%S %Y GMT"),
        )
    not_yet_valid_manifest = FILE_NOT_YET_VALID_RE.match(line)
    if not_yet_valid_manifest:
        expiry = not_yet_valid_manifest.group("expiry")
        yield ExpirationWarning(
            "not_yet_valid_manifest",
            expired_manifest.group("path"),
            datetime.strptime(expiry, "%b %d %H:%M:%S %Y GMT"),
        )

    # likely cause: A partial read, one object is updated while another
    # is not.
    bad_message_digest = FILE_BAD_MESSAGE_DIGEST_RE.match(line)
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
                tls_cert_verification = (
                    SYNC_RRDP_TLS_CERTIFICATE_VERIFICATION_FAILED.match(line)
                )
                if tls_cert_verification:
                    yield FetchStatus(
                        tls_cert_verification.group("uri"),
                        "rrdp_tls_certificate_verification_failed",
                    )
                    continue

                rrdp_parse_aborted = SYNC_RRDP_PARSE_ABORTED.match(line)
                if rrdp_parse_aborted:
                    yield FetchStatus(
                        rrdp_parse_aborted.group("uri"), "rrdp_parse_aborted"
                    )
                    continue
                rrdp_content_too_big = SYNC_RRDP_CONTENT_TOO_BIG.match(line)
                if rrdp_content_too_big:
                    yield FetchStatus("<unknown>", "rrdp_parse_error_file_too_big")
                    continue

                fallback = SYNC_RSYNC_FALLBACK.match(line)
                if fallback:
                    yield FetchStatus(fallback.group("uri"), "rrdp_rsync_fallback", 1)
                    continue

                cache_fallback = SYNC_CACHE_FALLBACK.match(line)
                if cache_fallback:
                    yield FetchStatus(
                        cache_fallback.group("uri"), "sync_fallback_to_cache"
                    )
                    continue

                load_failed = SYNC_RSYNC_LOAD_FAILED.match(line)
                if load_failed:
                    yield FetchStatus(load_failed.group("uri"), "rsync_load_failed", 1)
                    continue
                not_modified = SYNC_RSYNC_RRDP_NOT_MODIFIED.match(line)
                if not_modified:
                    yield FetchStatus(
                        not_modified.group("uri"), "rrdp_notification_not_modified", 1
                    )
                    continue
                repository_not_modified = SYNC_RRDP_REPOSITORY_NOT_MODIFIED.match(line)
                if repository_not_modified:
                    yield FetchStatus(
                        repository_not_modified.group("uri"), "rrdp_repository_not_modified", 1
                    )
                    continue
                snapshot = SYNC_RSYNC_RRDP_SNAPSHOT.match(line)
                if snapshot:
                    yield FetchStatus(snapshot.group("uri"), "rrdp_snapshot", 1)
                    continue
                deltas = SYNC_RSYNC_RRDP_DELTAS.match(line)
                if deltas:
                    yield FetchStatus(
                        deltas.group("uri"), "rrdp_delta", int(deltas.group("count"))
                    )
                    continue
                serial_decreased = SYNC_RRDP_SERIAL_DECREASED.match(line)
                if serial_decreased:
                    delta = int(serial_decreased.group("previous")) - int(serial_decreased.group("current"))

                    yield FetchStatus(
                        serial_decreased.group("uri"), "rrdp_serial_decreased", delta
                    )
                    continue
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
