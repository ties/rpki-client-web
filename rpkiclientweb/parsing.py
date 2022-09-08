import re
from datetime import datetime
from typing import Generator

from rpkiclientweb.models import (
    ExpirationWarning,
    FetchStatus,
    LabelWarning,
    ManifestObjectWarning,
    RpkiClientError,
    RPKIClientWarning,
)

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
FILE_MFT_EXPIRED_RE = re.compile(
    r"rpki-client: (?P<path>.*): mft expired on (?P<expiry>.*)"
)
FILE_MFT_NOT_AVAILABLE_RE = re.compile(
    r"rpki-client: (?P<path>.*): no valid mft available"
)
FILE_MFT_NOT_YET_VALID_RE = re.compile(
    r"rpki-client: (?P<path>.*): mft not yet valid (?P<expiry>.*)"
)
# TODO: Consider a more elegant way of filtering out TLS handshake errors
FILE_CERTIFICATE_EXPIRED = re.compile(
    r"rpki-client: (?P<path>(?!TLS handshake:).+): certificate has expired"
)
FILE_CERTIFICATE_NOT_YET_VALID_RE = re.compile(
    r"rpki-client: (?P<path>(?!TLS handshake:).+): certificate is not yet valid"
)
FILE_CERTIFICATE_REVOKED_RE = re.compile(
    r"rpki-client: (?P<path>(?!TLS handshake:).+): certificate revoked"
)
FILE_BAD_UPDATE_INTERVAL_RE = re.compile(
    r"rpki-client: (?P<path>.*): bad update interval.*"
)
FILE_MISSING_FILE_RE = re.compile(
    r"rpki-client: (?P<path>.*): No such file or directory"
)

SYNC_RSYNC_LOAD_FAILED = re.compile(r"rpki-client: rsync (?P<uri>.*) failed$")
SYNC_RSYNC_FALLBACK = re.compile(
    r"rpki-client: (?P<uri>.*): load from network failed, fallback to rsync$"
)
SYNC_BAD_MESSAGE_DIGEST = re.compile(r"rpki-client: (?P<uri>.*): bad message digest")
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
SYNC_RRDP_BAD_FILE_DIGEST = re.compile(
    r"rpki-client: (?P<uri>.*): bad file digest for .*"
)
SYNC_RRDP_SERIAL_DECREASED = re.compile(
    r"rpki-client: (?P<uri>.*): serial number decreased from (?P<previous>[0-9]+) to (?P<current>[0-9]+)"
)
SYNC_RRDP_TLS_CERTIFICATE_VERIFICATION_FAILED = re.compile(
    r"rpki-client: (?P<uri>.*): TLS handshake: certificate verification failed:.*"
)
SYNC_RRDP_TLS_FAILURE = re.compile(
    r"rpki-client: (?P<uri>.*): TLS read: read failed:.*"
)
SYNC_RRDP_CONTENT_TOO_BIG = re.compile(r"rpki-client: parse failed - content too big")

FILE_MISSING_SIA_RE = re.compile(
    r"rpki-client: (?P<path>.*): RFC 6487 section 4.8.8: missing SIA"
)
FILE_RESOURCE_OVERCLAIMING_RE = re.compile(
    r"rpki-client: (?P<path>.*): RFC 3779 resource not subset of parent's resources"
)
#
# Error states hit by rpki-client
#
RPKI_CLIENT_ASSERTION_FAILED = re.compile(
    r"rpki-client: .*\.c:[0-9]+: .*Assertion.*failed."
)

RPKI_CLIENT_TERMINATED = re.compile(r"rpki-client: (?P<module>.*) terminated signal .*")

RPKI_CLIENT_NOT_ALL_FILES = re.compile(
    r"rpki-client: not all files processed, giving up"
)


def parse_maybe_warning_line(line) -> Generator[RPKIClientWarning, None, None]:
    """Parse a line for warnings - may be empty."""
    # LabelWarning (<type, file> tuples) first
    missing_file = FILE_MISSING_FILE_RE.match(line)
    if missing_file:
        yield LabelWarning("missing_file", missing_file.group("path"))
        return

    overclaiming = FILE_RESOURCE_OVERCLAIMING_RE.match(line)
    if overclaiming:
        yield LabelWarning("overclaiming", overclaiming.group("path"))
        return

    cert_expired = FILE_CERTIFICATE_EXPIRED.match(line)
    if cert_expired:
        yield LabelWarning("ee_certificate_expired", cert_expired.group("path"))
        return

    cert_not_yet_valid = FILE_CERTIFICATE_NOT_YET_VALID_RE.match(line)
    if cert_not_yet_valid:
        yield LabelWarning(
            "ee_certificate_not_yet_valid", cert_not_yet_valid.group("path")
        )
        return

    cert_revoked = FILE_CERTIFICATE_REVOKED_RE.match(line)
    if cert_revoked:
        yield LabelWarning("ee_certificate_revoked", cert_revoked.group("path"))
        return

    unsupported_filetype = FILE_UNSUPPORTED_FILETYPE_RE.match(line)
    if unsupported_filetype:
        yield ManifestObjectWarning(
            "unsupported_filetype",
            unsupported_filetype.group("path"),
            unsupported_filetype.group("object"),
        )
        return

    no_valid_mft = FILE_MFT_NOT_AVAILABLE_RE.match(line)
    if no_valid_mft:
        yield LabelWarning("no_valid_mft_available", no_valid_mft.group("path"))
        return

    missing_sia = FILE_MISSING_SIA_RE.match(line)
    if missing_sia:
        yield LabelWarning("missing_sia", missing_sia.group("path"))
        return

    # manifest time-related checks
    bad_update_interval = FILE_BAD_UPDATE_INTERVAL_RE.match(line)
    if bad_update_interval:
        yield LabelWarning(
            "bad_manifest_update_interval", bad_update_interval.group("path")
        )
        return

    expired_manifest = FILE_MFT_EXPIRED_RE.match(line)
    if expired_manifest:
        expiry = expired_manifest.group("expiry")
        yield ExpirationWarning(
            "expired_manifest",
            expired_manifest.group("path"),
            datetime.strptime(expiry, "%b %d %H:%M:%S %Y GMT"),
        )
        return

    not_yet_valid_manifest = FILE_MFT_NOT_YET_VALID_RE.match(line)
    if not_yet_valid_manifest:
        expiry = not_yet_valid_manifest.group("expiry")
        yield ExpirationWarning(
            "not_yet_valid_manifest",
            not_yet_valid_manifest.group("path"),
            datetime.strptime(expiry, "%b %d %H:%M:%S %Y GMT"),
        )
        return

    # likely cause: A partial read, one object is updated while another
    # is not.
    bad_message_digest = FILE_BAD_MESSAGE_DIGEST_RE.match(line)
    if bad_message_digest:
        yield ManifestObjectWarning(
            "bad_message_digest",
            bad_message_digest.group("path"),
            bad_message_digest.group("object"),
        )
        return


def parse_fetch_status(line: str) -> Generator[FetchStatus, None, None]:
    tls_cert_verification = SYNC_RRDP_TLS_CERTIFICATE_VERIFICATION_FAILED.match(line)
    if tls_cert_verification:
        yield FetchStatus(
            tls_cert_verification.group("uri"),
            "rrdp_tls_certificate_verification_failed",
        )
        return

    # Generic tls failure
    tls_failure = SYNC_RRDP_TLS_FAILURE.match(line)
    if tls_failure:
        yield FetchStatus(
            tls_failure.group("uri"),
            "tls_failure",
        )
        return

    rrdp_parse_aborted = SYNC_RRDP_PARSE_ABORTED.match(line)
    if rrdp_parse_aborted:
        yield FetchStatus(rrdp_parse_aborted.group("uri"), "rrdp_parse_aborted")
        return

    rrdp_content_too_big = SYNC_RRDP_CONTENT_TOO_BIG.match(line)
    if rrdp_content_too_big:
        yield FetchStatus("<unknown>", "rrdp_parse_error_file_too_big")
        return

    fallback = SYNC_RSYNC_FALLBACK.match(line)
    if fallback:
        yield FetchStatus(fallback.group("uri"), "rrdp_rsync_fallback", 1)
        return

    cache_fallback = SYNC_CACHE_FALLBACK.match(line)
    if cache_fallback:
        yield FetchStatus(cache_fallback.group("uri"), "sync_fallback_to_cache")
        return

    bad_message_digest = SYNC_BAD_MESSAGE_DIGEST.match(line)
    if bad_message_digest:
        yield FetchStatus(bad_message_digest.group("uri"), "bad_message_digest")
        return

    file_bad_message_digest = SYNC_RRDP_BAD_FILE_DIGEST.match(line)
    if file_bad_message_digest:
        yield FetchStatus(
            file_bad_message_digest.group("uri"), "sync_bad_message_digest"
        )
        return

    load_failed = SYNC_RSYNC_LOAD_FAILED.match(line)
    if load_failed:
        yield FetchStatus(load_failed.group("uri"), "rsync_load_failed", 1)
        return

    not_modified = SYNC_RSYNC_RRDP_NOT_MODIFIED.match(line)
    if not_modified:
        yield FetchStatus(
            not_modified.group("uri"), "rrdp_notification_not_modified", 1
        )
        return
    repository_not_modified = SYNC_RRDP_REPOSITORY_NOT_MODIFIED.match(line)
    if repository_not_modified:
        yield FetchStatus(
            repository_not_modified.group("uri"), "rrdp_repository_not_modified", 1
        )
        return
    snapshot = SYNC_RSYNC_RRDP_SNAPSHOT.match(line)
    if snapshot:
        yield FetchStatus(snapshot.group("uri"), "rrdp_snapshot", 1)
        return
    deltas = SYNC_RSYNC_RRDP_DELTAS.match(line)
    if deltas:
        yield FetchStatus(deltas.group("uri"), "rrdp_delta", int(deltas.group("count")))
        return
    serial_decreased = SYNC_RRDP_SERIAL_DECREASED.match(line)
    if serial_decreased:
        delta = int(serial_decreased.group("previous")) - int(
            serial_decreased.group("current")
        )

        yield FetchStatus(serial_decreased.group("uri"), "rrdp_serial_decreased", delta)
        return


def parse_rpki_client_error(line) -> Generator[RpkiClientError, None, None]:
    """Errors output by rpki-client."""
    assertion_failed = RPKI_CLIENT_ASSERTION_FAILED.match(line)
    if assertion_failed:
        yield RpkiClientError("assertion_failed")
        return

    not_all_files = RPKI_CLIENT_NOT_ALL_FILES.match(line)
    if not_all_files:
        yield RpkiClientError("not_all_files_processed")
        return

    terminated = RPKI_CLIENT_TERMINATED.match(line)
    if terminated:
        yield RpkiClientError(f"{terminated.group('module')}_terminated")
        return
