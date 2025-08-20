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
from rpkiclientweb.util.misc import parse_proto_host_from_url

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
FILE_MFT_CRL_EXPIRED_RE = re.compile(r"rpki-client: (?P<path>.*): CRL has expired")
FILE_MFT_NOT_AVAILABLE_RE = re.compile(
    r"rpki-client: (?P<path>.*): no valid mft available"
)
FILE_MFT_FAILED_FETCH_RE = re.compile(
    r"rpki-client: (?P<path>.*): failed fetch, continuing with #[0-9]+"
)

FILE_MFT_UNEXPECTED_NUMBER_RE = re.compile(
    r"rpki-client: (?P<path>.*): unexpected manifest number.*"
)
FILE_MFT_MISISSUANCE_RECYCLED_RE = re.compile(
    r"rpki-client: (?P<path>.*): manifest misissuance, #[0-9]+ was recycled"
)
FILE_MFT_MISSING_CRL_RE = re.compile(
    r"rpki-client: (?P<path>.*): unable to get certificate CRL"
)
FILE_MFT_NOT_YET_VALID_RE = re.compile(
    r"rpki-client: (?P<path>.*): mft not yet valid (?P<expiry>.*)"
)
FILE_CMS_UNEXPECTED_SIGNED_ATTRIBUTE = re.compile(
    r"rpki-client: (?P<path>.*): RFC 6488: CMS has unexpected signed attribute "
    "(?P<attribute>.*)"
)
# Known cause: ASPA pre-profile 15 objects. Would be more idiomatic if rpki-client warned about the version.
FILE_ASPA_PARSE_FAILED = re.compile(
    r"rpki-client: (?P<path>[^:]+): ASPA: failed to parse ASProviderAttestation"
)
# TODO: Consider a more elegant way of filtering out TLS handshake errors
FILE_CERTIFICATE_EXPIRED = re.compile(
    r"rpki-client: (?P<path>[^:]+): certificate has expired"
)
FILE_CERTIFICATE_NOT_YET_VALID_RE = re.compile(
    r"rpki-client: (?P<path>[^:]+): certificate is not yet valid"
)
FILE_CERTIFICATE_REVOKED_RE = re.compile(
    r"rpki-client: (?P<path>[^:]+): certificate revoked"
)
FILE_CERTIFICATE_6487_DUPLICATE_SKI = re.compile(
    r"rpki-client: (?P<path>.*): RFC 6487: duplicate SKI"
)
FILE_CERTIFICATE_6487_UNCOVERED_IP = re.compile(
    r"rpki-client: (?P<path>.*): RFC 6487: uncovered IP:.+"
)
# Needs to be processed _after_ the other 6487 lines.
FILE_CERTIFICATE_6487_OTHER_ERROR = re.compile(
    r"rpki-client: (?P<path>.*): RFC 6487:.*"
)
FILE_CERTIFICATE_UNABLE_TO_GET_LOCAL_ISSUER = re.compile(
    r"rpki-client: (?P<path>.*): unable to get local issuer certificate"
)
FILE_BAD_UPDATE_INTERVAL_RE = re.compile(
    r"rpki-client: (?P<path>.*): bad update interval.*"
)
FILE_MISSING_FILE_RE = re.compile(
    r"rpki-client: (?P<path>.*): No such file or directory"
)
FILE_BOTH_POSSIBILITES_PRESENT = re.compile(
    r"rpki-client: (?P<path>.*): both possibilities of file present"
)
SYNC_RSYNC_LOAD_FAILED = re.compile(r"rpki-client: rsync (?P<uri>.*) failed$")
SYNC_RSYNC_FALLBACK = re.compile(
    r"rpki-client: (?P<uri>.*): load from network failed, fallback to rsync$"
)
SYNC_BAD_MESSAGE_DIGEST = re.compile(r"rpki-client: (?P<uri>.*): bad message digest")
SYNC_CACHE_FALLBACK = re.compile(
    r"rpki-client: (?P<uri>.*): load from network failed, fallback to cache$"
)
SYNC_HTTP_ERROR = re.compile(
    r"^rpki-client: Error retrieving (?P<uri>.+): (?P<http_status>[0-9]{3}).*$"
)
SYNC_RSYNC_RRDP_NOT_MODIFIED = re.compile(
    r"rpki-client: (?P<uri>.*): notification file not modified( \((?P<session>[\w-]+)#(?P<serial>[0-9]+)\))?$"
)
# connection refused/cannot assign requested address, likely only for RRDP.
SYNC_CONNECT_ERROR = re.compile(
    r"rpki-client: (?P<uri>[^ ]+)(?P<ip> \([0-9a-f:\.]+\))?: connect: .+$"
)
SYNC_CONNECT_TIMEOUT = re.compile(
    r"rpki-client: (?P<uri>[^ ]+)(?P<ip> \([0-9a-f:\.]+\))?: connect timeout$"
)
SYNC_SYNCHRONISATION_TIMEOUT = re.compile(
    r"rpki-client: (?P<uri>.+): synchronisation timeout$"
)
SYNC_RRDP_REPOSITORY_NOT_MODIFIED = re.compile(
    r"rpki-client: (?P<uri>.*): repository not modified$"
)
SYNC_RRDP_SNAPSHOT_FALLBACK = re.compile(
    r"^rpki-client: (?P<uri>.+): delta sync failed, fallback to snapshot$"
)

SYNC_RSYNC_RRDP_SNAPSHOT = re.compile(
    r"rpki-client: (?P<uri>.*): downloading snapshot( \((?P<session>[\w-]+)#(?P<serial>[0-9]+)\))?$"
)
SYNC_RSYNC_RRDP_DELTAS = re.compile(
    r"rpki-client: (?P<uri>.*): downloading (?P<count>\d+) deltas( \((?P<session>[\w-]+)#(?P<serial>[0-9]+)\))?$"
)

SYNC_RRDP_PARSE_ABORTED = re.compile(
    r"rpki-client: (?P<uri>.*): parse error at line [0-9]+: parsing aborted"
)
SYNC_RRDP_BAD_FILE_DIGEST = re.compile(
    r"rpki-client: (?P<uri>.*): bad file digest for .*"
)
"""The hash of a delta for a specific <serial, session> tuple does not match what was seen before."""
SYNC_RRDP_HASH_MUTATION = re.compile(
    r"rpki-client: (?P<uri>.*): [a-f0-9\-]+#(?P<serial>[0-9]+) unexpected delta mutation.*$"
)
"""
A RRDP <withdraw .../> was signaled from the RRDP server to the RRDP client for a URL but the file is still referenced.
https://github.com/openbsd/src/blob/fbeb52932c09e79e51eda25f2ad7008b9aba1099/usr.sbin/rpki-client/repo.c#L1570
"""
SYNC_RRDP_REFERENCED_FILE_DELETED = re.compile(
    r"rpki-client: (?P<uri>.*): referenced file supposed to be deleted"
)
SYNC_RRDP_SERIAL_DECREASED = re.compile(
    r"rpki-client: (?P<uri>.*): serial number decreased from "
    "(?P<previous>[0-9]+) to (?P<current>[0-9]+)"
)
SYNC_RRDP_TLS_CERTIFICATE_VERIFICATION_FAILED = re.compile(
    r"rpki-client: (?P<uri>[^ ]+)(?P<ip> \([0-9a-f:\.]+\))?: TLS handshake: certificate verification failed:.*"
)
SYNC_RRDP_TLS_FAILURE = re.compile(
    r"rpki-client: (?P<uri>[^ ]+)(?P<ip> \([0-9a-f:\.]+\))?: TLS read: read failed:.*"
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


def parse_maybe_warning_line(line: str) -> Generator[RPKIClientWarning, None, None]:
    """Parse a line for warnings - may be empty."""
    # LabelWarning (<type, file> tuples) first
    #
    # Basic cases and certificate validity
    for regex, warning_type in [
        (FILE_MISSING_FILE_RE, "missing_file"),
        (FILE_RESOURCE_OVERCLAIMING_RE, "overclaiming"),
        (FILE_CERTIFICATE_EXPIRED, "ee_certificate_expired"),
        (FILE_CERTIFICATE_NOT_YET_VALID_RE, "ee_certificate_not_yet_valid"),
        (FILE_CERTIFICATE_REVOKED_RE, "ee_certificate_revoked"),
        (
            FILE_CERTIFICATE_UNABLE_TO_GET_LOCAL_ISSUER,
            "unable_to_get_local_issuer_certificate",
        ),
        (FILE_CERTIFICATE_6487_DUPLICATE_SKI, "rfc6487_duplicate_ski"),
        (FILE_CERTIFICATE_6487_UNCOVERED_IP, "rfc6487_uncovered_ip"),
        (FILE_CERTIFICATE_6487_OTHER_ERROR, "rfc6487_unknown_error"),
        (FILE_BOTH_POSSIBILITES_PRESENT, "both_possibilities_file_present"),
        (FILE_MFT_NOT_AVAILABLE_RE, "no_valid_mft_available"),
        (FILE_MFT_CRL_EXPIRED_RE, "mft_crl_expired"),
        (FILE_MFT_FAILED_FETCH_RE, "mft_failed_fetch"),
        (FILE_MFT_UNEXPECTED_NUMBER_RE, "mft_unexpected_number"),
        (FILE_MFT_MISISSUANCE_RECYCLED_RE, "mft_misissuance_recycled"),
        (FILE_MFT_MISSING_CRL_RE, "mft_missing_crl"),
        (FILE_MISSING_SIA_RE, "missing_sia"),
        (FILE_CMS_UNEXPECTED_SIGNED_ATTRIBUTE, "unexpected_signed_cms_attribute"),
        (FILE_ASPA_PARSE_FAILED, "aspa_parse_failed"),
    ]:
        match = regex.match(line)
        if match:
            yield LabelWarning(warning_type, match.group("path"))
            return

    unsupported_filetype = FILE_UNSUPPORTED_FILETYPE_RE.match(line)
    if unsupported_filetype:
        yield ManifestObjectWarning(
            "unsupported_filetype",
            unsupported_filetype.group("path"),
            unsupported_filetype.group("object"),
        )
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


def parse_fetch_status(line: str) -> Generator[FetchStatus, None, None]:  # noqa: C901
    """Parse a line for a potential data fetching error."""
    # (rrdp) failures while connecting
    connect_error = SYNC_CONNECT_ERROR.match(line)
    if connect_error:
        yield FetchStatus(connect_error.group("uri"), "connect_error")
        return

    connect_timeout = SYNC_CONNECT_TIMEOUT.match(line)
    if connect_timeout:
        yield FetchStatus(connect_timeout.group("uri"), "connect_timeout")
        return

    tls_cert_verification = SYNC_RRDP_TLS_CERTIFICATE_VERIFICATION_FAILED.match(line)
    if tls_cert_verification:
        yield FetchStatus(
            tls_cert_verification.group("uri"),
            "rrdp_tls_certificate_verification_failed",
        )
        return

    tls_failure = SYNC_RRDP_TLS_FAILURE.match(line)
    if tls_failure:
        yield FetchStatus(tls_failure.group("uri"), "tls_failure")
        return

    synchronisation_timeout = SYNC_SYNCHRONISATION_TIMEOUT.match(line)
    if synchronisation_timeout:
        yield FetchStatus(
            synchronisation_timeout.group("uri"), "synchronisation_timeout"
        )
        return

    http_error = SYNC_HTTP_ERROR.match(line)
    if http_error:
        yield FetchStatus(
            parse_proto_host_from_url(http_error.group("uri")),
            f"http_{http_error.group('http_status')}",
        )
        return

    # RRDP content failures
    rrdp_parse_aborted = SYNC_RRDP_PARSE_ABORTED.match(line)
    if rrdp_parse_aborted:
        yield FetchStatus(rrdp_parse_aborted.group("uri"), "rrdp_parse_aborted")
        return

    rrdp_content_too_big = SYNC_RRDP_CONTENT_TOO_BIG.match(line)
    if rrdp_content_too_big:
        yield FetchStatus("<unknown>", "rrdp_parse_error_file_too_big")
        return

    bad_message_digest = SYNC_BAD_MESSAGE_DIGEST.match(line)
    if bad_message_digest:
        yield FetchStatus(bad_message_digest.group("uri"), "bad_message_digest")
        return

    rrdp_hash_mutation = SYNC_RRDP_HASH_MUTATION.match(line)
    if rrdp_hash_mutation:
        yield FetchStatus(
            rrdp_hash_mutation.group("uri"), "rrdp_delta_hash_mutation", 1
        )
        return

    rrdp_referenced_file_deleted = SYNC_RRDP_REFERENCED_FILE_DELETED.match(line)
    if rrdp_referenced_file_deleted:
        yield FetchStatus(
            rrdp_referenced_file_deleted.group("uri"), "rrdp_referenced_file_deleted"
        )
        return

    file_bad_message_digest = SYNC_RRDP_BAD_FILE_DIGEST.match(line)
    if file_bad_message_digest:
        yield FetchStatus(file_bad_message_digest.group("uri"), "sync_bad_file_digest")
        return

    snapshot_fallback = SYNC_RRDP_SNAPSHOT_FALLBACK.match(line)
    if snapshot_fallback:
        yield FetchStatus(snapshot_fallback.group("uri"), "rrdp_snapshot_fallback")
        return

    # RRDP: regular updates
    not_modified = SYNC_RSYNC_RRDP_NOT_MODIFIED.match(line)
    if not_modified:
        yield FetchStatus(not_modified.group("uri"), "rrdp_notification_not_modified")
        return
    repository_not_modified = SYNC_RRDP_REPOSITORY_NOT_MODIFIED.match(line)
    if repository_not_modified:
        yield FetchStatus(
            repository_not_modified.group("uri"), "rrdp_repository_not_modified"
        )
        return
    snapshot = SYNC_RSYNC_RRDP_SNAPSHOT.match(line)
    if snapshot:
        yield FetchStatus(snapshot.group("uri"), "rrdp_snapshot")
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

    # Messages about behaviour/fallback
    fallback = SYNC_RSYNC_FALLBACK.match(line)
    if fallback:
        yield FetchStatus(fallback.group("uri"), "rrdp_rsync_fallback")
        return

    cache_fallback = SYNC_CACHE_FALLBACK.match(line)
    if cache_fallback:
        yield FetchStatus(cache_fallback.group("uri"), "sync_fallback_to_cache")
        return

    load_failed = SYNC_RSYNC_LOAD_FAILED.match(line)
    if load_failed:
        yield FetchStatus(load_failed.group("uri"), "rsync_load_failed")
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
