from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class FetchStatus:
    """
    rpki-client fetch status for a repo.

    Can be both positive or negative.
    """

    uri: str
    type: str
    count: int = 1


@dataclass(frozen=True)
class LabelWarning:
    """rpki-client warning about a file."""

    warning_type: str
    uri: str


@dataclass(frozen=True)
class ExpirationWarning:
    """rpki-client warning about an expiration."""

    warning_type: str
    uri: str
    expiration: datetime


@dataclass(frozen=True)
class ManifestObjectWarning:
    """rpki-client warning about a file on a manifest."""

    warning_type: str
    uri: str
    object_name: str


@dataclass(frozen=True)
class MissingLabel:
    """A missing label."""

    warning_type: str
    hostname: str


@dataclass(frozen=True)
class WarningSummary:
    """Summary of warnings of a type for a host."""

    warning_type: str
    hostname: str
    count: int


@dataclass(frozen=True)
class RpkiClientError:
    """Error messages from rpki-client."""

    warning_type: str


RPKIClientWarning = LabelWarning | ExpirationWarning | ManifestObjectWarning
