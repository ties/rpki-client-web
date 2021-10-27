from datetime import datetime
from typing import NamedTuple, Union


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
