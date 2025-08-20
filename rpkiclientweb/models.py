from dataclasses import dataclass
from datetime import datetime
from typing import NamedTuple, Union


@dataclass
class FetchStatus:
    """
    rpki-client fetch status for a repo.

    Can be both positive or negative.
    """

    uri: str
    type: str
    count: int = 1

    def __post_init__(self):
        # Strip leading .rsync/ from the URI if present
        if self.uri.startswith(".rsync/"):
            self.uri = "rsync://" + self.uri[7:]


class LabelWarning(NamedTuple):
    """rpki-client warning about a file."""

    warning_type: str
    uri: str


class ExpirationWarning(NamedTuple):
    """rpki-client warning about an expiration."""

    warning_type: str
    uri: str
    expiration: datetime


@dataclass
class ManifestObjectWarning:
    """rpki-client warning about a file on a manifest."""

    warning_type: str
    uri: str
    object_name: str

    def __post_init__(self):
        # Strip leading .rsync/ from the URI if present
        if self.uri.startswith(".rsync/"):
            self.uri = self.uri[7:]

        # Remove everything after the '#' if present
        if "#" in self.uri:
            self.uri = self.uri.split("#")[0]


class MissingLabel(NamedTuple):
    """A missing label."""

    warning_type: str
    hostname: str


class WarningSummary(NamedTuple):
    """Summary of warnings of a type for a host."""

    warning_type: str
    hostname: str
    count: int


class RpkiClientError(NamedTuple):
    """Error messages from rpki-client."""

    warning_type: str


RPKIClientWarning = Union[LabelWarning, ExpirationWarning, ManifestObjectWarning]
