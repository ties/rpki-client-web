import datetime
import json
import logging
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, TextIO

from prometheus_client.openmetrics.parser import text_string_to_metric_families

from rpkiclientweb.metrics import (
    RPKI_CLIENT_JSON_ERROR,
    RPKI_OBJECTS_BUILD_TIME,
    RPKI_OBJECTS_COUNT,
    RPKI_OBJECTS_MIN_EXPIRY,
    RPKI_OBJECTS_VRPS_BY_TA,
)

from .util.prometheus import ListCollector

LOG = logging.getLogger(__name__)

__all__ = ["JSONOutputParser", "OpenmetricsOutputParser"]

#
# Authoratitive source for what labels exist:
# http://cvsweb.openbsd.org/cgi-bin/cvsweb/~checkout~/src/usr.sbin/rpki-client/output-json.c
#

BUILDTIME_KEY = "buildtime"
METADATA_LABELS = (
    # ignore "buildmachine"
    "buildtime",
    "elapsedtime",
    "usertime",
    "systemtime",
    "roas",
    "failedroas",
    "invalidroas",
    "bgpsec_router_keys",
    "invalidbgpsec_router_keys",
    "bgpsec_pubkeys",
    "certificates",
    "failcertificates",
    "invalidcertificates",
    "tals",
    # ignore "talfiles" strings
    "manifests",
    "failedmanifests",
    "stalemanifests",
    "crls",
    "gbrs",
    "repositories",
    "vrps",
    "uniquevrps",
    "cachedir_del_files",
    "cachedir_superfluous_files",
    "cachedir_del_dirs",
)
OPTIONAL_METADATA_LABELS = frozenset(
    [
        # recent attributes (2023-05-03, 8.4)
        "aspas",
        "failedaspas",
        "invalidaspas",
        "taks",
        "invalidtals",
        "vaps",
        "uniquevaps",
        # recent attribute (2022-03-11)
        "bgpsec_pubkeys",
        "failedroas",
        "invalidroas",
        "failcertificates",
        "invalidcertificates",
        "stalemanifests",
        # not present on 7.3 on fedora:
        "bgpsec_router_keys",
        "invalidbgpsec_router_keys",
        "gbrs",
        "cachedir_del_files",
        "cachedir_del_dirs",
        # recent attribute (2022-03-11)
        "cachedir_superfluous_files",
    ]
)


class OpenmetricsOutputParser:
    """Parse, validate, and collect the rpki-client openmetrics output."""

    collector: ListCollector

    def __init__(self) -> None:
        self.collector = ListCollector()

    def parse(self, metrics_path: Path) -> None:
        """Parse the metrics and update the collector"""
        with metrics_path.open("r") as f:
            self.collector.update(text_string_to_metric_families(f.read()))


class JSONOutputParser:
    """Parse and implicitly validate the rpki-client JSON output."""

    def parse(self, json_io: TextIO) -> None:
        """Parse rpki-client JSON output."""
        try:
            data = json.load(json_io)
        except json.decoder.JSONDecodeError as err:
            LOG.error("Error while parsing JSON in %s: %s", json_io.name, str(err))
            RPKI_CLIENT_JSON_ERROR.inc()
            return

        # {
        #   metadata: {...},
        #   roas: [...],
        #   bgpsec_keys: [...],
        #   provider_authorizations: {
        #     "ipv4": [...],
        #     "ipv6": [...]
        #   }
        # }
        roas = data.get("roas", [])
        bgpsec_keys = data.get("bgpsec_keys", [])
        vaps = data.get("provider_authorizations", {"ipv4": [], "ipv6": []})

        self.update_object_expiry(roas, bgpsec_keys, vaps["ipv4"], vaps["ipv6"])

        metadata = data["metadata"]
        missing_keys = set()

        for key in METADATA_LABELS:
            value = metadata.get(key, None)

            if key == BUILDTIME_KEY and value is not None:
                # format from
                # https://github.com/rpki-client/rpki-client-openbsd/blob/92e173c2a0accb425e1130192655d1b57928d986/src/usr.sbin/rpki-client/output-json.c#L36
                buildtime = datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
                RPKI_OBJECTS_BUILD_TIME.set(buildtime.timestamp())
            elif value is not None:
                RPKI_OBJECTS_COUNT.labels(type=key).set(value)
            elif key not in OPTIONAL_METADATA_LABELS:
                missing_keys.add(key)

        if missing_keys:
            LOG.info(
                "keys (%s) missing in json .metadata (%s)",
                ", ".join(missing_keys),
                json.dumps(metadata),
            )

    # TODO: Update to TypedDict when only supporting 3.8+
    def update_object_expiry(
        self,
        roas: List[Dict],
        bgpsec_keys: List[Dict],
        vaps_v4: List[Dict],
        vaps_v6: List[Dict],
    ) -> None:
        """Update the object expiry metrics."""
        # roas may not be sorted by ta. Using `itertools.groupby` would require
        # a sort - so just do this in code.
        # ta name -> timestamp
        min_expires_by_ta: Dict[str, int] = {}
        # deprecated in May 2023
        vrps_by_ta: Dict[str, int] = Counter()

        def update_expires(obj: Dict) -> None:
            expires = obj.get("expires", None)
            ta = obj.get("ta", None)
            if (expires is not None) and (ta is not None):
                # take expires when not found, otherwise, min value.
                min_expires_by_ta[ta] = min(min_expires_by_ta.get(ta, expires), expires)

        for brk in bgpsec_keys:
            update_expires(brk)

        for vap in vaps_v4:
            update_expires(vap)

        for vap in vaps_v6:
            update_expires(vap)

        for roa in roas:
            ta = roa.get("ta", None)
            if ta is not None:
                vrps_by_ta[ta] += 1
                update_expires(roa)

        for ta, vrp_count in vrps_by_ta.items():
            RPKI_OBJECTS_VRPS_BY_TA.labels(ta=ta).set(vrp_count)

        # Might be an empty loop - which is no problem
        for ta, min_expires in min_expires_by_ta.items():
            RPKI_OBJECTS_MIN_EXPIRY.labels(ta=ta).set(min_expires)
