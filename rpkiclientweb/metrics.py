from prometheus_client import Counter, Gauge, Histogram

#
# Metrics about how/when rpki-client was running
#
# buckets from https://github.com/Netflix/rend/pull/93/files
# with a number of added buckets at frequent durations.
RPKI_CLIENT_DURATION = Histogram(
    "rpkiclient_duration_seconds",
    "Time spent calling rpki-client",
    buckets=[
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        16,
        21,
        26,
        31,
        36,
        41,
        46,
        51,
        56,
        64,
        74,  # added
        85,
        95,  # added
        106,
        116,  # added
        127,
        148,
        169,
        190,
        211,
        232,
        256,
        341,
        426,
        511,
        596,
        681,
        766,
    ],
)
RPKI_CLIENT_LAST_DURATION = Gauge(
    "rpkiclient_last_duration_seconds",
    "Duration of the last call to rpki-client",
)
RPKI_CLIENT_LAST_UPDATE = Gauge(
    "rpkiclient_last_update",
    "Timestamp of the last successful call to rpki-client",
)
RPKI_CLIENT_UPDATE_COUNT = Counter(
    "rpkiclient_update", "Number of rpki-client updates", ["returncode"]
)
RPKI_CLIENT_RUNNING = Gauge(
    "rpkiclient_running", "Number of running rpki-client instances"
)

#
# Metrics about retrieval behaviour
#
RPKI_CLIENT_FETCH_STATUS = Counter(
    "rpkiclient_fetch_status",
    "count of fetch status per repository and type encountered by rpki-client.",
    ["uri", "type"],
)
RPKI_CLIENT_PULLED = Gauge(
    "rpkiclient_pulled",
    "Last time repo was pulled (before process ended due to timeout).",
    ["uri"],
)
RPKI_CLIENT_PULLING = Gauge(
    "rpkiclient_pulling",
    "Last time pulling from this repository was started (referenced).",
    ["uri"],
)
RPKI_CLIENT_REMOVED_UNREFERENCED = Counter(
    "rpkiclient_removed_unreferenced",
    "Number of removals of repositories that were no longer referenced.",
)
#
# Metrics about RPKI objects
#
RPKI_CLIENT_WARNINGS = Gauge(
    "rpkiclient_warnings", "Warnings from rpki-client", ["hostname", "type"]
)
RPKI_OBJECTS_BUILD_TIME = Gauge(
    "rpki_objects_buildtime", "Time at which the JSON was generated"
)
RPKI_OBJECTS_COUNT = Gauge("rpki_objects", "Number of objects by type", ["type"])
RPKI_OBJECTS_MIN_EXPIRY = Gauge(
    "rpki_objects_min_expiry",
    "First expiry time for file in exported objects by trust anchor (includes non-hosted repositories)",
    ["ta"],
)

RPKI_OBJECTS_VRPS_BY_TA = Gauge(
    "rpki_vrps",
    "Number of exported Validated Roa Payloads by Trust Anchor",
    ["ta"],
)

#
# Metrics about rpki-client-web
#
RPKI_CLIENT_WEB_PARSE_ERROR = Counter(
    "rpkiclientweb_parse_error",
    "Number of parse errors encountered by rpki-client-web",
    ["type"],
)
