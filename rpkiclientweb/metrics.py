from prometheus_client import Counter, Gauge, Histogram
#
# Metrics about how/when rpki-client was running
#
# buckets from https://github.com/Netflix/rend/pull/93/files
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
        85,
        106,
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
RPKI_CLIENT_FETCH_ERROR = Counter(
    "rpkiclient_fetch_error",
    "fetch errors encountered by rpki-client.",
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
RPKI_OBJECTS_COUNT = Gauge("rpki_objects", "Number of objects by type", ["type"])
RPKI_OBJECTS_MIN_EXPIRY = Gauge(
    "rpki_objects_min_expiry",
    "First expiry time for file in exported objects by trust anchor",
    ["ta"]
)
