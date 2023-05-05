import logging
from typing import Iterable, List

from prometheus_client.metrics_core import Metric
from prometheus_client.registry import REGISTRY, Collector

__all__ = ["ListCollector"]


LOG = logging.getLogger(__name__)


class WrappedCollector(Collector):
    """
    Inner class for ListCollector for reference management.

    This will be referrred to from the prometheus registry, so this object will never be garbage collected because of it being unreferenced.
    That is why the outer class exists, to which no other reference is held.
    """

    metrics: List[Metric] = []

    def collect(self) -> Iterable[Metric]:
        return self.metrics


class ListCollector:
    """A collector of a list of metrics that manages its lifecycle in the registry."""

    inner: WrappedCollector

    def __init__(self) -> None:
        self.inner = WrappedCollector()
        REGISTRY.register(self.inner)

    def __del__(self) -> None:
        LOG.debug("unregistering ListCollector from prometheus registry")
        REGISTRY.unregister(self.inner)

    def collect(self) -> Iterable[Metric]:
        """Collect from the wrapped collector."""
        return self.inner.metrics

    def update(self, new_metrics: Iterable[Metric]) -> None:
        """Update the metrics contained in this collector."""
        self.inner.metrics = list(new_metrics)
