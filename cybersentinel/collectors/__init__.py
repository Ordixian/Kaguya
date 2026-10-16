"""Collector registry."""

from .base import Collector
from .network import NetworkCollector
from .process import ProcessCollector
from .authlog import AuthLogCollector
from .fim import FIMCollector

REGISTRY = {
    "network": NetworkCollector,
    "process": ProcessCollector,
    "authlog": AuthLogCollector,
    "fim": FIMCollector,
}


def build_collectors(config, host: str = "localhost") -> list[Collector]:
    """Instantiate every collector enabled by config *and* tier."""
    built = []
    for name, cls in REGISTRY.items():
        if config.collector_enabled(name):
            built.append(cls(config.get(f"collectors.{name}", {}), host=host))
    return built


__all__ = ["Collector", "REGISTRY", "build_collectors"]
