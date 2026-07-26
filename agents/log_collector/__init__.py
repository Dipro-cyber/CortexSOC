"""
CortexSOC — Log Collector Agent package.

Exports the ``LogCollectorAgent`` for use by the Orchestrator and tests.

Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6
"""
from agents.log_collector.agent import LogCollectorAgent

__all__ = ["LogCollectorAgent"]
