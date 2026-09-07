"""Temporary Blackforge Development Console.

The console is a *temporary* development UI that proves the Phase 14.1
mission orchestration experience end-to-end. It is strictly separated from
core engine logic:

    UI  ->  DevelopmentConsoleService  ->  MissionOrchestrator  ->  core

The UI never writes evidence, never mutates world-model storage, never
bypasses authorization or scope, and never invokes a transport directly. All
execution funnels through the deterministic mission orchestrator.

This package concerns itself only with the console surface. The
orchestration engine itself lives in :mod:`blackforge.orchestration`.
"""

from blackforge.ui.access import AccessGate, AccessSession
from blackforge.ui.console import ConsoleAccessError, DevelopmentConsole
from blackforge.ui.service import (
    ConsoleError,
    DevelopmentConsoleService,
    PlannerSelection,
)

__all__ = [
    "AccessGate",
    "AccessSession",
    "ConsoleAccessError",
    "ConsoleError",
    "DevelopmentConsole",
    "DevelopmentConsoleService",
    "PlannerSelection",
]
