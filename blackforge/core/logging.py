from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

_CONFIGURED = False


def setup_logging(level: str = "INFO", component: str = "blackforge") -> structlog.BoundLogger:
    global _CONFIGURED

    if not _CONFIGURED:
        structlog.configure(
            processors=[
                structlog.contextvars.merge_contextvars,
                structlog.processors.add_log_level,
                structlog.processors.StackInfoRenderer(),
                structlog.dev.set_exc_info,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.dev.ConsoleRenderer() if sys.stderr.isatty() else structlog.processors.JSONRenderer(),
            ],
            wrapper_class=structlog.make_filtering_bound_logger(
                getattr(logging, level.upper(), logging.INFO)
            ),
            context_class=dict,
            logger_factory=structlog.PrintLoggerFactory(),
            cache_logger_on_first_use=True,
        )
        _CONFIGURED = True

    return structlog.get_logger(component)


def get_logger(component: str, **initial_context: Any) -> structlog.BoundLogger:
    logger = structlog.get_logger(component)
    if initial_context:
        logger = logger.bind(**initial_context)
    return logger
