from blackforge.core.logging import get_logger, setup_logging


class TestLogging:
    def test_setup_logging_returns_logger(self) -> None:
        logger = setup_logging("INFO", "test_component")
        assert logger is not None

    def test_get_logger_returns_logger(self) -> None:
        logger = get_logger("test_module")
        assert logger is not None

    def test_logger_with_context(self) -> None:
        logger = get_logger("test", mission_id="m_123", task_id="t_456")
        assert logger is not None

    def test_structured_logging_works(self) -> None:
        logger = get_logger("test_structured")
        logger.info("test_event", key="value", count=42)
