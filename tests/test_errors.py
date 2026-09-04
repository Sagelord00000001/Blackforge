import pytest

from blackforge.core.errors import (
    AuthorizationError,
    BlackforgeError,
    ConfigurationError,
    EvidenceError,
    MissionError,
)


class TestErrors:
    def test_base_error(self) -> None:
        err = BlackforgeError("test message")
        assert str(err) == "test message"
        assert err.message == "test message"

    def test_error_with_details(self) -> None:
        err = BlackforgeError("msg", details={"key": "value"})
        assert err.details == {"key": "value"}

    def test_specific_errors_inherit(self) -> None:
        assert issubclass(ConfigurationError, BlackforgeError)
        assert issubclass(AuthorizationError, BlackforgeError)
        assert issubclass(MissionError, BlackforgeError)
        assert issubclass(EvidenceError, BlackforgeError)

    def test_error_catching(self) -> None:
        with pytest.raises(BlackforgeError):
            raise ConfigurationError("bad config")
