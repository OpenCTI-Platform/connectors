from internal_enrichment_connector.errors import (
    SPLAuthError,
    SPLConnectionError,
    SPLEnrichmentError,
    SPLResultParseError,
    SPLSyntaxError,
    SPLTimeoutError,
)


def test_syntax_error_not_retryable():
    assert SPLSyntaxError.retryable is False


def test_timeout_error_retryable():
    assert SPLTimeoutError.retryable is True


def test_auth_error_not_retryable():
    assert SPLAuthError.retryable is False


def test_connection_error_retryable():
    assert SPLConnectionError.retryable is True


def test_parse_error_not_retryable():
    assert SPLResultParseError.retryable is False


def test_base_class_attributes():
    cause = ValueError("boom")
    err = SPLEnrichmentError("failed", indicator_id="indicator--123", cause=cause)
    assert err.indicator_id == "indicator--123"
    assert err.cause == cause


def test_error_messages_include_context():
    cause = RuntimeError("timeout")
    err = SPLTimeoutError("query failed", indicator_id="indicator--abc", cause=cause)
    message = str(err)
    assert "indicator--abc" in message
    assert "timeout" in message
