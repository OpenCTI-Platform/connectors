import time

import pytest
from crowdstrike_feeds_connector.settings import CrowdstrikeConfig


def _minimal_kwargs():
    # Provide required secret fields so the model can be constructed
    return {
        "client_id": "cid",
        "client_secret": "csecret",
    }


def test_missing_keys_get_default_values():
    """If no start timestamp keys are provided, the defaults should be integers."""
    config = CrowdstrikeConfig(**_minimal_kwargs())

    assert isinstance(config.actor_start_timestamp, int)
    assert isinstance(config.report_start_timestamp, int)
    assert isinstance(config.indicator_start_timestamp, int)


@pytest.mark.parametrize(
    "field",
    [
        "actor_start_timestamp",
        "report_start_timestamp",
        "indicator_start_timestamp",
    ],
)
def test_past_timestamp_is_allowed_and_preserved(field):
    past = int(time.time()) - 3600
    kwargs = _minimal_kwargs()
    kwargs[field] = past

    config = CrowdstrikeConfig(**kwargs)

    assert getattr(config, field) == past


@pytest.mark.parametrize(
    "field",
    [
        "actor_start_timestamp",
        "report_start_timestamp",
        "indicator_start_timestamp",
    ],
)
def test_future_timestamp_raises_value_error(field):
    future = int(time.time()) + 3600

    kwargs = _minimal_kwargs()
    kwargs[field] = future

    with pytest.raises(ValueError):
        CrowdstrikeConfig(**kwargs)
