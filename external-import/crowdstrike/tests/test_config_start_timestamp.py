import time

import pytest
from models.configs.crowdstrike_configs import _ConfigLoaderCrowdstrike


def _minimal_kwargs():
    # Provide required secret fields so the model can be constructed
    return {
        "client_id": "cid",
        "client_secret": "csecret",
    }


def test_missing_keys_get_default_values():
    """If no start timestamp keys are provided, the defaults should be integers."""
    config = _ConfigLoaderCrowdstrike(**_minimal_kwargs())

    assert isinstance(config.actor_start_timestamp, int)
    assert isinstance(config.report_start_timestamp, int)
    assert isinstance(config.indicator_start_timestamp, int)


@pytest.mark.parametrize(
    "value",
    [None, "", "   "],
)
def test_none_or_empty_are_replaced_by_default(value):
    """Explicit None or empty strings should be replaced by the default timestamp."""
    kwargs = _minimal_kwargs()
    kwargs.update(
        {
            "actor_start_timestamp": value,
            "report_start_timestamp": value,
            "indicator_start_timestamp": value,
        }
    )

    config = _ConfigLoaderCrowdstrike(**kwargs)

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

    config = _ConfigLoaderCrowdstrike(**kwargs)

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
        _ConfigLoaderCrowdstrike(**kwargs)
