from src.severity import severity_to_score


def test_high_maps_to_90():
    assert severity_to_score("High") == 90


def test_medium_maps_to_60():
    assert severity_to_score("Medium") == 60


def test_low_maps_to_30():
    assert severity_to_score("low") == 30


def test_unknown_maps_to_50():
    assert severity_to_score("critical") == 50
    assert severity_to_score("") == 50
    assert severity_to_score(None) == 50
