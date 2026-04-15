def _convert_score_to_confidence(score_str: str) -> int:
    score_map = {
        "Critical": 95,
        "Dangerous": 85,
        "Moderate": 65,
        "Low": 35,
        "Safe": 10,
    }
    return score_map.get(score_str, 0)
