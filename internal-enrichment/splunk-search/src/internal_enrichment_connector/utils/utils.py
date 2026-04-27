def process_indicator(indicator):
    """Normalize an OpenCTI indicator into a Splunk event dict."""
    # Expected keys: value, type, confidence, description, labels
    event = {
        "event_type": "indicator",
        "value": indicator.get("value"),
        "indicator_type": indicator.get("type"),
        "confidence": indicator.get("confidence", 0),
        "description": indicator.get("description", ""),
        "labels": indicator.get("labels", []),
    }
    # Remove empty fields
    event = {k: v for k, v in event.items() if v not in (None, "", [], {})}
    return event
