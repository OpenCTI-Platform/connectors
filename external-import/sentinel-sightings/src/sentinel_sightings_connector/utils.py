from dateutil.parser import parse


def format_incident(incident) -> dict:
    incident["lastUpdateDateTime"] = int(
        round(parse(incident["lastUpdateDateTime"]).timestamp())
    )

    return incident


def validate_incident(incident, last_incident_date) -> bool:
    incident_timestamp = int(round(parse(incident["lastUpdateDateTime"]).timestamp()))
    return (
        int(incident_timestamp) > int(last_incident_date)
        and incident["status"] != "resolved"
    )
