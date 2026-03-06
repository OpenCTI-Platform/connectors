def calculate_priority(score) -> str:
    """Calculate case priority based on score"""
    if score is None:
        return "P4"
    try:
        score_float = float(score)
        if score_float > 0.8:
            return "P1"
        elif score_float >= 0.5:
            return "P2"
        elif score_float > 0:
            return "P3"
        else:
            return "P4"
    except (ValueError, TypeError):
        return "P4"


def is_takedown_state(queue_state) -> bool:
    """Check if alert is in takedown state"""
    return queue_state and queue_state.lower() in ["actioned", "taken_down"]


def is_reverted_state(queue_state) -> bool:
    """Check if alert is reverted from takedown"""
    return queue_state and queue_state.lower() in [
        "archived",
        "needs_confirmation",
        "doppel_review",
        "monitoring",
    ]


def build_external_references(alert) -> list:
    """
    Build external references for observables/indicators
    :param alert: Doppel alert
    :return: List of external reference dicts
    """
    external_references = []
    audit_logs = alert.get("audit_logs", [])
    audit_log_text = (
        "\n".join(
            [
                f"{log.get('timestamp', '')}: {log.get('type', '')} - {log.get('value', '')} (by {log.get('changed_by', '')})"
                for log in audit_logs
            ]
        )
        if audit_logs
        else ""
    )

    if alert.get("doppel_link") or alert.get("id"):
        external_ref = {
            "source_name": alert.get("source", "Doppel"),
        }
        if alert.get("doppel_link"):
            external_ref["url"] = alert.get("doppel_link")
        if alert.get("id"):
            external_ref["external_id"] = alert.get("id")
        if audit_log_text:
            external_ref["description"] = audit_log_text
        external_references.append(external_ref)

    return external_references


def build_description(alert) -> str:
    """
    Build description field from alert data
    :param alert: Doppel alert
    :return: Description string
    """

    # Extract entity_content data
    entity_content = alert.get("entity_content", {})
    root_domain = entity_content.get("root_domain", {})

    country_code = root_domain.get("country_code")
    registrar = root_domain.get("registrar")
    hosting_provider = root_domain.get("hosting_provider")
    contact_email = root_domain.get("contact_email")
    mx_records = root_domain.get("mx_records", [])
    nameservers = root_domain.get("nameservers", [])

    description_parts = []
    if alert.get("brand"):
        description_parts.append(f"**Brand**: {alert.get('brand')}\n")
    if alert.get("product"):
        description_parts.append(f"**Product**: {alert.get('product')}\n")
    if alert.get("notes"):
        description_parts.append(f"**Notes**: {alert.get('notes')}\n")
    if alert.get("uploaded_by"):
        description_parts.append(f"**Uploaded By**: {alert.get('uploaded_by')}\n")
    if alert.get("screenshot_url"):
        description_parts.append(f"**Screenshot URL**: {alert.get('screenshot_url')}\n")
    if alert.get("message"):
        description_parts.append(f"**Message**: {alert.get('message')}\n")
    if alert.get("source"):
        description_parts.append(f"**Source**: {alert.get('source')}\n")
    if alert.get("assignee"):
        description_parts.append(f"**Assignee**: {alert.get('assignee')}\n")
    if country_code:
        description_parts.append(f"**Country**: {country_code}\n")
    if registrar:
        description_parts.append(f"**Registrar**: {registrar}\n")
    if hosting_provider:
        description_parts.append(f"**Hosting Provider**: {hosting_provider}\n")
    if contact_email:
        description_parts.append(f"**Contact Email**: {contact_email}\n")
    if mx_records:
        formatted_mx = [
            f"{mx.get('exchange')} (pref: {mx.get('preference')})" for mx in mx_records
        ]
        description_parts.append(f"**MX Records**: {', '.join(formatted_mx)}\n")
    if nameservers:
        ns_text = ", ".join(
            [ns if isinstance(ns, str) else ns.get("host") for ns in nameservers]
        )
        description_parts.append(f"**Nameservers**: {ns_text}\n")

    return "\n".join(description_parts) if description_parts else ""


def build_custom_properties(alert, author_id) -> dict:
    """
    Build custom properties for observables/indicators
    :param alert: Doppel alert
    :return: Dict of custom properties
    """
    custom_properties = {}
    raw_score = alert.get("score")
    try:
        score = int(float(raw_score)) if raw_score is not None else 0
    except (ValueError, TypeError):
        score = 0
    custom_properties["x_opencti_created_by_ref"] = author_id
    custom_properties["x_opencti_score"] = score
    custom_properties["x_opencti_workflow_id"] = alert.get(
        "id"
    )  # Store alert_id for lookup

    if alert.get("product") == "telco":
        custom_properties["x_opencti_labels"] = build_labels(alert)
        custom_properties["x_opencti_external_references"] = build_external_references(alert)

    x_opencti_description = build_description(alert)
    if x_opencti_description:
        custom_properties["x_opencti_description"] = x_opencti_description

    return custom_properties


def build_labels(alert) -> list:
    """
    Build labels for observables/indicators with semantic prefixes
    Returns dict with categorized labels and flat list
    """
    labels_dict = {
        "queue_state": None,
        "entity_state": None,
        "severity": None,
        "platform": None,
        "brand": None,
        "tags": [],
    }

    if alert.get("queue_state"):
        labels_dict["queue_state"] = f"queue_state:{alert['queue_state']}"
    if alert.get("entity_state"):
        labels_dict["entity_state"] = f"entity_state:{alert['entity_state']}"
    if alert.get("severity"):
        labels_dict["severity"] = f"severity:{alert['severity']}"
    if alert.get("platform"):
        labels_dict["platform"] = f"platform:{alert['platform']}"
    if alert.get("brand"):
        labels_dict["brand"] = f"brand:{alert['brand']}"

    tags = alert.get("tags", [])

    if tags:
        labels_dict["tags"] = [tag.get("name") for tag in tags if "name" in tag]

    labels_flat = [v for v in labels_dict.values() if v and isinstance(v, str)]
    labels_flat.extend(labels_dict["tags"])

    return labels_flat
