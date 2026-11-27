"""Links to GTI pages."""

GTI_GUI_URL = "https://www.virustotal.com/gui"

# GTI object type -> (display label, GUI path segment)
GTI_GUI_PATHS = {
    "collection": ("Collection", "collection"),
    "file": ("File", "file"),
    "domain": ("Domain", "domain"),
    "ip_address": ("IP", "ip-address"),
    "url": ("URL", "url"),
}


def gti_gui_url(object_type: str | None, object_id: str | None) -> str | None:
    """Return the GTI page of an object, or None for an unknown type or no id."""
    if not object_id or object_type not in GTI_GUI_PATHS:
        return None
    return f"{GTI_GUI_URL}/{GTI_GUI_PATHS[object_type][1]}/{object_id}"


def gti_external_reference(
    ioc_type: str, ioc_id: str, name: str | None = None
) -> dict[str, str]:
    """Return the external reference to the GTI page of an IOC.

    Args:
        ioc_type: GTI IOC type: file, domain, ip_address or url.
        ioc_id: GTI identifier; for URLs, the URL identifier, not the URL.
        name: Value shown in the source name, defaults to the identifier.

    Returns:
        The external reference fields.

    """
    label, path = GTI_GUI_PATHS[ioc_type]
    return {
        "source_name": f"[GTI] {label} {name or ioc_id}",
        "description": f"Google Threat Intelligence {label} Link",
        "url": f"{GTI_GUI_URL}/{path}/{ioc_id}",
    }
