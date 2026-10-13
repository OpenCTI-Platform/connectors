"""Pure helpers that shape a macadress.com API result into labels, an observable
description and a summary note. No HTTP, no STIX, no config access."""

from typing import Any

_UNKNOWN_DEVICE = ("unknown", "", None)
_RANDOMIZED_CONFIDENCE = ("possible", "likely")


def _slug(value: Any) -> str:
    return str(value).strip().lower().replace(" ", "-")


class MacadressUtils:
    @staticmethod
    def build_labels(data: dict) -> list[str]:
        """Labels applied to the enriched Mac-Addr observable."""
        labels: list[str] = ["macadress"]

        device = (data.get("device") or {}).get("category")
        if device and device not in _UNKNOWN_DEVICE:
            labels.append(_slug(device))

        if data.get("locally_administered"):
            labels.append("locally-administered")
        else:
            labels.append("universally-administered")

        if data.get("potentially_randomized") and (
            data.get("randomization_confidence") in _RANDOMIZED_CONFIDENCE
        ):
            labels.append("mac-randomized")

        virt = data.get("virtualization") or {}
        if virt.get("detected"):
            labels.append(f"virtualization:{_slug(virt.get('platform') or 'virtual')}")

        special = data.get("special_use") or {}
        if special.get("detected"):
            tag = special.get("type") or special.get("name") or "special-use"
            labels.append(f"special-use:{_slug(tag)}")

        return labels

    @staticmethod
    def build_external_references(data: dict, mac: str) -> list[dict]:
        refs = [
            {
                "source_name": "macadress.com",
                "url": f"https://macadress.com/lookup/{mac}",
                "description": "Full MAC address analysis",
            }
        ]
        vendor = data.get("vendor") or {}
        if vendor.get("lookup_url"):
            refs.append(
                {
                    "source_name": "macadress.com (vendor)",
                    "url": vendor["lookup_url"],
                    "description": "Registered vendor and its other blocks",
                }
            )
        return refs

    @staticmethod
    def build_description(data: dict) -> str:
        parts: list[str] = []

        org = data.get("organization")
        country = data.get("country")
        if org:
            parts.append(f"**Vendor:** {org}" + (f" ({country})" if country else ""))
        elif data.get("locally_administered"):
            parts.append("**Vendor:** locally administered (no IEEE assignment)")
        else:
            parts.append("**Vendor:** unregistered")

        prefix = data.get("matched_prefix")
        if prefix:
            block = data.get("block_type")
            parts.append(
                f"**Registered block:** `{prefix}`" + (f" ({block})" if block else "")
            )

        device = (data.get("device") or {}).get("category")
        if device and device not in _UNKNOWN_DEVICE:
            confidence = (data.get("device") or {}).get("confidence")
            parts.append(
                f"**Device category:** {device}"
                + (f" (confidence: {confidence})" if confidence else "")
            )

        virt = data.get("virtualization") or {}
        if virt.get("detected"):
            parts.append(
                f"**Virtualization:** {virt.get('platform') or 'virtual interface'}"
            )

        special = data.get("special_use") or {}
        if special.get("detected"):
            parts.append(
                f"**Special use:** {special.get('name') or special.get('type')}"
            )

        if data.get("potentially_randomized"):
            parts.append(
                "**Randomization:** potentially randomized "
                f"(confidence: {data.get('randomization_confidence')})"
            )

        deriv = data.get("local_vendor_derivation") or {}
        if deriv.get("detected"):
            who = deriv.get("organization") or deriv.get("matched_prefix")
            parts.append(f"**Possible vendor (U/L bit flip):** {who} (low confidence)")

        if data.get("explanation"):
            parts.append("")
            parts.append(str(data["explanation"]))

        return "\n".join(parts)

    @staticmethod
    def build_summary(mac: str, data: dict) -> str:
        lines: list[str] = [
            "## macadress.com Results",
            "",
            f"MAC: `{mac}`",
            "",
            f"Lookup: https://macadress.com/lookup/{mac}",
            "",
            MacadressUtils.build_description(data),
        ]
        return "\n".join(line for line in lines if line is not None)
