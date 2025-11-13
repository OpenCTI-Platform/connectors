#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
STIX Pattern Parser for converting STIX indicator patterns to observables
"""

import re
from typing import Dict, List, Optional


def parse_stix_pattern(pattern: str) -> List[Dict]:
    """
    Parse a STIX pattern and extract observables

    Example patterns:
    - [file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']
    - [ipv4-addr:value = '192.168.1.1']
    - [domain-name:value = 'evil.com']
    - [url:value = 'http://malware.com/payload']
    - [email-addr:value = 'bad@actor.com']
    - [file:hashes.'SHA-256' = 'abc123...']
    - [file:name = 'malware.exe']
    - [windows-registry-key:key = 'HKEY_LOCAL_MACHINE\\Software\\Evil']
    - [process:name = 'evil.exe']
    - [network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '10.0.0.1']
    """
    observables = []

    # Clean the pattern
    pattern = pattern.strip()

    # Handle composite patterns (AND, OR)
    # Split by AND/OR but keep track of brackets
    pattern_parts = []

    # Simple split for now - can be enhanced for complex patterns
    if " AND " in pattern or " OR " in pattern:
        # Split by AND/OR outside of brackets
        parts = re.split(r"\s+(?:AND|OR)\s+", pattern)
        pattern_parts.extend(parts)
    else:
        pattern_parts = [pattern]

    for part in pattern_parts:
        observable = parse_single_pattern(part.strip())
        if observable:
            observables.append(observable)

    return observables


def parse_single_pattern(pattern: str) -> Optional[Dict]:
    """Parse a single STIX pattern component"""

    # Remove outer brackets if present
    pattern = pattern.strip()
    if pattern.startswith("[") and pattern.endswith("]"):
        pattern = pattern[1:-1].strip()

    # Pattern format: object_type:property = 'value'
    # or object_type:property.subproperty = 'value'

    # Match pattern like: file:hashes.MD5 = 'hash_value'
    match = re.match(r"(\w+[-\w]*):([.\w'\"]+)\s*=\s*['\"]?([^'\"]+)['\"]?", pattern)

    if not match:
        # Try to match patterns with special characters
        match = re.match(r"(\w+[-\w]*):([.\w'\"]+)\s*=\s*(.+)", pattern)

    if match:
        obj_type = match.group(1)
        property_path = match.group(2)
        value = match.group(3).strip().strip("'\"")

        # Create observable based on type
        if obj_type == "file":
            observable = {"type": "file"}

            if "hashes" in property_path:
                # Extract hash type
                hash_type = None
                if "MD5" in property_path or "md5" in property_path:
                    hash_type = "MD5"
                elif "SHA-256" in property_path or "sha256" in property_path:
                    hash_type = "SHA-256"
                elif "SHA-1" in property_path or "sha1" in property_path:
                    hash_type = "SHA-1"
                elif "SHA256" in property_path:
                    hash_type = "SHA-256"
                elif "SHA1" in property_path:
                    hash_type = "SHA-1"
                else:
                    # Try to extract hash type from property path
                    # Pattern might be: hashes.'SHA-256' or hashes["SHA-256"]
                    hash_match = re.search(
                        r"['\"]?([\w-]+)['\"]?", property_path.split(".")[-1]
                    )
                    if hash_match:
                        hash_type = hash_match.group(1).upper()
                        if hash_type == "SHA256":
                            hash_type = "SHA-256"
                        elif hash_type == "SHA1":
                            hash_type = "SHA-1"

                if hash_type:
                    observable["hashes"] = {hash_type: value}

            elif "name" in property_path:
                observable["name"] = value

            elif "size" in property_path:
                observable["size"] = int(value) if value.isdigit() else value

            return observable

        elif obj_type == "ipv4-addr":
            return {"type": "ipv4-addr", "value": value}

        elif obj_type == "ipv6-addr":
            return {"type": "ipv6-addr", "value": value}

        elif obj_type == "domain-name" or obj_type == "domain":
            return {"type": "domain-name", "value": value}

        elif obj_type == "url":
            return {"type": "url", "value": value}

        elif obj_type == "email-addr" or obj_type == "email-address":
            return {"type": "email-addr", "value": value}

        elif obj_type == "mac-addr":
            return {"type": "mac-addr", "value": value}

        elif obj_type == "windows-registry-key":
            return {"type": "windows-registry-key", "key": value}

        elif obj_type == "process":
            observable = {"type": "process"}

            if "name" in property_path:
                observable["name"] = value
            elif "pid" in property_path:
                observable["pid"] = int(value) if value.isdigit() else value
            elif "command_line" in property_path:
                observable["command_line"] = value

            return observable

        elif obj_type == "user-account":
            observable = {"type": "user-account"}

            if "account_login" in property_path or "user_id" in property_path:
                observable["account_login"] = value
            elif "display_name" in property_path:
                observable["display_name"] = value

            return observable

        elif obj_type == "network-traffic":
            # Network traffic patterns are complex, simplified handling
            return {
                "type": "network-traffic",
                "protocols": [value] if "protocols" in property_path else [],
                "src_port": (
                    int(value)
                    if "src_port" in property_path and value.isdigit()
                    else None
                ),
                "dst_port": (
                    int(value)
                    if "dst_port" in property_path and value.isdigit()
                    else None
                ),
            }

        elif obj_type == "autonomous-system":
            observable = {"type": "autonomous-system"}

            if "number" in property_path:
                observable["number"] = int(value) if value.isdigit() else value
            elif "name" in property_path:
                observable["name"] = value

            return observable

        elif obj_type == "x509-certificate":
            return {
                "type": "x509-certificate",
                "serial_number": value if "serial_number" in property_path else None,
                "subject": value if "subject" in property_path else None,
                "issuer": value if "issuer" in property_path else None,
            }

        elif obj_type == "directory":
            return {"type": "directory", "path": value}

        elif obj_type == "mutex":
            return {"type": "mutex", "name": value}

        elif obj_type == "software":
            return {
                "type": "software",
                "name": value if "name" in property_path else None,
                "version": value if "version" in property_path else None,
                "vendor": value if "vendor" in property_path else None,
            }

        else:
            # Generic observable
            return {"type": obj_type, "value": value}

    # Try alternate pattern formats
    # Simple format: [value = '192.168.1.1']
    simple_match = re.match(r"value\s*=\s*['\"]?([^'\"]+)['\"]?", pattern)
    if simple_match:
        value = simple_match.group(1).strip()
        # Try to infer type from value
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", value):
            return {"type": "ipv4-addr", "value": value}
        elif re.match(r"^[a-f0-9]{32}$", value, re.IGNORECASE):
            return {"type": "file", "hashes": {"MD5": value}}
        elif re.match(r"^[a-f0-9]{40}$", value, re.IGNORECASE):
            return {"type": "file", "hashes": {"SHA-1": value}}
        elif re.match(r"^[a-f0-9]{64}$", value, re.IGNORECASE):
            return {"type": "file", "hashes": {"SHA-256": value}}
        elif "@" in value:
            return {"type": "email-addr", "value": value}
        elif value.startswith("http://") or value.startswith("https://"):
            return {"type": "url", "value": value}
        elif "." in value and not "/" in value:
            return {"type": "domain-name", "value": value}

    return None


def combine_file_observables(observables: List[Dict]) -> List[Dict]:
    """
    Combine multiple file observables that refer to the same file
    For example, if we have separate patterns for file:name and file:hashes
    """
    combined = []
    file_observables = {}

    for obs in observables:
        if obs.get("type") == "file":
            # Try to find a key to group by
            key = None
            if "name" in obs:
                key = f"file:{obs['name']}"
            elif "hashes" in obs:
                # Use first hash as key
                hash_values = list(obs["hashes"].values())
                if hash_values:
                    key = f"file:{hash_values[0]}"

            if key:
                if key not in file_observables:
                    file_observables[key] = {"type": "file"}

                # Merge properties
                for prop, value in obs.items():
                    if prop == "hashes" and "hashes" in file_observables[key]:
                        # Merge hashes
                        file_observables[key]["hashes"].update(value)
                    else:
                        file_observables[key][prop] = value
            else:
                combined.append(obs)
        else:
            combined.append(obs)

    # Add combined file observables
    combined.extend(file_observables.values())

    return combined
