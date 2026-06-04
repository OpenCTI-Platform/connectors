def check_vuln_description(descriptions: list) -> str:
    for d in descriptions:
        if d.lang == "en":
            return d.value
    return ""
