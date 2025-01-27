def dict_to_serialized_list(dict: dict) -> str:
    """
    Convert a dict to a stringified list of key/value pairs.
    :param dict: Dict to convert
    :return: Stringified list
    """
    serialized_items = [f"{key} = {dict[key]}" for key in dict]

    return ", ".join(serialized_items)


def dict_to_markdown_table(dict: dict) -> str:
    """
    Convert a dict to a key/value markdown table.
    :param dict: Dict to build markdown table from
    :return: String representing the markdown table
    """
    markdown_table = "| Field | Value |  \n"
    markdown_table += "| ---- | ----- |  \n"

    for key in dict:
        markdown_table += f"| {key} | {dict[key]} |  \n"

    return markdown_table
