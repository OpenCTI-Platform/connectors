def make_markdown_table(array):
    """the same input as above"""

    nl = "\n"

    markdown = nl
    markdown += f"| {' | '.join(array[0])} |"

    markdown += nl
    markdown += f"| {' | '.join(['---'] * len(array[0]))} |"

    markdown += nl
    for entry in array[1:]:
        entry_has_list = any(isinstance(x, list) for x in entry)
        if not entry_has_list:
            markdown += f"| {' | '.join(entry)} |{nl}"

    markdown += nl
    markdown += "> "

    return markdown
