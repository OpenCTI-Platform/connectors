def format_time(utc_time):
    """
    Format the given UTC time to a specific string format
    :param utc_time: A datetime object representing UTC time
    :return: Formatted string representation of the datetime object
    """
    return utc_time.strftime("%Y-%m-%dT%H:%M:%S")


def convert_hours_to_seconds(hours) -> int:
    """
    Convert the given days into seconds
    :param hours: hours in integer
    :return: Formatted days into second in int
    """
    return int(hours) * 60 * 60
