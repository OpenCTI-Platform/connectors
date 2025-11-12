class IOCRule:
    """
    Represent an IOC rule on Harfanglab.
    """

    def __init__(
        self,
        id: str = None,
        type: str = None,
        value: str = None,
        description: str = None,
        comment: dict = None,
        hl_status: str = None,
        enabled: bool = True,
    ):
        self.id = id
        self.type = type
        self.value = value
        self.description = description
        self.comment = comment
        self.hl_status = hl_status
        self.enabled = enabled


class SigmaRule:
    """
    Represent a Sigma rule on Harfanglab.
    """

    def __init__(
        self,
        id: str = None,
        name: str = None,
        content: str = None,
        hl_status: str = None,
        enabled: bool = None,
    ):
        self.id = id
        self.name = name
        self.content = content
        self.hl_status = hl_status
        self.enabled = enabled


class YaraFile:
    """
    Represent a Yara file on Harfanglab.
    """

    def __init__(
        self,
        id: str = None,
        name: str = None,
        content: str = None,
        hl_status: str = None,
        enabled: bool = None,
    ):
        self.id = id
        self.name = name
        self.content = content
        self.hl_status = hl_status
        self.enabled = enabled
