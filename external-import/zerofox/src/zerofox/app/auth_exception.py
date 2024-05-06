class AuthException(Exception):
    def __init__(self) -> None:
        msg = "The token you have provided is not allowed to access this integration"
        super().__init__(msg)
