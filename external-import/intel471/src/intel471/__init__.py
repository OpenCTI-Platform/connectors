from enum import Enum


class HelperRequest:
    class Operation(Enum):
        GET = "get"
        UPDATE = "update"

    def __init__(self, stream: str, operation: Operation, data: dict = None) -> None:
        self.stream = stream
        self.operation = operation
        self.data = data

    def __repr__(self) -> str:
        return f"HelperRequest<stream={self.stream}, operation={self.operation}, data={str(self.data)}>"
