"""The module defines the ProcessModel class, which represents a STIX 2.1 Process object."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import Field
from stix2.v21 import Process, _STIXBase21  # type: ignore


class ProcessModel(BaseSCOModel):
    """Model representing a Process in STIX 2.1 format."""

    extensions: Optional[Dict[str, Dict[str, Any]]] = Field(
        default=None,
        description="Dictionary of supported process extensions (e.g., windows-process-ext, windows-service-ext).",
    )

    is_hidden: Optional[bool] = Field(
        default=None,
        description="Indicates whether the process is hidden from userland/system tools.",
    )
    pid: Optional[int] = Field(
        default=None, ge=0, description="Process ID (PID) of the process."
    )
    created_time: Optional[datetime] = Field(
        default=None, description="Timestamp of when the process was created."
    )
    cwd: Optional[str] = Field(
        default=None, description="Current working directory of the process."
    )
    command_line: Optional[str] = Field(
        default=None,
        description="Full command line used to launch the process (including executable and arguments).",
    )

    environment_variables: Optional[Dict[str, str]] = Field(
        default=None,
        description="Dictionary of environment variables (case-sensitive). Keys are variable names, values are their string contents.",
    )

    opened_connection_refs: Optional[List[str]] = Field(
        default=None,
        description="List of references to network-traffic objects opened by this process. MUST be of type 'network-traffic'.",
    )

    creator_user_ref: Optional[str] = Field(
        default=None,
        description="Reference to a user-account object representing the user that created the process. MUST be of type 'user-account'.",
    )

    image_ref: Optional[str] = Field(
        default=None,
        description="Reference to a file object representing the executable binary run by this process. MUST be of type 'file'.",
    )

    parent_ref: Optional[str] = Field(
        default=None,
        description="Reference to the parent process (if any). MUST be of type 'process'.",
    )

    child_refs: Optional[List[str]] = Field(
        default=None,
        description="References to child processes spawned by this one. MUST be of type 'process'.",
    )

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return Process(**self.model_dump(exclude_none=True))


def test_process_model() -> None:
    """Test function to demonstrate the usage of ProcessModel."""
    from datetime import UTC, datetime
    from uuid import uuid4

    now = datetime.now(UTC)

    # === Minimal Process ===
    minimal = ProcessModel(
        type="process", spec_version="2.1", id=f"process--{uuid4()}", pid=1337
    )

    print("=== MINIMAL PROCESS ===")  # noqa: T201
    print(minimal.to_stix2_object().serialize(pretty=True))  # noqa: T201

    # === Full Process ===
    full = ProcessModel(
        type="process",
        spec_version="2.1",
        id=f"process--{uuid4()}",
        pid=2458,
        is_hidden=True,
        created_time=now,
        cwd="C:\\Windows\\Temp",
        command_line="C:\\Windows\\Temp\\loader.exe -s beacon",
        environment_variables={
            "TEMP": "C:\\Windows\\Temp",
            "SESSION": "XID-1337",
        },
        opened_connection_refs=[f"network-traffic--{uuid4()}"],
        creator_user_ref=f"user-account--{uuid4()}",
        image_ref=f"file--{uuid4()}",
        parent_ref=f"process--{uuid4()}",
        child_refs=[f"process--{uuid4()}", f"process--{uuid4()}"],
        extensions={
            "windows-process-ext": {
                "aslr_enabled": True,
                "dep_enabled": True,
                "priority": 8,
                "startup_info": {
                    "x": 100,
                    "y": 200,
                    "window_title": "cmd.exe",
                },
            }
        },
    )

    print("\n=== FULL PROCESS ===")  # noqa: T201
    print(full.to_stix2_object().serialize(pretty=True))  # noqa: T201


if __name__ == "__main__":
    test_process_model()
