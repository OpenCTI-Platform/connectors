"""The module contains the Windows PE Binary Type OV Enums."""

from enum import Enum


class WindowsPEBinaryTypeOV(str, Enum):
    """Windows PE Binary Type Enumeration."""

    DLL = "dll"
    EXE = "exe"
    SYS = "sys"
