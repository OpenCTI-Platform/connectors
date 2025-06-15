"""The module defines the ProcessorArchitectureOV enumeration."""

from enum import Enum


class ProcessorArchitectureOV(str, Enum):
    """Processor Architecture Enumeration."""

    ALPHA = "alpha"
    ARM = "arm"
    IA_64 = "ia-64"
    MIPS = "mips"
    POWERPC = "powerpc"
    SPARC = "sparc"
    X86 = "x86"
    X86_64 = "x86-64"
