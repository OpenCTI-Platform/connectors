"""The module contains the ImplementationLanguageOV enum class."""

from enum import Enum


class ImplementationLanguageOV(str, Enum):
    """Implementation Language Enumeration."""

    APPLESCRIPT = "applescript"
    BASH = "bash"
    C = "c"
    CPP = "c++"
    CSHARP = "c#"
    GO = "go"
    JAVA = "java"
    JAVASCRIPT = "javascript"
    LUA = "lua"
    OBJECTIVE_C = "objective-c"
    PERL = "perl"
    PHP = "php"
    POWERSHELL = "powershell"
    PYTHON = "python"
    RUBY = "ruby"
    SCALA = "scala"
    SWIFT = "swift"
    TYPESCRIPT = "typescript"
    VISUAL_BASIC = "visual-basic"
    X86_32 = "x86-32"
    X86_64 = "x86-64"
