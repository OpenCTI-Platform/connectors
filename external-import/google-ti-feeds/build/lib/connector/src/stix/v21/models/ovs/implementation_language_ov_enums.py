"""The module contains the ImplementationLanguageOV enum class."""

from connector.src.stix.v21.models.ovs.base_open_vocab import BaseOV


class ImplementationLanguageOV(BaseOV):
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
