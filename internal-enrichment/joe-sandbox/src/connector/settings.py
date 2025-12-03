from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
)
from pydantic import Field, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="JoeSandbox",
    )


class JoeSandboxConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `JoeSandboxConnector`.
    """

    report_types: str = Field(
        description="Download/upload as external ref files for these report types. json/xml are only allowed to be used with Joe Sandbox Cloud Pro",
        default="executive,html,iochtml,iocjson,iocxml,unpackpe,stix,ida,pdf,pdfexecutive,misp,pcap,maec,memdumps,json,lightjsonfixed,xml,lightxml,pcapunified,pcapsslinspection",
    )
    api_url: str = Field(
        description="Cloud Pro: https://jbxcloud.joesecurity.org/api, Cloud Basic: https://joesandbox.com/api",
        default="https://jbxcloud.joesecurity.org/api",
    )
    api_key: SecretStr = Field(
        description="The API key for Joe Sandbox", default=SecretStr("ChangeMe")
    )
    analysis_url: str = Field(
        description="Cloud Pro: https://jbxcloud.joesecurity.org/analysis, Cloud Basic: https://joesandbox.com/analysis",
        default="https://jbxcloud.joesecurity.org/analysis",
    )
    accept_tac: bool = Field(
        description="If true you accept Terms and Conditions at https://jbxcloud.joesecurity.org/tandc",
        default=True,
    )
    api_timeout: int = Field(
        description="Time in seconds to timeout after calling Joe Sandbox API",
        default=30,
    )
    verify_ssl: bool = Field(description="Verify SSL for API calls", default=True)
    api_retries: int = Field(
        description="How many times to retry API calls before giving up", default=5
    )
    proxies: str | None = Field(
        description="A JSON encoded map of proxies to use for API calls. See https://requests.readthedocs.io/en/latest/user/advanced/?highlight=proxy#proxies",
        default=None,
    )
    user_agent: str = Field(
        description="The user agent. Use this when you write an integration with Joe Sandbox so that it is possible to track how often an integration is being used.",
        default="OpenCTI",
    )
    systems: str = Field(
        description="Analysis systems to use (comma separated if multiple)",
        default="w10x64_office",
    )
    analysis_time: int = Field(description="Timeout for the analysis", default=300)
    internet_access: bool = Field(
        description="Enable full internet access in the analysis (must be false if internet simulation is true)",
        default=True,
    )
    internet_simulation: bool = Field(
        description="Enable internet simulation (must be false if internet access is true)",
        default=False,
    )
    hybrid_code_analysis: bool = Field(
        description="Enable Hybrid Code Analysis (HCA).", default=True
    )
    hybrid_decompilation: bool = Field(
        description="Enable Hybrid Decompilation (DEC).", default=True
    )
    report_cache: bool = Field(
        description="Enable the report cache. Check the cache for existing reports before running a full analysis.",
        default=False,
    )
    apk_instrumentation: bool = Field(
        description="Perform APK DEX code instrumentation.", default=True
    )
    amsi_unpacking: bool = Field(
        description="Perform generic unpacking using the Microsoft Antimalware Scan Interface (AMSI).",
        default=True,
    )
    ssl_inspection: bool = Field(description="Enable HTTPS inspection.", default=True)
    vba_instrumentation: bool = Field(
        description="Enable VBA instrumentation (two analyses are performed)",
        default=False,
    )
    js_instrumentation: bool = Field(
        description="Enable Javascript instrumentation (two analyses are performed)",
        default=False,
    )
    java_jar_tracing: bool = Field(
        description="Enable JAVA JAR tracing (two analyses are performed)",
        default=False,
    )
    dotnet_tracing: bool = Field(
        description="Enable .NET tracing (two analyses are performed)", default=False
    )
    start_as_normal_user: bool = Field(
        description="Starts the Sample with normal user privileges", default=False
    )
    system_date: str | None = Field(
        description="Change the analyzer's system date (helpful for date-aware samples), format is: YYYY-MM-DD",
        default=None,
    )
    language_and_locale: str | None = Field(
        description="Changes the language and locale of the analysis machine",
        default=None,
    )
    localized_internet_country: str | None = Field(
        description="Select the country to use for routing internet access through.",
        default=None,
    )
    email_notification: bool | None = Field(
        description="Enable email notification", default=None
    )
    archive_no_unpack: bool = Field(
        description="Do not unpack archives (zip, 7z etc) containing multiple files.",
        default=False,
    )
    hypervisor_based_inspection: bool = Field(
        description="Enable Hypervisor based Inspection", default=False
    )
    fast_mode: bool = Field(
        description="Fast Mode focuses on fast analysis and detection versus deep forensic analysis.",
        default=False,
    )
    secondary_results: bool = Field(
        description="Enables secondary results such as Yara rule generation, classification via Joe Sandbox Class as well as several detail reports. Analysis will run faster with disabled secondary results",
        default=True,
    )
    cookbook_file_path: str | None = Field(
        description="Path to a cookbook to run for the analysis", default=None
    )
    document_password: SecretStr = Field(
        description="Password for decrypting documents like MS Office and PDFs",
        default=SecretStr("1234"),
    )
    archive_password: SecretStr = Field(
        description="This password will be used to decrypt archives (zip, 7z, rar etc.).",
        default=SecretStr("infected"),
    )
    command_line_argument: str | None = Field(
        description="Will start the sample with the given command-line argument. Currently only available on Windows analyzers.",
        default=None,
    )
    encrypt_with_password: SecretStr | None = Field(
        description="Encryption password for analyses, AES-256 is used to encrypt files and the password is deleted on the backend after encrypting files",
        default=None,
    )
    browser: bool = Field(
        description="Use a browser for analysis of URLs, false == download/execute",
        default=False,
    )
    url_reputation: bool = Field(
        description="Lookup the reputation of URLs and domains to improve the analysis. This option will send URLs and domains to third party services and WHOIS servers!",
        default=False,
    )
    export_to_jbxview: bool = Field(
        description="Export the report(s) from this analysis to Joe Sandbox View.",
        default=False,
    )
    delete_after_days: int = Field(
        description="Delete the analysis after X days. If not set, the default value is used",
        default=30,
    )
    priority: int | None = Field(
        description="ON PREMISE EXCLUSIVE PARAMETER, set the priority of the submission between 1 and 10, high value means higher priority",
        default=None,
    )
    default_tlp: str = Field(
        description="The default TLP for newly created stix objects",
        default="TLP:CLEAR",
    )
    yara_color: str = Field(
        description="The color for yara labels applied to the observable",
        default="#0059f7",
    )
    default_color: str = Field(
        description="The color for default labels", default="#54483b"
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `JoeSandboxConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    joe_sandbox: JoeSandboxConfig = Field(default_factory=JoeSandboxConfig)
