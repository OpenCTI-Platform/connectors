from base_connector.config import BaseConnectorConfig
from pydantic import BaseModel


class EmailIntelConfig(BaseModel):
    imap_host: str
    imap_port: int
    imap_ssl: bool
    imap_username: str
    imap_password: str
    imap_mailbox: str

    relative_import_since_days: int  # FIXME timedelta


class ConnectorConfig(BaseConnectorConfig):
    email_intel: EmailIntelConfig
