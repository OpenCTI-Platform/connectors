from email_client.base import BaseEmailClient


def create_email_client(config) -> BaseEmailClient:
    """Factory: create the appropriate email client based on protocol config."""
    protocol = config.email_cases.protocol

    if protocol == "imap":
        from email_client.imap_client import ImapClient

        return ImapClient(
            host=config.email_cases.imap_host,
            port=config.email_cases.imap_port,
            username=config.email_cases.imap_username,
            password=config.email_cases.imap_password,
            folder=config.email_cases.imap_folder,
            use_ssl=config.email_cases.imap_use_ssl,
            tls_verify=config.email_cases.tls_verify,
        )

    if protocol == "microsoft_graph":
        from email_client.graph_client import GraphClient

        return GraphClient(
            tenant_id=config.email_cases.graph_tenant_id,
            client_id=config.email_cases.graph_client_id,
            client_secret=config.email_cases.graph_client_secret,
            user_id=config.email_cases.graph_user_id,
            tls_verify=config.email_cases.tls_verify,
        )

    if protocol == "gmail":
        from email_client.gmail_client import GmailClient

        return GmailClient(
            credentials_file=config.email_cases.gmail_credentials_file,
            user_id=config.email_cases.gmail_user_id,
            tls_verify=config.email_cases.tls_verify,
        )

    if protocol == "ews":
        from email_client.ews_client import EwsClient

        return EwsClient(
            server=config.email_cases.ews_server,
            username=config.email_cases.ews_username,
            password=config.email_cases.ews_password,
            auth_type=config.email_cases.ews_auth_type,
            tls_verify=config.email_cases.tls_verify,
        )

    raise ValueError(f"Unsupported email protocol: {protocol}")
