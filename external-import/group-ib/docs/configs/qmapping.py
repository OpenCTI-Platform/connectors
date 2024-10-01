class TIAMapping:
    """
    MISP-object:
        "name" - is the name of your object.
        "meta-category" - is the category where the object falls into. (such as file, network, financial, misc, internal...)
        "description" - is a summary of the object description.
        "version" - is the version number as a decimal value.
        "required" - is an array containing the minimal required attributes to describe the object.
        "requiredOneOf" - is an array containing the attributes where at least one needs to be present to describe the object.
        "attributes" - key names which object expected

        Attributes nested info:
            "misp-attribute" - field type
            "ui-priority" - number, priority in order
            "disable_correlation" - bool, create correlations or not. To suggest the disabling of correlation for a specific attribute.
            "to_ids" - IDS (Intrusion Detection System) - is a system that monitors network traffic for suspicious activity and alerts when such activity is discovered.

    Malware/CnC:
        Group by:
            For groups:
            - service.host
            - login
            - password

            For event:
            - events[].cnc.cnc
            - events[].source.id
            - events[].source.type
            - events[].clientIp.ip
            - events[].malware.name
            - events[].threatActor.name

        Contains CnC from:
            - compromised/access
            - compromised/account_group
            - compromised/bank_card_group
            - compromised/imei
            - compromised/masked_card
            - compromised/mule

    IoC/Common:
        Contains:
            - malware/cnc
            - apt/threat
            - hi/threat
            - apt/threat_actor
            - hi/threat_actor

    """

    # MISP-object: ti-account
    ACCOUNT = {
        "__description": "*Compromised account information",
        "service-domain": "service.domain",
        "service-url": "service.url",
        "username": "login",
        "password": "password",
    }
    # MISP-object: ti-article-ip
    ARTICLE_IP = {
        "__description": "*IP addresses found in the article",
        "ip-src": "data.ip.ip",
        "port": "data.ip.port",
        "name": "data.ip.tags",
    }
    # MISP-object: ti-article-domain
    ARTICLE_DOMAIN = {
        "__description": "*Domains found in the article",
        "domain": "data.domains.value",
    }
    # MISP-object: ti-c2
    C2 = {
        "__description": "*Command and Control Server (C2)",
        "url": "cnc.url",
        "domain": "cnc.domain",
        "ip-address": "cnc.ipv4.ip",
        "country": "cnc.ipv4.countryName",
        "city": "cnc.ipv4.city",
        "provider": "cnc.ipv4.provider",
        "platform": "platform",
    }
    # MISP-object: ti-c2
    C2_INFO = {
        "__description": "*Command and Control Server (C2) short",
        "url": "url",
        "domain": "domain",
        "platform": "platform",
    }
    # MISP-object: ti-cpe-table
    CPE_TABLE = {  # Common Platform Enumeration
        "__description": "*CPE table for vulnerability",  # Common Vulnerabilities and Exposures CVE CCE?
        "type": "cpeTable.type",
        "vendor": "cpeTable.vendor",
        "product": "cpeTable.product",
        "version": "cpeTable.version",
    }
    # MISP-object: ti-cvssv2
    CVSSv2 = {  # Common Vulnerability Scoring System
        "__description": "*CVSSv2 information",
        "score": "cvss.score",
        "vector": "cvss.vector",
    }
    # MISP-object: ti-contacts
    CONTACTS = {"__description": "*Contacts information", "contact": "contacts"}
    # MISP-object: ti-chat
    CHAT__TELEGRAM = {
        "__description": "*Compromised chat information",
        "server": "",
        "chat": "name",
        "chat-id": "chatStat.id",
        "tittle": "chatStat.title",
        "description": "",
        "message": "message",
    }
    # MISP-object: ti-chat
    CHAT__DISCORD = {
        "__description": "*Compromised chat information",
        "server": "channel.server",
        "chat": "channel.name",
        "chat-id": "channel.id",
        "tittle": "",
        "description": "channel.description",
        "message": "text",
    }
    # MISP-object: ti-chat
    CHAT_USER__TELEGRAM = {
        "__description": "*Compromised chat user",
        "user-id": "author.id",
        "username": "author.userName",
        "first-name": "author.firstName",
        "last-name": "author.lastName",
    }
    # MISP-object: ti-chat-user
    CHAT_USER__DISCORD = {
        "__description": "*Compromised chat user",
        "user-id": "author.id",
        "username": "author.name",
        "first-name": "",
        "last-name": "",
    }
    # MISP-object: ti-chat-user
    CHAT_USER__ARTICLE = {
        "__description": "*Article author",
        "user-id": "author.userId",
        "username": "author.screenName",
        "first-name": "author.name",
        "last-name": "",
    }
    # MISP-object: ti-credit-card
    CREDIT_CARD = {
        "__description": "*Compromised card",
        "cc-number": "cardInfo.number",
        "card-security-code": "events.cardInfo.cvv",
        "card-pin": "events.cardInfo.pin",
        "bank_name": "cardInfo.issuer.issuer",
        "payment-system": "cardInfo.system",
        "type": "cardInfo.type",
        "date": {
            "expiration": "events.cardInfo.validThru",
            "expiration-dt": "events.cardInfo.validThruDate",
        },
    }
    # MISP-object: ti-ddos
    DDOS = {  # MISP
        "__description": "*DDOS activity information",
        "text": "type",
        "protocol": "protocol",
        "dst-port": "port",
        "ip-dst": "target.ipv4.ip",
        "date": {
            "first-seen": "dateBegin",
            "last-seen": "dateEnd",
        },
    }
    # MISP-object: ti-email
    EMAIL__ARTICLE = {
        "__description": "*Emails found in the article",
        "to": "data.emails",
    }
    # MISP-object: ti-file
    FILE_IOC = {
        "__description": "*IoC File",
        "md5": "indicators.params.hashes.md5",
        "sha1": "indicators.params.hashes.sha1",
        "sha256": "indicators.params.hashes.sha256",
        "filename": "indicators.params.name",
        "size-in-bytes": "indicators.params.size",
    }
    # MISP-object: ti-file
    FILE_IOC__HASH = {"__description": "*IoC File", "hash": "hash"}
    # MISP-object: ti-file
    FILE_IOC__ARTICLE = {
        "__description": "*IoC File",
        "md5": "data.files.hashes.md5",
        "sha1": "data.files.hashes.sha1",
        "sha256": "data.files.hashes.sha256",
        "filename": "data.files.name",
        "size-in-bytes": "data.files.size",
    }
    # MISP-object: ti-file
    FILE_CONFIG = {
        "__description": "*IoC File",
        "md5": "*md5",
        "sha1": "*sha1",
        "sha256": "*sha256",
        "filename": "*name",
        "size-in-bytes": "*size",
    }
    # MISP-object: ti-leak-git-info
    GIT_LEAK = {
        "__description": "*Git repository leak information",
        "repository": "name",
        "match-type": "matchesTypes",
        "date": {"detection-date": "dateDetected"},
    }
    # MISP-object: ti-leak-git-revision
    GIT_LEAK__REVISION = {
        "__description": "*GIT repository leak revision information",
        "file": "files.name",
        "hash": "files.revisions.hash",
        "author-name": "files.revisions.info.authorName",
        "author-email": "files.revisions.info.authorEmail",
    }
    # MISP-object: ti-ip-address
    IP_ADDRESS = {  # MISP
        "__description": "*Source IP address",
        "ip-src": "ipv4.ip",
        "country": "ipv4.countryName",
        "country-code": "ipv4.countryCode",
        "city": "ipv4.city",
        "asn": "ipv4.asn",
        "date": {"first-seen": "dateFirstSeen", "last-seen": "dateDetected"},
    }
    # MISP-object: ti-ip-address
    IP_ADDRESS__CLIENT = {  # MISP
        "__description": "*Source IP address",
        "ip-src": "client.ipv4.ip",
        "country": "client.ipv4.countryName",
        "country-code": "client.ipv4.countryCode",
        "city": "client.ipv4.city",
        "asn": "client.ipv4.asn",
        "date": {"first-seen": "dateFirstSeen", "last-seen": "dateDetected"},
    }
    # MISP-object: ti-ip-address
    IP_ADDRESS__CNC = {
        "__description": "*Source IP address",
        "ip-src": "cnc.ipv4.ip",
        "country": "cnc.ipv4.countryName",
        "country-code": "ipv4.countryCode",
        "city": "cnc.ipv4.city",
        "asn": "cnc.ipv4.asn",
        "date": {"first-seen": "dateCompromised", "last-seen": "dateDetected"},
    }
    # MISP-object: ti-ip-address
    IP_ADDRESS__PHISHING = {
        "__description": "*Phishing IP address information",
        "ip-src": "phishing.phishing_ip.ip",
        "country": "phishing.phishing_ip.country_name",
        "country-code": "phishing.phishing_ip.country_code",
        "city": "phishing.phishing_ip.city",
        "provider": "phishing.phishing_ip.provider",
    }
    # MISP-object: ti-imei
    IMEI = {
        "__description": "*Compromised IMEI information",
        "imei": "device.imei",
        "model": "device.model",
        "os": "device.os",
    }
    # MISP-object: ti-money-mule
    MULE = {
        "__description": "*Compromised mule information",
        "account": "account",
        "issuer": "organization.name",
    }
    # MISP-object: ti-malware
    MALWARE = {"__description": "*Malware short information", "name": "malware.name"}
    # MISP-object: ti-malware
    MALWARE__LIST = {
        "__description": "*Malware short information",
        "name": "malwareList.name",
    }
    # MISP-object: ti-malware
    MALWARE__ARTICLE = {
        "__description": "*Malware short information",
        "name": "data.malware.name",
    }
    # MISP-object: ti-network-profile
    NETWORK_PROFILE = {
        "__description": "*IoC Network",
        "domain": "indicators.params.domain",
        "url": "indicators.params.url",
        "ip-address": "indicators.params.ipv4",
    }
    # MISP-object: ti-person
    PERSON__OWNER = {
        "__description": "*Personal information",
        "address": "owner.address",
        "full-name": "owner.name",
        "e-mail": "owner.email",
        "phone-number": "owner.phone",
    }
    # MISP-object: ti-person
    PERSON__PERSON = {
        "__description": "*Personal information",
        "address": "person.address",
        "full-name": "person.name",
        "e-mail": "person.email",
        "phone-number": "person.phone",
    }
    # MISP-object: ti-phishing
    PHISHING = {  # MISP
        "__description": "*Phishing URL information",
        "hostname": "phishingDomain.domain",
        "url": "url",
        "date": {"submission-time": "dateDetected", "takedown-time": "dateBlocked"},
    }
    # MISP-object: ti-phishing
    PHISHING__GROUP = {  # MISP
        "__description": "*Phishing URL information",
        "domain": "phishing.phishing_domain.domain",
        "url": "phishing.url",
        "date": {
            "submission-time": "phishing.date.detected",
            "takedown-time": "phishing.date.blocked",
        },
    }
    # MISP-object: ti-file
    PHISHING_KIT = {"__description": "*Phishing kit", "md5": "hash", "fullpath": "path"}
    # MISP-object: ti-url
    PHISHING_KIT_SOURCE = {
        "__description": "*Phishing kit source",
        "url": "downloadedFrom.url",
        "domain": "downloadedFrom.domain",
    }
    # MISP-object: ti-email
    PHISHING_KIT_EMAIL = {
        "__description": "*Emails found in the phishing kit",
        "to": "emails",
    }
    # MISP-object: ti-proxy-info
    PROXY_INFO = {
        "__description": "*Additional information about proxy",
        "anonymous": "anonymous",
        "port": "port",
        "type": "type",
    }
    # MISP-object: gib-leak-public-content
    PUBLIC_LEAK__CONTENT = {
        "__description": "*Public leak information",
        "author": "linkList.author",
        "hash": "linkList.hash",
        "link": "linkList.link",
        "size": "linkList.size",
        "source": "linkList.source",
        "title": "linkList.title",
        "date": {
            "detection-date": "linkList.dateDetected",
            "publishing-date": "linkList.datePublished",
        },
    }
    # MISP-object: gib-leak-public-info
    PUBLIC_LEAK__INFO = {
        "__description": "*Public leak common information",
        "syntax": "language",
        "hash": "hash",
        "size": "size",
        "creation-date": "created",
    }
    # MISP-object: gib-report
    REPORT = {
        "__description": "*Malware Report",
        "report-id": "id",  # Link: https://tap.group-ib.com/malware/reports/ + id
        "name": "name",
        "description": "shortDescription",
        "platform": "platform",
        "language": "langs",
        "category": "category",
        "malware-alias": "malwareAliasList",
        "date": {"date-updated": "updatedAt"},
    }
    # MISP-object: gib-sb-signature
    SIGNATURE = {
        "__description": "*Signature",
        "sid": "sid",
        "signature": "name",
        "software": "malware.name",
        "text": "content",
        "date": {"date-created": "createdAt"},
    }
    # MISP-object: gib-yara
    YARA = {
        "__description": "*Yara rule",
        "yara": "name",
        "yara-rule-name": "sourceName",
        "context": "content",
    }
    # MISP-object: gib-threat
    THREAT_INFO = {
        "__description": "*Threat Actor information from threat Report",
        "title": "title",
        "country": "countries",
        "language": "langs",
        "region": "regions",
        "sector": "sectors",
        "source": "sources",
        "date": {"date-published": "datePublished"},
    }
    # MISP-object: gib-threat-actor
    THREAT_ACTOR = {
        "__description": "*Threat Actor short information",
        "name": "threatActor.name",
    }
    # MISP-object: gib-threat-actor
    THREAT_ACTOR__TA_LIST = {
        "__description": "*Threat Actor short information",
        "name": "taList.name",
    }
    # MISP-object: gib-threat-actor
    THREAT_ACTOR__THREAT_ACTORS = {
        "__description": "*Threat Actor short information",
        "name": "threatActors.name",
    }
    # MISP-object: gib-threat-actor
    THREAT_ACTOR__THREAT_LIST = {
        "__description": "*Threat Actor short information",
        "name": "threatList.name",
    }
    # MISP-object: gib-threat-actor
    THREAT_ACTOR_INFO = {
        "__description": "*Threat Actor information",
        "name": "name",
        "country": "country",
        "description": "description",
        "alias": "aliases",
        "goal": "goals",
        "language": "langs",
        "role": "roles",
        "date": {"first-seen": "dateFirstSeen", "last-seen": "dateLastSeen"},
    }
    # MISP-object: gib-victim
    VICTIM__NAME = {"__description": "*Phishing attack target", "name": "brand"}
    # MISP-object: gib-victim
    VICTIM__COMPANY = {
        "__description": "*Targeted companies",
        "name": "targetedCompany",
    }
    # MISP-object: gib-victim
    VICTIM__TARGET = {
        "__description": "*Targeted brand",
        "name": "targetBrand",
        "regions": "targetCountryName",
        "sectors": "targetCategory",
        "domain": "targetDomain",
    }
    # MISP-object: gib-victim-location
    VICTIM_LOCATION__TARGET = {
        "__description": "*The targeted victim information",
        "url": "target.url",
        "domain": "target.domain",
        "ip-address": "target.ipv4.ip",
        "country": "target.ipv4.countryName",
        "city": "target.ipv4.city",
        "provider": "target.ipv4.provider",
        "category": "target.category",
    }
    # MISP-object: gib-victim-location
    VICTIM_LOCATION__TARGET_IP = {
        "__description": "*The targeted victim information",
        "url": "url",
        "domain": "targetDomain",
        "ip-address": "targetIp.ip",
        "country": "targetIp.countryName",
        "city": "targetIp.city",
        "provider": "targetIp.provider",
        "category": "",
    }
    # MISP-object: gib-victim-location
    VICTIM_LOCATION__CLIENT = {
        "__description": "*The targeted victim information",
        "url": "client.url",
        "domain": "client.domain",
        "ip-address": "client.ipv4.ip",
        "country": "client.ipv4.countryName",
        "city": "client.ipv4.city",
        "provider": "client.ipv4.provider",
        "category": "client.category",
    }
    # MISP-object: vulnerability
    VULNERABILITY = {
        "__description": "*List of CVEs connected to this threat",
        "id": "cveList.name",
    }
    # MISP-object: vulnerability
    VULNERABILITY__ARTICLE = {
        "__description": "*List of CVEs connected to this article",
        "id": "data.cve.id",
    }
    # MISP-object: vulnerability
    VULNERABILITY_INFO = {
        "__description": "*Vulnerability Information",
        "id": "id",
        "description": "extDescription",
        "credit": "reporter",
        "cvss-score": "extCvss.base",
        "cvss-string": "extCvss.vector",
        "vulnerable-configuration": "cpeTable.string23",
        "references": "exploitList.href",
        "date": {"published": "datePublished", "modified": "dateModified"},
    }
    # MISP-object: gib-date
    DATE = {
        "__description": "*Event date",
        "detection-date": "",
        "publishing-date": "",
        "first-seen": "",
        "last-seen": "",
        "expiration": "",
        "expiration-dt": "",
        "submission-time": "",
        "takedown-time": "",
        "date-created": "",
        "date-updated": "",
        "date-published": "",
        "date-modified": "",
        "date-compromised": "",
        "date-add": "",
    }
    DATE__THREAT = {
        "__description": "*Event date",
        "date-created": "createdAt",  # event created - no need for client(all)
        "date-updated": "updatedAt",  # event updated - no need for client(all)
        "first-seen": "dateFirstSeen",  # actor action first-seen
        "last-seen": "dateLastSeen",  # actor action last-seen
        "date-published": "datePublished",  # report published
    }
    DATE__THREAT_ACTOR = {
        "__description": "*Event date",
        "date-created": "createdAt",  # event created
        "date-updated": "updatedAt",  # event updated
        "first-seen": "stat.dateFirstSeen",  # actor first-seen
        "last-seen": "stat.dateLastSeen",  # actor last-seen
    }
    DATE__DDOS = {
        "__description": "*Event date",
        "detection-date": "dateReg",  # ddos detected
        "submission-time": "dateBegin",  # ddos start
        "takedown-time": "dateEnd",  # ddos end
    }
    DATE__DEFACE = {
        "__description": "*Event date",
        "detection-date": "date",  # deface detected
    }
    DATE__PHISHING = {
        "__description": "*Event date",
        "date-created": "date.added",  # event created
        "date-updated": "date.updated",  # event updated
        "submission-time": "date.detected",  # phishing detected
        "takedown-time": "date.blocked",  # phishing blocked
    }
    DATE__PHISHING_KIT = {
        "__description": "*Event date",
        "detection-date": "dateDetected",  # phishing kit detected           ?
        "first-seen": "dateFirstSeen",  # phishing kit changes first-seen ?
        "last-seen": "dateLastSeen",  # phishing kit changes last-seen  ?
    }
    # MISP-object: gib-metadata
    METADATA = {
        "__description": "*Feed metadata",
        "object-id": "id",
        "portal-link": "portalLink",
        "source": "source",
        "source-url": "link",
        "path-to-file": "path",
    }
    MITRE_MATRIX = {
        "__description": "*MITRE Matrix Adversarial Tactics, Techniques & Common Knowledge",
        "mitreMatrix": "mitreMatrix",  # mitreId -> used by map from common/matrix/vocab/techniques
    }
    EVALUATION = {
        "__description": "*Evaluation",
        "severity": "evaluation.severity",  # Severity level (green)
        "tlp": "evaluation.tlp",  # Traffic Light Protocol (amber)
        "admiralty_code": "evaluation.admiraltyCode",  # Data confidence level (C3)
    }

    """
        TACTIC (Mitre)
        FROM (Server)
        HOW (DDOS)
        WHO (Attacker)
        WITH (Malware)
        WHOM (Victim)
        PAYLOAD (File)
        ATTACK INFO (IP, Domain)
        ATTACK DESCRIPTION (Vulnerability)
        METADATA (Event metadata)
        EVALUATION (TLP, Severity, Admiralty)
    """
    MAPPING = {
        # Collection apt/threat - Advance Persistence Threat
        "apt/threat": {
            "threat_actor": {**THREAT_ACTOR},
            "threat_info": {**THREAT_INFO},
            "malware__list": {**MALWARE__LIST},
            "victim_company": {**VICTIM__COMPANY},
            "file_ioc": {**FILE_IOC},  # Nested: indicators.params
            "network_profile": {**NETWORK_PROFILE},  # Nested: indicators.params
            "vulnerability": {**VULNERABILITY},
            "mitre_matrix": {**MITRE_MATRIX},
            "metadata": {**METADATA},
            "evaluation": {**EVALUATION},
            "date": {**DATE},
        },
        "apt/threat_actor": {
            "threat_actor_info": {**THREAT_ACTOR_INFO},
            "metadata": {**METADATA},
            # NO EVALUATION
            "date": {**DATE},
        },
        "attacks/ddos": {
            "c2": {**C2},
            "ddos": {**DDOS},
            "threat_actor": {**THREAT_ACTOR},
            "malware": {**MALWARE},
            "victim_location": {**VICTIM_LOCATION__TARGET},
            "metadata": {**METADATA},
            "evaluation": {**EVALUATION},
            "date": {**DATE},
        },
        "attacks/deface": {
            "threat_actor": {**THREAT_ACTOR},
            "victim_location": {**VICTIM_LOCATION__TARGET_IP},
            "contacts": {**CONTACTS},
            "metadata": {**METADATA},
            "evaluation": {**EVALUATION},
            "date": {**DATE},
        },
        "attacks/phishing": {
            "phishing": {**PHISHING},
            "ip": {**IP_ADDRESS},
            "victim_brand": {**VICTIM__TARGET},
            "metadata": {**METADATA},
            "evaluation": {**EVALUATION},
            "date": {**DATE},
        },
        "attacks/phishing_group": {
            "phishing": {**PHISHING__GROUP},
            "ip": {**IP_ADDRESS__PHISHING},
            "threat_actor": {**THREAT_ACTOR},
            "victim_brand": {**VICTIM__NAME},
            "metadata": {**METADATA},
            "evaluation": {**EVALUATION},
            "date": {**DATE},
        },
        "attacks/phishing_kit": {
            "phishing_kit_source": {**PHISHING_KIT_SOURCE},  # Nested: downloadedFrom
            "phishing_kit": {**PHISHING_KIT},
            "phishing_kit_email": {**PHISHING_KIT_EMAIL},
            "victim_brand": {**VICTIM__TARGET},
            "metadata": {**METADATA},
            "evaluation": {**EVALUATION},
            "date": {**DATE},
        },
        "compromised/access": {
            "c2": {**C2},
            "ip_address_cnc": {**IP_ADDRESS__CNC},
            "malware": {**MALWARE},
            "victim_location": {**VICTIM_LOCATION__TARGET},
            "metadata": {**METADATA},
            "evaluation": {**EVALUATION},
            "date": {**DATE},
        },
        "compromised/account_group": {
            "c2": {**C2},  # Nested: events
            "threat_actor": {**THREAT_ACTOR},
            "malware": {**MALWARE},
            "account": {**ACCOUNT},
            "person": {**PERSON__PERSON},  # Nested: events
            "victim_location": {**VICTIM_LOCATION__CLIENT},  # Nested: events
            "metadata": {**METADATA},
            "evaluation": {**EVALUATION},
            "date": {**DATE},
        },
        "compromised/bank_card_group": {
            "c2": {**C2},  # Nested: events
            "threat_actor": {**THREAT_ACTOR},
            "malware": {**MALWARE},
            "ip_address__client": {**IP_ADDRESS__CLIENT},  # Nested: events
            "person__owner": {**PERSON__OWNER},  # Nested: events
            "credit_card": {**CREDIT_CARD},  # !!! - Need modifications
            "metadata": {**METADATA},
            "evaluation": {**EVALUATION},
            "date": {**DATE},
        },
        "compromised/discord": {
            "chat__discord": {
                **CHAT__DISCORD
            },  # chat - https://discordapp.com/channels/@me/userID/   18 numb
            "chat_user__discord": {
                **CHAT_USER__DISCORD
            },  # chat in server - https://discordapp.com/channels/serverID/chatID
            # https://support.discord.com/hc/en-us/community/posts/360037884532-Link-to-enter-in-DM
            "metadata": {**METADATA},
            # NO EVALUATION
            "date": {**DATE},
        },
        # Collection compromised/imei - IMEI (International Mobile Equipment Identity)
        "compromised/imei": {
            "c2": {**C2},
            "threat_actor": {**THREAT_ACTOR},
            "malware": {**MALWARE},
            "imei": {**IMEI},
            "victim_location": {**VICTIM_LOCATION__CLIENT},
            "metadata": {**METADATA},
            "evaluation": {**EVALUATION},
            "date": {**DATE},
        },
        "compromised/masked_card": {
            "c2": {**C2},
            "threat_actor": {**THREAT_ACTOR},
            "malware": {**MALWARE},
            "ip_address__client": {**IP_ADDRESS__CLIENT},
            "person__owner": {**PERSON__OWNER},  # !!! Need modifications
            "credit_card": {**CREDIT_CARD},  # !!! Need modifications
            "metadata": {**METADATA},
            "evaluation": {**EVALUATION},
            "date": {**DATE},
        },
        "compromised/messenger": {
            "chat__telegram": {**CHAT__TELEGRAM},  # Link: https://t.me/ + chatStat.name
            "chat_user__telegram": {**CHAT_USER__TELEGRAM},
            "metadata": {**METADATA},
            # NO EVALUATION
            "date": {**DATE},
        },
        # Collection compromised/mule - All information is about the threat actor
        "compromised/mule": {
            "c2": {**C2},
            "threat_actor": {**THREAT_ACTOR},
            "malware": {**MALWARE},
            "mule": {**MULE},
            "person": {**PERSON__PERSON},
            "metadata": {**METADATA},
            "evaluation": {**EVALUATION},
            "date": {**DATE},
        },
        "hi/open_threats": {
            "threat_actor__list": {**THREAT_ACTOR__THREAT_ACTORS},
            "malware__list": {**MALWARE__ARTICLE},
            "vulnerability": {**VULNERABILITY__ARTICLE},
            "file_ioc": {**FILE_IOC__ARTICLE},
            "emails": {**EMAIL__ARTICLE},
            "ip": {**ARTICLE_IP},
            "domain": {**ARTICLE_DOMAIN},
            "chat_user__article": {**CHAT_USER__ARTICLE},
            "metadata": {**METADATA},
            "evaluation": {**EVALUATION},
            "date": {**DATE},
        },
        "hi/threat": {
            "threat_actor": {**THREAT_ACTOR},
            "threat_info": {**THREAT_INFO},
            "malware__list": {**MALWARE__LIST},
            "victim_company": {**VICTIM__COMPANY},
            "file_ioc": {**FILE_IOC},  # Nested: indicators.params
            "network_profile": {**NETWORK_PROFILE},  # Nested: indicators.params
            "vulnerability": {**VULNERABILITY},
            "mitre_matrix": {**MITRE_MATRIX},
            "metadata": {**METADATA},
            "evaluation": {**EVALUATION},
            "date": {**DATE},
        },
        "hi/threat_actor": {
            "threat_actor_info": {**THREAT_ACTOR_INFO},
            "metadata": {**METADATA},
            # NO EVALUATION
            "date": {**DATE},
        },
        "ioc/common": {
            "threat_list": {**THREAT_ACTOR__THREAT_LIST},
            "malware__list": {**MALWARE__LIST},
            "file_ioc__hash": {**FILE_IOC__HASH},
            "network_profile": {**NETWORK_PROFILE},
            "metadata": {**METADATA},
            # NO EVALUATION
            "date": {**DATE},
        },
        "malware/cnc": {
            "c2_info": {**C2_INFO},
            "threat_actor": {**THREAT_ACTOR},
            "ip": {**IP_ADDRESS},  # Nested: ipv4
            "malware__list": {**MALWARE__LIST},
            "file_ioc": {**FILE_IOC},  # Nested: file
            "metadata": {**METADATA},
            # NO EVALUATION
            "date": {**DATE},
        },
        "malware/config": {
            "malware": {**MALWARE},
            "file_config": {**FILE_CONFIG},  # Nested: file
            "metadata": {**METADATA},
            # NO EVALUATION
            "date": {**DATE},
        },
        # Collection malware/malware - Malware Report Description
        "malware/malware": {
            "report": {**REPORT},
            "threat_actor__list": {**THREAT_ACTOR__TA_LIST},
            "signature": {**SIGNATURE},
            "yara": {**YARA},
            "mitre_matrix": {**MITRE_MATRIX},
            "metadata": {**METADATA},
            # NO EVALUATION
            "date": {**DATE},
        },
        "malware/signature": {
            "signature": {**SIGNATURE},
            "metadata": {**METADATA},
            # NO EVALUATION
            "date": {**DATE},
        },
        "malware/yara": {
            "yara": {**YARA},
            "malware": {**MALWARE},
            "metadata": {**METADATA},
            # NO EVALUATION
            "date": {**DATE},
        },
        "osi/git_repository": {
            "git_leak": {**GIT_LEAK},
            "git_leak__revision": {**GIT_LEAK__REVISION},  # Nested: files
            "metadata": {**METADATA},
            "evaluation": {**EVALUATION},
            "date": {**DATE},
        },
        "osi/public_leak": {
            "public_leak__content": {**PUBLIC_LEAK__CONTENT},  # Nested: linkList
            "public_leak__info": {**PUBLIC_LEAK__INFO},
            "metadata": {**METADATA},
            "evaluation": {**EVALUATION},
            "date": {**DATE},
        },
        "osi/vulnerability": {
            "vulnerability_info": {**VULNERABILITY_INFO},
            "cpe_table": {**CPE_TABLE},  # Nested: cpeTable
            "cvssv2": {**CVSSv2},
            "metadata": {**METADATA},
            "evaluation": {**EVALUATION},
            "date": {**DATE},
        },
        "suspicious_ip/open_proxy": {
            "ip": {**IP_ADDRESS},
            "proxy_info": {**PROXY_INFO},
            "metadata": {**METADATA},
            "evaluation": {**EVALUATION},
            "date": {**DATE},
        },
        "suspicious_ip/scanner": {
            "ip": {**IP_ADDRESS},
            "metadata": {**METADATA},
            "evaluation": {**EVALUATION},
            "date": {**DATE},
        },
        # Collection suspicious_ip/socks_proxy - We know only IP not ports. Socks5 used with extra auth. More protected.
        "suspicious_ip/socks_proxy": {
            "ip": {**IP_ADDRESS},
            # P???_I???
            "metadata": {**METADATA},
            "evaluation": {**EVALUATION},
            "date": {**DATE},
        },
        "suspicious_ip/tor_node": {
            "ip": {**IP_ADDRESS},
            "metadata": {**METADATA},
            "evaluation": {**EVALUATION},
            "date": {**DATE},
        },
        "suspicious_ip/vpn": {
            "ip": {**IP_ADDRESS},
            "metadata": {**METADATA},
            "evaluation": {**EVALUATION},
            "date": {**DATE},
        },
    }


# x = TIAMapping()
# import json
# print(json.dumps(x.MAPPING, indent=4))
