import urllib

import requests
import validators


def intelixlookup(token, observable, regionuri, observable_type) -> dict:
    # use Validators to redirect the observable to the correct Intelix endpoint
    if validators.ipv4(observable):
        u = f"{regionuri}/lookup/ips/v1/{observable}"
    elif validators.domain(observable) or validators.url(observable):
        observable = urllib.parse.quote(observable.encode("utf8"), safe="")
        u = f"{regionuri}/lookup/urls/v1/{observable}"
    elif validators.sha256(observable):
        u = f"{regionuri}/lookup/files/v1/{observable}"
    else:
        raise ValueError("Observable not supported by connector")

    headers = {"Authorization": f"{token}"}
    r = requests.get(u, headers=headers)
    if not r.ok:
        raise ValueError("Intelix API returned an error")
    j = r.json()
    response = {}
    # Set the URL for the external reponse reference
    response["url"] = u

    # Color the Labels
    maliciouscolor = "#d90e18"
    warncolor = "#FF8F00"
    goodcolor = "#32c822"

    # File reponses
    if observable_type == "Artifact" or observable_type == "StixFile":
        if "reputationScore" in j:
            response["reputationScore"] = j["reputationScore"]
            if j["reputationScore"] <= 19:
                response["description"] = "Malware"
                response["category"] = "Malware"
                response["labelcolor"] = maliciouscolor
            elif j["reputationScore"] <= 29:
                response["description"] = "PUA (potentially unwanted application)"
                response["category"] = "PUA (potentially unwanted application)"
                response["labelcolor"] = warncolor
            elif j["reputationScore"] <= 69:
                response["description"] = "Unknown/suspicious"
                response["category"] = "Unknown/suspicious"
                response["labelcolor"] = warncolor
            elif j["reputationScore"] <= 100:
                response["description"] = "Known good"
                response["category"] = "Known good"
                response["labelcolor"] = goodcolor
        if "detectionName" in j:
            response["detectionName"] = j["detectionName"]

        return response

    # IP reponses
    if observable_type == "IPv4-Addr":
        if "category" in j:
            intelixdescriptions = {
                "malware": "Known source of malware",
                "botnet": "Known FUR, TFX and RIP bot proxy IP",
                "spam_mta": "Known spam network",
                "phishing": "Known source of phishing",
                "enduser_network": "Known dynamic IP",
                "generic_mta": "Known mail server",
                "clean_mta": "Known whitelisted mail server",
                "free_mta": "Known free email service provider",
                "bulk_mta": "Known bulk email service provider",
                "isp_mta": "Known ISP outbound mail server",
                "biz_mta": "Known corporate email service provider",
                "bulk_mta_grey": "Known grey bulk email service provider",
                "news_mta": "Known newsletter provider",
                "notifications_mta": "Notification alert",
                "illegal": "Suspected criminal source",
            }
            observablecategory = j["category"][0]
            # Grab the Description from the DICT
            response["description"] = intelixdescriptions[observablecategory]
            # Remove the category underscore and title the label
            response["category"] = observablecategory.replace("_", " ")
            # Give the category the correct color
            if (
                observablecategory == "malware"
                or observablecategory == "botnet"
                or observablecategory == "spam_mta"
                or observablecategory == "phishing"
                or observablecategory == "illegal"
            ):
                response["labelcolor"] = maliciouscolor

            elif (
                observablecategory == "free_mta"
                or observablecategory == "bulk_mta"
                or observablecategory == "bulk_mta_grey"
            ):
                response["labelcolor"] = warncolor

            elif (
                observablecategory == "enduser_network"
                or observablecategory == "generic_mta"
                or observablecategory == "clean_mta"
                or observablecategory == "isp_mta"
                or observablecategory == "biz_mta"
                or observablecategory == "news_mta"
                or observablecategory == "notifications_mta"
            ):
                response["labelcolor"] = goodcolor

            else:
                response["labelcolor"] = goodcolor

        else:
            response["description"] = "Unknown to SophosLabs"
            response["category"] = "Unknown"
            response["labelcolor"] = goodcolor

        return response

    # URL reponses
    if observable_type == "Url" or observable_type == "Domain-Name":
        intelixdescriptions = {
            "PROD_UNCATEGORIZED": "Uncategorized",
            "PROD_ADVERTISEMENTS": "Unwanted. Sites serving advertising content. Blocking advertisements reduces unnecessary bandwidth usage and reduces risk of compromise through poorly controlled advertising content.",
            "PROD_ALCOHOL_AND_TOBACCO": "Adult. Sites that provide information about, promote or support the sale or use of alcoholic and tobacco and related items or beverages. Inappropriate in educational context.",
            "PROD_ANONYMIZERS": "Risky. Sites whose main purpose is to allow users to access content from other sites that may otherwise be blocked. Prevent users circumventing URL filtering.",
            "PROD_AUCTIONS_AND_CLASSIFIED_ADS": "Services. Sites providing services for individuals to advertise or trade in goods or services. Users can waste a lot of time doing personal transactions in a work environment.",
            "PROD_BLOGS_AND_FORUMS": "Social Networking. Sites whose primary content is user-generated postings or discussions. Posting to blogs and forums can be time wasting. Access to user-generated content can be risky in controlled environments such as schools.",
            "PROD_GENERAL_BUSINESS": "BizGov. Sites concerned with or operated by general business concerns, business or industry associations that do not fit into other specific categories. Generally allowed in a business context.",
            "PROD_BUSINESS_CLOUD_APPS**": "Business-focused web applications. Managing access to cloud apps to help avoid data leakage to unauthorized locations.",
            "PROD_BUSINESS_NETWORKING": "BizGov. Social networking services dedicated to connecting people at a business or professional level, e.g. LinkedIn. May be allowed in more restrictive contexts.",
            "PROD_COMMAND_AND_CONTROL": "Risky. Locations used for communication by malicious software. Can help identify endpoints that may be infected.",
            "PROD_CONTENT_DELIVERY": "Infrastructure. Sites providing content delivery services. These sites are generally only accessed as secondary content from a primary domain's site and should be permitted. These sites should generally be allowed as their content is usually only accessed via links or embedding from other websites that can be controlled by category.",
            "PROD_CONTROLLED_SUBSTANCES": "Drugs & Health. Sites providing information about or promoting the use, trade or manufacture of drugs other than marijuana that are controlled or regulated in most jurisdictions. Generally illegal so access would usually be blocked.",
            "PROD_CRIMINAL_ACTIVITY": "Illegal. Sites engaged in, promoting or inciting non-violent criminal behaviour, dishonesty or across a wide range of societies. Inappropriate for most situations.",
            "PROD_CRL_AND_OCSP": "Infrastructure. Certificate revocation services. These sites need to be allowed to ensure correct operation of certificate revocation processes.",
            "PROD_DOWNLOAD_FREEWARE_AND_SHAREWARE": "Bandwidth. Legal Open Source download stores.",
            "PROD_DYNAMIC_DNS_AND_ISP_SITES": "Risky. Sites that are hosted on ISP networks that rely on dynamic DNS. Sites in this category are unlikely to be legitimate, professionally-run websites and may be pop-up sites or used for malware distribution.",
            "PROD_EDUCATIONAL_INSTITUTIONS": "Education. Sites sponsored by school, universities or other education or research organizations. May be allowed in restrictive policies.",
            "PROD_ENTERTAINMENT": "Entertainment. Sites about television, music, movies, radio, celebrities, books and magazines. Time wasting.",
            "PROD_EXTREME": "Adult. Sites containing extreme pornographic or other graphic visual content. Generally blocked as inappropriate.",
            "PROD_FASHION_AND_BEAUTY": "Entertainment. Sites relating to fashion, glamour and aesthetics. Personal browsing may not be permitted in work environments.",
            "PROD_FINANCIAL_SERVICES": "BizGov. Sites offering or providing information about financial services, including personal and commercial online banking, credit cards and insurance. Excludes online trading. May be necessary to monitor or use for selective HTTPS filtering.",
            "PROD_GAMBLING": "Entertainment. Sites that offer or provide information about gambling services, online betting or games of chance involving wagers of money. Time-consuming, inappropriate for work even where other personal browsing may be allowed.",
            "PROD_GAMES": "Entertainment. Online games and sites relating to computer gaming. Does not include board games, which fall under hobbies. Time-consuming, inappropriate for work even where other personal browsing may be allowed.",
            "PROD_GOVERNMENT": "BizGov. Sites operated or sponsored by government organizations, providing information including the operation of government departments and services provided. May be allowed in more restrictive contexts.",
            "PROD_HACKING": "Risky. Sites providing tools or instruction in illegal or questionable activities to access computer systems, data or networks. Prevent access to tools or content that may be abused on a corporate network.",
            "PROD_HEALTH_AND_MEDICINES": "Drugs & Health. Sites providing information about medical and healthcare services, prescription and legitimate non-prescription pharmaceuticals, and other personal health issues. May be controlled or monitored in some situations.",
            "PROD_HOBBIES": "Entertainment. Sites promoting or supporting private pasttimes. Personal browsing may not be permitted in work environments.",
            "PROD_HUNTING_AND_FISHING": "Entertainment. Sites dedicated to blood sports and fishing that may contain gory or disturbing images. May contain unpleasant or distasteful content that is unsuitable in education or other sensitive environments.",
            "PROD_IMAGE_SEARCH": "Search. Sites or services dedicated to providing the ability to search large quantities of images. May provide access to inappropriate content from sites that would not otherwise be allowed.",
            "PROD_INFORMATION_TECHNOLOGY": "BizGov. Sites concerned with or relating to information technology including hardware, software, networks, services and sites concerned with the sale of them. Generally allowed in a business context.",
            "PROD_INTELLECTUAL_PIRACY": "Illegal. Sites supporting, enabling or engaging in sharing of content that is protected intellectual property. Risk of liability for organizations if they allow infringement of IP rights.",
            "PROD_INTOLERANCE_AND_HATE": "Adult. Sites that promote or condone intolerance or hateful attitudes towards individuals or groups. Generally blocked as inappropriate.",
            "PROD_JOB_SEARCH": "BizGov. Sites providing information about job vacancies or supporting job seeking activities. May be monitored or controlled in a business context.",
            "PROD_KIDS_SITES": "Children. Sites intended primarily for the use of children. May be permitted in more restrictive environments.",
            "PROD_LEGAL_HIGHS": "Drugs & Health. Sites providing information about the growth, trade or use of non-controlled substances for the purpose of inducing highs or other narcotic effects. Not appropriate for more controlled environments such as education.",
            "PROD_LIVE_AUDIO": "Bandwidth. Sites offering live audio streaming of events or programming. Eliminate a significant source of non-business bandwidth.",
            "PROD_LIVE_VIDEO": "Bandwidth. Sites offering live video streaming of events or other programming. Eliminate a significant source of non-business bandwidth.",
            "PROD_MARIJUANA": "Drugs & Health. Sites providing information about the growth, trade or use of marijuana. Although still widely illegal or controlled, it is becoming more accepted in some jurisdictions.",
            "PROD_MILITANCY_AND_EXTREMIST": "Adult. Sites promoting or sponsored by groups advocating anti-government beliefs. Generally blocked as inappropriate.",
            "PROD_MILITARY": "BizGov. Sites sponsored by armed forces organizations or their agencies. May be allowed in more restrictive contexts.",
            "PROD_NEWLY_REGISTERED_WEBSITES": "Risky. Sites using recently registered domains that have yet to be assessed or whose content has yet to be established. Sites hosted on recently-registered domains are more likely to be poorly managed or deliberately malicious in nature.",
            "PROD_NEWS": "Sites that offer news and opinion about current events. Personal browsing may not be permitted in work environments.",
            "PROD_NGOS_AND_NON_PROFITS": "BizGov. Sites relating to charitable and non-profit organizations whether local or global. May be allowed in more restrictive contexts.",
            "PROD_NUDITY": "Sexual. Sites containing non-sexual depictions of human forms in varying states of undress. May be OK where more explicit material is not allowed, although still inappropriate for kids.",
            "PROD_ONLINE_CHAT": "Social Networking. Sites enabling one-to-one or group real-time messaging. Risks of time-wasting, data sharing, inappropriate communications (chinese walls in financial institutions), unmonitored communications.",
            "PROD_ONLINE_SHOPPING": "Services. Sites that provide online purchasing opportunities. Time wasting.",
            "PROD_PARKED_DOMAINS": "Unwanted. Domains that are not actively being used to host original content. Generally domains that are for sale or non-malicious typo-squatting. Reduce unnecessary traffic and limit potential for attack from poorly controlled sites.",
            "PROD_PEER_TO_PEER_AND_TORRENTS": "Bandwidth. Sites offering links to content that can be retrieved using peer-to-peer technologies such as Bittorrent. Eliminate a significant source of non-business bandwidth or potential IP/copyright infringement.",
            "PROD_PERSONAL_CLOUD_APPS": "Data Loss. Web services associated with apps that may provide user data storage. Risk of data leakage - note-taking apps, calendar apps, to-do list apps, all require sharing of information that could be sensitive.",
            "PROD_PERSONAL_NETWORK_STORAGE": "Data Loss. Web services associated with apps that may provide user data storage. Risk of data leakage - corporate files or content being posted to personal network storage accounts.",
            "PROD_PERSONALS_AND_DATING": "Social Networking. Sites providing or supporting dating, romantic connections or matchmaking. Do it on your own time. Also, content could be considered inappropriate in controlled environments.",
            "PROD_PERSONAL_SITES": "Risky. Sites operated by private individuals with space to host unrestricted custom content. Sites that may not be well managed could introduce risk or contain inappropriate content.",
            "PROD_PHISHING_AND_FRAUD": "Risky. Content designed to defraud users, including sites that masquerade as legitimate websites to gain financial advantage. Protect users from fraud.",
            "PROD_PHOTO_GALLERIES": "Search. Sites that provide services for storage and display of image content. Concerns about inappropriate content.",
            "PROD_PLAGIARISM": "Education. Sites providing material intended enabling cheating in educational or academic contexts. Block or monitor unethical behaviour in schools.",
            "PROD_POLITICAL_ORGANIZATION": "BizGov. Sites operated by or supporting political parties, election campaigns, lobbying or other political activities. May be allowed in more restrictive contexts.",
            "PROD_PORTAL_SITES": "Search. Sites that provide lists or directories of content on other sites. Like search engines, may provide content from sites categories that are not considered appropriate.",
            "PROD_PROFESSIONAL_AND_WORKERS_ORGANIZATIONS": "BizGov. Sites sponsored by organizations supporting people with common professional or trade interests and qualification. May be allowed in more restrictive contexts.",
            "PROD_PRO_SUICIDE_AND_SELF_HARM": "Adult. Sites promoting suicide and self-harm. Schools may need to monitor student activities for potential areas of concern.",
            "PROD_RADIO_AND_AUDIO_HOSTING": "Bandwidth. Sites offering legitimate on-demand audio/music content, e.g. Spotify, Pandora. Eliminate a significant source of non-business bandwidth or timewasting.",
            "PROD_REAL_ESTATE": "Services. Sites dedicated to the sale or purchase of real estate. Users should not waste their work day looking for new houses.",
            "PROD_REFERENCE": "Education. Sites containing reference materials and educational content including teaching materials, academic journals, encyclopedias and dictionaries. Sites likely to be allowed even for restrictive policies.",
            "PROD_RELIGION_AND_SPIRITUALITY": "Entertainment. Sites sponsored by or promoting spiritual and religious organizations and beliefs. Personal browsing may not be permitted in work environments.",
            "PROD_RESTAURANTS_AND_DINING": "Services. Sites sponsored by or promoting restaurants or other dining establishment, including reservation services, reviews and recommendations. Some customers might prefer users organize their social engagements on their own time.",
            "PROD_SEARCH_ENGINES": "Search. Sites dedicated to providing services to search for internet content. Search engines may be allowed, in otherwise restrictive policies. Also used to target HTTPS filtering for search terms/search results.",
            "PROD_SEX_EDUCATION": "Education. Sites that deal with sex and sexuality in an educational context. May be allowed for certain classes or under certain circumstances in an educational context.",
            "PROD_SEXUALLY_EXPLICIT": "Sexual. Sites containing depictions of nudity in a sexual context; sex-oriented businesses, goods and services. Generally blocked as inappropriate.",
            "PROD_SOCIAL_NETWORKS": "Social Networking. Mainstream social networking sites providing a range of personal services enabling users to communicate with groups of contacts.",
            "PROD_SOFTWARE_UPDATES": "Infrastructure. Sites providing updates to mainstream software products. These sites should usually be allowed to ensure software updates for mainstream products can be downloaded and installed when necessary.",
            "PROD_SPAM_URLS": "Risky. Pages and sites that have been used in spam email campaigns. Prevent access to unwanted and potentially risky content.",
            "PROD_SPORTS": "Entertainment. Sites covering professional and amateur sports and associated businesses including sporting equipment. Personal browsing may not be permitted in work environments.",
            "PROD_SPYWARE_AND_MALWARE": "Risky. Pages and sites associated with distribution, creation or trade in spyware or malicious software. Prevent risky web access.",
            "PROD_STOCKS_AND_TRADING": "Services. Sites providing online trading services. Users should not be spending work time trading stocks.",
            "PROD_SURVEILLANCE": "Bandwidth. URLs associated with video surveillance systems. Users consume a lot of bandwidth having a home surveillance system running on their desktop all day.",
            "PROD_SWIMWEAR_LINGERIE": "Sexual. Sites containing suggestive but not overtly sexual imagery, including sites concerned with the promotion or sale of lingerie and swimwear. May be OK where more explicit material is not allowed, although still inappropriate for kids.",
            "PROD_TRANSLATORS": "Risky. Sites enabling access to content from other sites as a function of providing translation services. Can be used to access sites that would otherwise be blocked.",
            "PROD_TRAVEL": "Services. Sites providing travel booking services or providing recommendations or reviews of travel destinations. Time wasting.",
            "PROD_UNAUTHORIZED_SOFTWARE_STORES": "Risky. Sites providing software or apps for mobile devices or computers that are of questionable legitimacy. Prevent access to potentially malicious or trojanized apps for software.",
            "PROD_VIDEO_HOSTING": "Bandwidth. Sites offering on-demand video content, e.g. Youtube. Eliminate a significant source of non-business bandwidth.",
            "PROD_VOICE_AND_VIDEO_CALLS": "Bandwidth. Traffic related to internet-based telephony and video calling. Eliminate a significant source of non-business bandwidth or unmonitored communications.",
            "PROD_WEAPONS": "Adult. Sites promoting the sale and use of weapons and related items. May be considered inappropriate for children.",
            "PROD_WEB_E_MAIL": "Data Loss. Sites providing web-based email services allowing customers to send and receive messages with other email systems.",
            "PROD_SOCIETY_AND_CULTURE": "Society & Culture.",
            "PROD_VEHICLES": "Vehicles.",
            "SEC_UNCATEGORIZED": "Uncategorized.",
            "SEC_ILLEGAL_PHISHING": "Sites involved in phishing and telephone scams, service theft advice sites, and plagiarism and cheating sites, including the sale of research papers.",
            "SEC_MALWARE_DIALER_REPOSITORY": "Sites that host software which attempts to call pay for phone services without the consent of the user.",
            "SEC_MALWARE_HACKING": "Sites that provide information on compromising servers and exploiting vulnerabilities in software.",
            "SEC_MALWARE_INFECTED": "Otherwise legitimate sites that have been compromised and are serving malware or redirecting to malware hosting sites.",
            "SEC_MALWARE_RAT_REPOSITORY": "Sites that host software to mass email spam and malware.",
            "SEC_MALWARE_REFERENCE": "Sites that provide information on malware authoring.",
            "SEC_MALWARE_REPOSITORY": "Sites that host malware and are under control of malware authors.",
            "SEC_MALWARE_SPYWARE_INSTALL": "Sites that provide or promote information gathering or tracking that is unknown to, or done without the explicit consent of, the end user or the organization.",
            "SEC_MALWARE_SPYWARE_REPOSITORY": "Sites that provide or promote information gathering or tracking that is unknown to, or done without the explicit consent of, the end user or the organization.",
            "SEC_MALWARE_CALLHOME": "Sites that malware infected computers send information to about the infected computer.",
            "SEC_PUA_DIALER": "Sites that host software which attempts to call pay for phone services without the consent of the user.",
            "SEC_SPAM_CHINESE": "URLs found in spam from Chinese sources.",
            "SEC_SPAM_DRUGS": "URLs found in spam mentioning health and medicine.",
            "SEC_SPAM_MORTGAGE": "URLs found in spam mentioning mortgage rates.",
            "SEC_SPAM_OTHER": "URLs found in spam.",
            "SEC_SPAM_PRODUCT": "URLs found in spam mentioning general products and services.",
            "SEC_SPAM_RUSSIAN": "URLs found in spam from Russian sources.",
            "SEC_SPAM_STOCK": "URLs found in spam mentioning finance and stocks.",
            "SEC_SPAM_SURVEY": "URLs found in spam where the call to action requests the user to take a survey.",
            "SEC_SPAM_THAI": "URLs found in spam from Thai sources.",
            "SEC_TRUSTED_UPDATE_SITE": "Trusted sites like update.microsoft.com.",
            "SEC_PUA_ADWARE": "Sites of banner ad servers, sites with pop-up advertisements, and sites with known adware.",
            "SEC_PUA_SYSTEM_MONITOR": "Sites hosting software designed to monitor computer use.",
            "SEC_PUA_REMOTE_ADMIN_TOOL": "Sites hosting software designed to remotely control a computer by an administrator.",
            "SEC_PUA_HACKING_TOOL": "Sites hosting software for the purpose of hacking passwords, creating viruses, gaining access to other computers and computerized communication systems.",
            "SEC_PUA_OTHER": "Sites hosting potentially unwanted applications.",
        }
        if "productivityCategory" in j:
            observablecategory = j["productivityCategory"]
        elif "securityCategory" in j:
            observablecategory = j["securityCategory"]

        # Grab the Description from the DICT
        response["description"] = intelixdescriptions[observablecategory]
        # Remove the category underscore and title the label
        response["category"] = observablecategory.replace("_", " ")
        # Set label color based on risk
        if "riskLevel" in j:
            if j["riskLevel"] == "HIGH" or j["riskLevel"] == "MEDIUM":
                response["labelcolor"] = maliciouscolor
            elif j["riskLevel"] == "UNCLASSIFIED":
                response["labelcolor"] = warncolor
            elif j["riskLevel"] == "TRUSTED" or j["riskLevel"] == "LOW":
                response["labelcolor"] = goodcolor
        else:
            response["labelcolor"] = goodcolor
        return response
