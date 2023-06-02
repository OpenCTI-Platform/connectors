import stix2


def process(connector, campaign):
    campaign_id = campaign.get("id")

    connector.helper.log_debug(f"Processing campaign {campaign_id} ...")

    stix_campaign = create_campaign(connector, campaign)
    items = [stix_campaign]

    for attribution in campaign.get("...", []):
        items += [create_stix_relationship(connector, stix_campaign, campaign, attribution)]

    bundle = stix2.Bundle(objects=items, allow_custom=True)

    if bundle is None:
        connector.helper.log_error(f"Could not process campaign {campaign_id}. Skipping ...")

    return bundle


def create_campaign(connector, campaign):
    pass


def create_stix_relationship(connector, stix_campaign, campaign, attribution):
    pass
