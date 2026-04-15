import os


def get_config(helper):
    return {
        "akamai_base_url": os.environ["AKAMAI_BASE_URL"],
        "client_token": os.environ["AKAMAI_CLIENT_TOKEN"],
        "client_secret": os.environ["AKAMAI_CLIENT_SECRET"],
        "access_token": os.environ["AKAMAI_ACCESS_TOKEN"],
        "client_list_id": os.environ["AKAMAI_CLIENT_LIST_ID"],
    }