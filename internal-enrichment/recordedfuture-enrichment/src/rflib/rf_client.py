"""Client for Recorded Future API
############################## TERMS OF USE ####################################
# The following code is provided for demonstration purposes only, and should   #
# not be used without independent verification. Recorded Future makes no       #
# representations or warranties, express, implied, statutory, or otherwise,    #
# regarding this code, and provides it strictly "as-is".                       #
# Recorded Future shall not be liable for, and you assume all risk of          #
# using the foregoing.                                                         #
################################################################################
"""
import urllib
import requests
import requests.exceptions


API_BASE = 'https://api.recordedfuture.com'
CONNECT_BASE = API_BASE + '/v2'
LINKS_BASE = API_BASE + '/links'
LINK_SEARCH = LINKS_BASE + '/search'


class RFClient:
    """class for talking to the RF API, specifically for enriching indicators"""

    def __init__(self, token, helper, header='OpenCTI-Enrichment/2.0'):
        """Inits function"""
        self.token = token
        headers = {'X-RFToken': token, 'User-Agent': header}
        self.session = requests.Session()
        self.session.headers.update(headers)
        self.helper = helper

    def full_enrichment(self, entity, type_):
        """Enrich an individual IOC"""
        enrichment = self._enrich(entity, type_)
        links = self._get_links(enrichment['entity']['id'])
        enrichment['links'] = links
        return enrichment

    def _enrich(self, entity, type_):
        """Make enrichment call to get entity and risk score"""
        fields = 'entity,risk'
        if type_.lower() == 'hash':
            fields += ',hashAlgorithm'
        url = '{}/{}/{}'.format(CONNECT_BASE, type_, urllib.parse.quote(entity, safe=""))
        res = self.session.get(url, params={'fields': fields})
        res.raise_for_status()
        return res.json()['data']

    def _get_links(self, rfid):
        """Get links for entity"""
        query = {
            "entities": ["{}".format(rfid)],
            "limits": {"search_scope": "medium", "per_entity_type": 100},
        }
        res = self.session.post(LINK_SEARCH, json=query)
        res.raise_for_status()
        return res.json()['data'][0]['links']
