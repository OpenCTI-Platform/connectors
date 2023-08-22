from bs4 import BeautifulSoup
import requests
from pycti import OpenCTIConnectorHelper

class BlogFetcher:
    def __init__(self):
        self.EXTERNAL_HEADERS = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Set-Fetch-Site': 'none',
            'Accept-Encoding': 'gzip, deflate',
            'Set-Fetch-Mode': 'navigate',
            'Sec-Fetch-Dest': 'document',
        }

    def get_html(self,helper: OpenCTIConnectorHelper, url : str) -> str:
        blog_html = requests.get(url, headers=self.EXTERNAL_HEADERS).text
        helper.log_debug(f"html:\n{blog_html}")
        return blog_html



    
