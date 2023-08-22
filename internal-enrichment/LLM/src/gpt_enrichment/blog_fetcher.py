from bs4 import BeautifulSoup
import requests
from pycti import OpenCTIConnectorHelper

class BlogFetcher:
    EXTERNAL_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Set-Fetch-Site': 'none',
        'Accept-Encoding': 'gzip, deflate',
        'Set-Fetch-Mode': 'navigate',
        'Sec-Fetch-Dest': 'document',
    }
    def get_html(helper: OpenCTIConnectorHelper, url : str) -> str:
        blog_html = requests.get(url, headers=BlogFetcher.EXTERNAL_HEADERS).text
        helper.log_debug(f"html:\n{blog_html}")
        return blog_html

    def extract_all(helper: OpenCTIConnectorHelper, blog : str) -> str:

        soup = BeautifulSoup(blog, "html.parser")

        blog = soup.get_text()
        
        helper.log_info(f"text:\n{blog}")

        return blog 
    
    def extract_p_text(HTML):
        soup = BeautifulSoup(HTML, 'html.parser')
        p_text = soup.find_all('p')
        p_text = [p.get_text() for p in p_text]
        p_text_last = []
        for p in p_text:
            flag = False
            for p_ot in p_text_last:
                if p in p_ot:
                    flag = True
                    break
                if p_ot in p:
                    p_text_last.remove(p_ot)
            if not flag:
                p_text_last.append(p)
        return ''.join([p_text_el for p_text_el in p_text_last])