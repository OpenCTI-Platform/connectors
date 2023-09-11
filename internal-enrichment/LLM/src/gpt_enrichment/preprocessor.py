
from typing import Any
from bs4 import BeautifulSoup
class Preprocessor:
    def __init__(self,helper):
        super().__init__() #this is not used for now. Idea is to create a TextProcessor class and have Preprocessor and Postprocessor inherit from it.
        self.helper=helper

    
    def extract_p_text(self,HTML):
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
    
    def extract_all_text(blog : str) -> str:
        soup = BeautifulSoup(blog, "html.parser")
        blog = soup.get_text()
        return blog
    
    def preprocess(self, blog : str) -> str: #this is the main function
        blog = self.extract_p_text(blog)
        return blog

    