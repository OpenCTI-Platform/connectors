import openai
from pycti import OpenCTIConnectorHelper
from datetime import datetime

class GptClient:
    def prompt(helper : OpenCTIConnectorHelper, blog : str, apikey : str, model : str, temperature : float, prompt_version : str) -> str:
        return '''
{
    "title": "Storm-0978: Cyber Espionage and Ransomware Attacks with a Twist",
    "victims": [
        "N/A"
    ],
    "sectors":[
        "Government", "Finance", "Telecommunications"
    ],
    "victim_location": [
        "United States"
    ],
    "threat_actor": "Storm-0978",
    "threat_actor_aliases": [
        "DEV-0978"
    ],
    "malware": [
        "RomCom", "Industrial Spy", "Underground", "Trigona"
    ],
    "targeted_software": [
        "Microsoft Windows",
        "Microsoft Office"
    ],
    "tools": [
        "PowerShell",
        "Cobalt Strike"
    ],
    "CVE": [
        "CVE-2023-23397"
    ],
    "TTP": ["T1499", "Endpoint Denial of Service", "T1102", "Web Service", "T1072", "Software Deployment Tools"],
    "IoC": [
        {
            "type": "file:hashes.'SHA-256'",
            "value": "b2a0f0e1c2b2f1e1d2c3b4a5a6a7a8a9b0b1b2b3b4b5b6b7b8b9c0c1c2c3c4c5"
        },
        {
            "type": "file:hashes.'SHA-1'",
            "value": "a22cce4b39f389ee27accf5895383002cebf46b8"
        },
        {
            "type": "file:hashes.MD5",
            "value": "4c96f960ccc17c17bb8d1dc69488eb96"
        },
        {
            "type": "url",
            "value": "https://anakin.sky/walker/s.php"
        },
        {
            "type": "domain",
            "value": "anakin.sky"
        },
        {
            "type": "ipv4-addr",
            "value": "112.325.13.37"
        },
        {
            "type": "cryptocurrency-wallet",
            "value": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        }
    ]
}
''' #THIS IS A TEST REMOVE THIS LATER
        openai.api_key = apikey
        prompt_dir = f"gpt_enrichment/prompts/{prompt_version}/"
        system_prompt = open(prompt_dir + "system_prompt.txt", "r").read()
        user_prompt = open(prompt_dir + "user_prompt.txt", "r").read()
        helper.log_info(f"Querying the LLM @ time {datetime.now()}")
        response = openai.ChatCompletion.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt + blog},
            ],
            temperature=float(temperature),
            timeout=30
        )

        helper.log_info(f"System prompt:{system_prompt}")
        helper.log_info(f"User prompt:{user_prompt}")
        helper.log_info(f"Response from GPT-engine: {response}")


        return response["choices"][0]["message"]["content"]