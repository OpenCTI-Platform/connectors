import openai
from pycti import OpenCTIConnectorHelper

class GptClient:
    def prompt(helper : OpenCTIConnectorHelper, blog : str, apikey : str, model : str, temperature : float, prompt_version : str):
        openai.api_key = apikey
        prompt_dir = f"gpt_enrichment/prompts/{prompt_version}/"
        system_prompt = open(prompt_dir + "system_prompt.txt", "r").read()
        user_prompt = open(prompt_dir + "user_prompt.txt", "r").read()

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