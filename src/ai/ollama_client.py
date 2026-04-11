from openai import OpenAI
from src.ai.base_provider import BaseAIProvider

class OllamaClient(BaseAIProvider):
    def __init__(self, base_url: str, model: str, timeout: int):
        self.client = OpenAI(base_url=base_url, api_key="ollama", timeout=timeout)
        self.model = model

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system_prompt},
                      {"role": "user", "content": user_prompt}]
        )
        return resp.choices[0].message.content or ""