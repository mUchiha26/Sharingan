from openai import OpenAI
from src.ai.base_provider import BaseAIProvider

class OpenRouterClient(BaseAIProvider):
    def __init__(self, api_key: str, model: str, timeout: int):
        self.client = OpenAI(base_url="https://openrouter.ai/api/v1", api_key=api_key, timeout=timeout)
        self.model = model

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system_prompt},
                      {"role": "user", "content": user_prompt}]
        )
        return resp.choices[0].message.content or ""