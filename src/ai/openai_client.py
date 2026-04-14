"""Implement AI provider calls through an OpenAI-compatible API client."""

from openai import OpenAI

from src.ai.base_provider import BaseAIProvider


class OpenAIClient(BaseAIProvider):
    def __init__(self, api_key: str, model: str, timeout: int, base_url: str = "https://api.openai.com/v1"):
        self.client = OpenAI(base_url=base_url, api_key=api_key, timeout=timeout)
        self.model = model
        self.base_url = base_url
        self.timeout = timeout

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        return response.choices[0].message.content or ""