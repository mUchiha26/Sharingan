from openai import OpenAI
from src.ai.base_provider import BaseAIProvider


class OllamaClient(BaseAIProvider):
    def __init__(
        self,
        base_url: str = "http://localhost:11434/v1",
        model: str = "qwen3.5-9b-unredacted:latest",
        timeout: int = 120,
    ):
        self.client = OpenAI(base_url=base_url, api_key="ollama", timeout=timeout)
        self.model = model

    def is_available(self) -> bool:
        try:
            self.client.models.list()
            return True
        except Exception:
            return False

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system_prompt},
                      {"role": "user", "content": user_prompt}]
        )
        return resp.choices[0].message.content or ""