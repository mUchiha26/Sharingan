"""Minimal prompt templates used by tests and recon workflows."""

from dataclasses import dataclass


@dataclass(frozen=True)
class PromptTemplate:
    template: str

    def render(self, **kwargs) -> str:
        return self.template.format(**kwargs)


RECON_ANALYSIS_TEMPLATE = PromptTemplate(
    template=(
        "Analyze recon results for OS={os}. "
        "Observed ports={ports}. "
        "Return concise defensive recommendations."
    )
)
