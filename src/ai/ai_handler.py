# src/core/ai_handler.py
"""
Local AI Handler using Qwen via Ollama
MVP Focus: Analyze scan results, suggest ONE attack path + remediation
"""
import ollama
import json
import logging
from pydantic import BaseModel
from typing import Optional

logger = logging.getLogger(__name__)

class AIRecommendation(BaseModel):
    """Structured output from AI analysis"""
    finding_summary: str
    mitre_technique: str  # e.g., "T1190"
    attack_suggestion: str  # What COULD be done (not automated!)
    risk_level: str  # "LOW", "MEDIUM", "HIGH"
    short_term_fix: str  # Immediate mitigation
    long_term_fix: str   # Architectural improvement
    confidence: float  # 0.0 to 1.0

class QwenHandler:
    """Minimal Qwen/Ollama integration for security analysis"""
    
    def __init__(self, model: str = "qwen3.5:8b", audit_logger=None):
        self.model = model
        self.audit = audit_logger or logging.getLogger("ai")
        # Test connection
        try:
            ollama.chat(model=model, messages=[{"role": "user", "content": "ping"}])
            logger.info(f"Connected to Ollama model: {model}")
        except Exception as e:
            logger.error(f"Ollama connection failed: {e}")
            raise

    def _audit(self, level: str, event: str, **fields) -> None:
        """Log consistently with either stdlib logging or structured loggers."""
        log_fn = getattr(self.audit, level, None)
        if not callable(log_fn):
            return
        try:
            log_fn(event, **fields)
        except TypeError:
            details = " ".join(f"{k}={v}" for k, v in fields.items())
            log_fn(f"{event} {details}".strip())
    
    def _build_prompt(self, scan_result: dict, context: dict) -> str:
        """Craft security-focused prompt with guardrails"""
        return f"""
You are a senior penetration tester assisting with a security assessment.
Analyze the following scan results and provide EXACTLY ONE prioritized recommendation.

## SCAN RESULTS
{json.dumps(scan_result, indent=2)}

## ENGAGEMENT CONTEXT
- Scope: {context.get('scope', 'Not specified')}
- Goal: {context.get('goal', 'Reconnaissance')}
- Rules: NO automated exploitation, suggestions only

## REQUIRED OUTPUT FORMAT (JSON ONLY)
{{
  "finding_summary": "Brief description of the most critical finding",
  "mitre_technique": "ATT&CK ID like T1190",
  "attack_suggestion": "What a tester COULD try (human-executed only)",
  "risk_level": "LOW|MEDIUM|HIGH",
  "short_term_fix": "Immediate mitigation step",
  "long_term_fix": "Architectural improvement",
  "confidence": 0.85
}}

## RULES
1. Output VALID JSON ONLY, no markdown, no explanations
2. If scan results are empty or unclear, set confidence < 0.3
3. NEVER suggest attacking out-of-scope targets
4. Prioritize fixes over exploitation details
"""
    
    def analyze(self, scan_result: dict, context: dict) -> Optional[AIRecommendation]:
        """Send scan results to Qwen, parse structured response"""
        prompt = self._build_prompt(scan_result, context)
        
        try:
            response = ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                format="json",  # Force JSON output (Ollama 0.1.30+)
                options={"temperature": 0.1, "num_predict": 500}  # Low temp for consistency
            )
            
            # Parse and validate response
            content = response["message"]["content"].strip()
            # Remove markdown code blocks if present
            if content.startswith("```json"):
                content = content.removeprefix("```json").removesuffix("```").strip()
            
            data = json.loads(content)
            recommendation = AIRecommendation(**data)
            
            self._audit(
                "info",
                "ai_analysis_complete",
                technique=recommendation.mitre_technique,
                risk=recommendation.risk_level,
                confidence=recommendation.confidence,
            )
            return recommendation
            
        except Exception as e:
            self._audit("error", "ai_analysis_failed", error=str(e))
            logger.warning(f"AI analysis failed: {e}")
            return None  # Fail gracefully, don't block workflow