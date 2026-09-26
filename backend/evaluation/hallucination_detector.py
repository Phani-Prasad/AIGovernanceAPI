"""
Hallucination Detector — AI Governance & Security Layer API

Evaluates an LLM response for hallucination risk using the configured method.

Supported methods:
- llm_judge: Sends a structured meta-prompt to a judge model (default: gpt-4o-mini)
             via the existing llm_router. No new HTTP clients needed.
- grounding:  (future) Compare response against source docs passed in context.
- self_consistency: (future) Sample N responses and flag divergence.
"""
import json
import re
import structlog

from evaluation.eval_config import HallucinationConfig

logger = structlog.get_logger()

# ── Judge prompt template ──────────────────────────────────────
_JUDGE_PROMPT = """You are a factual accuracy evaluator for AI responses.

Your task: Rate the following AI response for hallucination risk.

Scoring scale:
- 0.0 = Fully grounded, factually safe, no concerns
- 0.5 = Uncertain or unverifiable, but not clearly wrong
- 1.0 = Likely hallucinated, contains false or fabricated claims

Respond ONLY with valid JSON. No explanation outside the JSON block.

Format:
{{"score": <float 0.0-1.0>, "reasoning": "<one sentence max>"}}

---
User prompt:
{prompt}

AI response:
{response}
---

JSON evaluation:"""


class HallucinationResult:
    """Result of a hallucination evaluation run."""

    def __init__(
        self,
        score: float = 0.0,
        flagged: bool = False,
        reasoning: str | None = None,
        method: str = "llm_judge",
        error: str | None = None,
    ):
        self.score = score
        self.flagged = flagged
        self.reasoning = reasoning
        self.method = method
        self.error = error

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "flagged": self.flagged,
            "reasoning": self.reasoning,
            "method": self.method,
            "error": self.error,
        }


class HallucinationDetector:
    """
    Evaluates LLM responses for hallucination risk.
    Uses llm_router so no additional API clients are needed.
    """

    async def evaluate(
        self,
        prompt: str,
        response: str,
        config: HallucinationConfig,
    ) -> HallucinationResult:
        """
        Run hallucination detection based on the configured method.

        Args:
            prompt:   The original user prompt sent to the LLM.
            response: The LLM's response text to evaluate.
            config:   HallucinationConfig for this org.

        Returns:
            HallucinationResult with score, flagged flag, and reasoning.
        """
        if not response or not response.strip():
            return HallucinationResult(score=0.0, flagged=False, reasoning="Empty response", method=config.method)

        if config.method == "llm_judge":
            return await self._llm_judge(prompt, response, config)
        elif config.method == "grounding":
            # Future: compare against grounding docs
            return HallucinationResult(
                score=0.0, flagged=False,
                reasoning="Grounding method not yet implemented — defaulting to safe",
                method="grounding",
            )
        elif config.method == "self_consistency":
            # Future: multi-sample consistency check
            return HallucinationResult(
                score=0.0, flagged=False,
                reasoning="Self-consistency method not yet implemented — defaulting to safe",
                method="self_consistency",
            )
        else:
            return HallucinationResult(score=0.0, flagged=False, reasoning="Unknown method", method=config.method)

    async def _llm_judge(
        self,
        prompt: str,
        response: str,
        config: HallucinationConfig,
    ) -> HallucinationResult:
        """
        Use a secondary LLM call (judge model) to evaluate hallucination risk.
        Routes through the existing llm_router — no new HTTP clients.
        """
        from core.llm_router import llm_router, LLMProviderError

        judge_prompt = _JUDGE_PROMPT.format(
            prompt=prompt[:2000],    # Truncate to avoid token bloat
            response=response[:2000],
        )

        try:
            result = await llm_router.complete(
                model=config.judge_model,
                messages=[{"role": "user", "content": judge_prompt}],
                temperature=0.0,     # Deterministic evaluation
                max_tokens=150,
            )

            raw_content = result["choices"][0]["message"]["content"].strip()
            score, reasoning = self._parse_judge_response(raw_content)

            flagged = score >= config.threshold

            logger.info(
                "Hallucination evaluation complete",
                score=score,
                flagged=flagged,
                method="llm_judge",
                judge_model=config.judge_model,
            )

            return HallucinationResult(
                score=score,
                flagged=flagged,
                reasoning=reasoning,
                method="llm_judge",
            )

        except LLMProviderError as e:
            logger.warning("Hallucination judge LLM call failed", error=str(e))
            return HallucinationResult(
                score=0.0, flagged=False,
                reasoning=None, method="llm_judge",
                error=f"Judge LLM error: {e}",
            )
        except Exception as e:
            logger.error("Unexpected hallucination detection error", error=str(e))
            return HallucinationResult(
                score=0.0, flagged=False,
                reasoning=None, method="llm_judge",
                error=f"Unexpected error: {e}",
            )

    def _parse_judge_response(self, raw: str) -> tuple[float, str]:
        """
        Parse the judge model's JSON response.
        Falls back gracefully if the model returns malformed JSON.
        """
        # Try to find a JSON block (sometimes models wrap it in ```json)
        json_match = re.search(r'\{[^{}]+\}', raw, re.DOTALL)
        if json_match:
            raw = json_match.group(0)

        try:
            data = json.loads(raw)
            score = float(data.get("score", 0.0))
            score = max(0.0, min(1.0, score))   # Clamp to [0, 1]
            reasoning = str(data.get("reasoning", "")).strip()[:300]
            return score, reasoning
        except (json.JSONDecodeError, ValueError, TypeError):
            logger.warning("Could not parse judge response", raw=raw[:200])
            return 0.0, "Parse error — treating as safe"


# ── Singleton ──────────────────────────────────────────────────
hallucination_detector = HallucinationDetector()
