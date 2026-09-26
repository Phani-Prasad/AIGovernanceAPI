"""
Prompt Injection Detector — AI Governance & Security Layer API
Pattern-based and heuristic detection of prompt injection attacks.
"""
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from core.config import settings
from models.schemas.schemas import InjectionScanResult

# ── Injection Pattern Library ──────────────────────────────────
INJECTION_PATTERNS: Dict[str, List[re.Pattern]] = {

    "instruction_override": [
        re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)", re.I),
        re.compile(r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|context)", re.I),
        re.compile(r"forget\s+(everything|all|your\s+instructions?)", re.I),
        re.compile(r"override\s+(your\s+)?(instructions?|programming|rules?|restrictions?)", re.I),
        re.compile(r"new\s+instructions?[:]\s*", re.I),
        re.compile(r"your\s+(new\s+)?(task|role|purpose|objective|job)\s+is\s+", re.I),
    ],

    "role_manipulation": [
        re.compile(r"you\s+are\s+now\s+(an?\s+)?(?!a\s+helpful|an?\s+AI)", re.I),
        re.compile(r"pretend\s+(you\s+are|to\s+be)\s+", re.I),
        re.compile(r"act\s+as\s+(if\s+you\s+are\s+)?(an?\s+)?(?!helpful|assistant)", re.I),
        re.compile(r"roleplay\s+as\s+", re.I),
        re.compile(r"simulate\s+(being\s+)?(an?\s+)?", re.I),
        re.compile(r"from\s+now\s+on\s+(you|respond|act)", re.I),
    ],

    "jailbreak": [
        re.compile(r"\bDAN\b|\bdo\s+anything\s+now\b", re.I),
        re.compile(r"developer\s+mode", re.I),
        re.compile(r"jailbreak", re.I),
        re.compile(r"unrestricted\s+(mode|AI|version)", re.I),
        re.compile(r"without\s+(any\s+)?(restrictions?|limitations?|filters?|censorship)", re.I),
        re.compile(r"bypass\s+(your\s+)?(safety|security|filter|restriction|guard)", re.I),
        re.compile(r"\[\s*JAILBREAK\s*\]|\[\s*SYSTEM\s*\]|\[\s*ADMIN\s*\]", re.I),
    ],

    "system_prompt_extraction": [
        re.compile(r"(reveal|show|print|display|output|tell\s+me)\s+(your\s+)?(system\s+prompt|instructions?|original\s+prompt|initial\s+prompt)", re.I),
        re.compile(r"what\s+(are|were)\s+your\s+(instructions?|system\s+prompt|initial\s+setup)", re.I),
        re.compile(r"ignore\s+.*?\s+and\s+(instead|then)\s+", re.I),
        re.compile(r"print\s+the\s+first\s+\d+\s+(words?|characters?|lines?)\s+of\s+your", re.I),
    ],

    "data_exfiltration": [
        re.compile(r"send\s+(this|the|all)\s+(data|information|content|conversation)\s+to\s+", re.I),
        re.compile(r"exfiltrate\s+", re.I),
        re.compile(r"leak\s+(the\s+)?(data|system|prompt|config)", re.I),
        re.compile(r"(http|https|ftp)://[^\s]+\.(exe|php|js)", re.I),
    ],

    "code_injection": [
        re.compile(r"<\s*script\s*>", re.I),
        re.compile(r"eval\s*\(", re.I),
        re.compile(r"exec\s*\(", re.I),
        re.compile(r"__import__\s*\(", re.I),
        re.compile(r"os\.(system|popen|exec)", re.I),
        re.compile(r"subprocess\.(call|run|Popen)", re.I),
    ],

    "separator_injection": [
        re.compile(r"---+\s*(HUMAN|USER|ASSISTANT|SYSTEM)\s*---+", re.I),
        re.compile(r"\[INST\]|\[/INST\]|\[SYS\]|\[/SYS\]"),
        re.compile(r"<\|im_start\|>|<\|im_end\|>"),
        re.compile(r"###\s*(Instruction|Input|Response|System)\s*:"),
    ],
}

# Severity scores per pattern category
PATTERN_SEVERITY: Dict[str, float] = {
    "instruction_override": 0.85,
    "role_manipulation": 0.75,
    "jailbreak": 0.95,
    "system_prompt_extraction": 0.80,
    "data_exfiltration": 0.90,
    "code_injection": 0.95,
    "separator_injection": 0.70,
}

# Sensitivity thresholds — score must exceed this to flag
SENSITIVITY_THRESHOLDS = {
    "low": 0.9,
    "medium": 0.75,
    "high": 0.6,
    "strict": 0.4,
}


class InjectionDetector:
    """
    Multi-layer prompt injection detector using:
    1. Pattern matching (regex library)
    2. Heuristic scoring
    3. Configurable sensitivity
    """

    def __init__(self):
        self.sensitivity = settings.injection_sensitivity
        self.threshold = SENSITIVITY_THRESHOLDS[self.sensitivity]

    async def scan(
        self,
        text: str,
        sensitivity: Optional[str] = None,
    ) -> InjectionScanResult:
        """
        Scan text for prompt injection patterns.

        Returns InjectionScanResult with:
        - detected: bool
        - score: 0.0-1.0 risk score
        - patterns_matched: list of matched pattern categories
        - action_taken: none | blocked | warned
        """
        if not text or not text.strip():
            return InjectionScanResult(detected=False, score=0.0, action_taken="none")

        effective_sensitivity = sensitivity or self.sensitivity
        threshold = SENSITIVITY_THRESHOLDS.get(effective_sensitivity, 0.75)

        score, matched_patterns = self._pattern_scan(text)

        # Add heuristic score adjustments
        score = self._apply_heuristics(text, score)

        # Clamp to [0, 1]
        score = min(1.0, max(0.0, score))

        detected = score >= threshold

        if detected:
            # Block in high/strict mode, warn in medium/low
            if effective_sensitivity in ("high", "strict"):
                action = "blocked"
            else:
                action = "warned"
        else:
            action = "none"

        return InjectionScanResult(
            detected=detected,
            score=round(score, 3),
            patterns_matched=matched_patterns,
            action_taken=action,
        )

    def _pattern_scan(self, text: str) -> Tuple[float, List[str]]:
        """Scan against all regex patterns and compute composite score."""
        matched_categories = []
        max_score = 0.0
        total_score = 0.0
        hit_count = 0

        for category, patterns in INJECTION_PATTERNS.items():
            category_score = PATTERN_SEVERITY[category]
            for pattern in patterns:
                if pattern.search(text):
                    if category not in matched_categories:
                        matched_categories.append(category)
                        total_score += category_score
                        max_score = max(max_score, category_score)
                        hit_count += 1
                    break  # One match per category is enough

        if hit_count == 0:
            return 0.0, []

        # Combine max score with weighted average
        avg_score = total_score / hit_count
        composite = (max_score * 0.6) + (avg_score * 0.3) + (min(hit_count / 5, 1.0) * 0.1)
        return composite, matched_categories

    def _apply_heuristics(self, text: str, base_score: float) -> float:
        """Apply heuristic boosts/deductions based on text characteristics."""
        score = base_score

        # Boost: excessive use of all-caps (urgency signaling)
        words = text.split()
        if words:
            caps_ratio = sum(1 for w in words if w.isupper() and len(w) > 2) / len(words)
            if caps_ratio > 0.3:
                score += 0.1

        # Boost: many special characters (encoding tricks)
        special_char_ratio = sum(1 for c in text if not c.isalnum() and not c.isspace()) / max(len(text), 1)
        if special_char_ratio > 0.2:
            score += 0.05

        # Boost: very long single messages (more attack surface)
        if len(text) > 2000:
            score += 0.05

        # Boost: multiple injection indicators in sequence
        if len(text.split("instruction")) > 3:
            score += 0.05

        return score

    def scan_messages(self, messages: list) -> str:
        """Extract and concatenate all user messages for scanning."""
        user_content = []
        for msg in messages:
            role = msg.get("role", "") if isinstance(msg, dict) else getattr(msg, "role", "")
            content = msg.get("content", "") if isinstance(msg, dict) else getattr(msg, "content", "")
            if role in ("user", "human") and isinstance(content, str):
                user_content.append(content)
        return "\n".join(user_content)


# ── Singleton ──────────────────────────────────────────────────
injection_detector = InjectionDetector()
