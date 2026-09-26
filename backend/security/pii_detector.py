"""
PII Detector — AI Governance & Security Layer API
Microsoft Presidio-based PII detection and anonymization.
"""
import re
from typing import List, Optional

from core.config import settings
from models.schemas.schemas import PIIEntity, PIIScanResult

# ── Lazy-loaded Presidio instances ─────────────────────────────
_analyzer = None
_anonymizer = None


def _get_analyzer():
    global _analyzer
    if _analyzer is None:
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider

            # Use a lightweight English NLP engine
            provider = NlpEngineProvider(nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
            })
            nlp_engine = provider.create_engine()
            _analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
        except Exception:
            # Fallback: regex-only mode if spaCy model not installed
            from presidio_analyzer import AnalyzerEngine
            _analyzer = AnalyzerEngine()
    return _analyzer


def _get_anonymizer():
    global _anonymizer
    if _anonymizer is None:
        from presidio_anonymizer import AnonymizerEngine
        _anonymizer = AnonymizerEngine()
    return _anonymizer


# ── PII Entity Types ───────────────────────────────────────────
DEFAULT_PII_ENTITIES = [
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "US_SSN",
    "US_BANK_NUMBER",
    "IP_ADDRESS",
    "URL",
    "US_PASSPORT",
    "US_DRIVER_LICENSE",
    "IBAN_CODE",
    "LOCATION",
    "DATE_TIME",
    "NRP",  # Nationality, Religion, Political
    "MEDICAL_LICENSE",
]

# Regex fallback patterns for when Presidio isn't fully available
REGEX_PATTERNS = {
    "EMAIL_ADDRESS": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b"),
    "PHONE_NUMBER": re.compile(r"\b(\+?1?[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
    "US_SSN": re.compile(r"\b\d{3}[-\s]\d{2}[-\s]\d{4}\b"),
    "IP_ADDRESS": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}


def _regex_fallback_scan(text: str) -> List[PIIEntity]:
    """Simple regex-based PII detection as fallback."""
    entities = []
    for entity_type, pattern in REGEX_PATTERNS.items():
        for match in pattern.finditer(text):
            entities.append(PIIEntity(
                type=entity_type,
                start=match.start(),
                end=match.end(),
                score=0.85,
            ))
    return entities


def _mask_text_regex(text: str, entities: List[PIIEntity]) -> str:
    """Replace detected PII with type-labeled placeholders."""
    # Sort by position descending to replace from end (avoids offset issues)
    sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)
    result = text
    for entity in sorted_entities:
        placeholder = f"[{entity.type}]"
        result = result[:entity.start] + placeholder + result[entity.end:]
    return result


class PIIDetector:
    """
    Presidio-powered PII detector with regex fallback.
    Supports detect, mask, and block modes.
    """

    def __init__(self):
        self.action = settings.pii_action
        self._presidio_available = self._check_presidio()

    def _check_presidio(self) -> bool:
        try:
            import presidio_analyzer  # noqa
            return True
        except ImportError:
            return False

    async def scan(
        self,
        text: str,
        action: Optional[str] = None,
        language: str = "en",
        entity_types: Optional[List[str]] = None,
    ) -> PIIScanResult:
        """
        Scan text for PII entities.

        Args:
            text: Input text to scan
            action: Override default action (detect|mask|block)
            language: Language code
            entity_types: Specific entity types to detect

        Returns:
            PIIScanResult with detected entities and sanitized text
        """
        effective_action = action or self.action
        entities_to_detect = entity_types or DEFAULT_PII_ENTITIES

        if not text or not text.strip():
            return PIIScanResult(
                detected=False,
                entities=[],
                action_taken="none",
            )

        # Try Presidio first, fall back to regex
        detected_entities: List[PIIEntity] = []

        if self._presidio_available:
            detected_entities = await self._presidio_scan(text, language, entities_to_detect)
        else:
            detected_entities = _regex_fallback_scan(text)

        if not detected_entities:
            return PIIScanResult(detected=False, entities=[], action_taken="none")

        # Apply action
        if effective_action == "block":
            return PIIScanResult(
                detected=True,
                entities=detected_entities,
                sanitized_text=None,
                action_taken="blocked",
            )
        elif effective_action == "mask":
            sanitized = await self._anonymize(text, detected_entities) if self._presidio_available else _mask_text_regex(text, detected_entities)
            return PIIScanResult(
                detected=True,
                entities=detected_entities,
                sanitized_text=sanitized,
                action_taken="masked",
            )
        else:  # detect only
            return PIIScanResult(
                detected=True,
                entities=detected_entities,
                action_taken="none",
            )

    async def _presidio_scan(
        self, text: str, language: str, entity_types: List[str]
    ) -> List[PIIEntity]:
        """Run Presidio analyzer."""
        try:
            analyzer = _get_analyzer()
            results = analyzer.analyze(
                text=text,
                language=language,
                entities=entity_types,
                score_threshold=0.5,
            )
            return [
                PIIEntity(
                    type=r.entity_type,
                    start=r.start,
                    end=r.end,
                    score=round(r.score, 3),
                )
                for r in results
            ]
        except Exception:
            return _regex_fallback_scan(text)

    async def _anonymize(self, text: str, entities: List[PIIEntity]) -> str:
        """Use Presidio anonymizer to replace PII with placeholders."""
        try:
            from presidio_anonymizer import AnonymizerEngine
            from presidio_anonymizer.entities import RecognizerResult, OperatorConfig

            anonymizer = _get_anonymizer()
            recognizer_results = [
                RecognizerResult(
                    entity_type=e.type,
                    start=e.start,
                    end=e.end,
                    score=e.score,
                )
                for e in entities
            ]
            result = anonymizer.anonymize(
                text=text,
                analyzer_results=recognizer_results,
                operators={"DEFAULT": OperatorConfig("replace", {"new_value": lambda x: f"[{x.entity_type}]"})},
            )
            return result.text
        except Exception:
            return _mask_text_regex(text, entities)

    def extract_text_from_messages(self, messages: list) -> str:
        """Extract all text content from a messages list."""
        parts = []
        for msg in messages:
            content = msg.get("content", "") if isinstance(msg, dict) else getattr(msg, "content", "")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        parts.append(item.get("text", ""))
        return "\n".join(parts)

    def apply_masks_to_messages(self, messages: list, original_text: str, masked_text: str) -> list:
        """Apply PII masking back to the original messages structure."""
        # Simple approach: rebuild messages with masked content
        import copy
        masked_messages = copy.deepcopy(messages)
        for msg in masked_messages:
            if isinstance(msg, dict) and isinstance(msg.get("content"), str):
                msg["content"] = msg["content"].replace(original_text, masked_text) if len(messages) == 1 else msg["content"]
        return masked_messages


# ── Singleton ──────────────────────────────────────────────────
pii_detector = PIIDetector()
