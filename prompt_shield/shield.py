"""
AI Prompt Shield - Prompt injection detection library.

Detects and prevents prompt injection attacks in LLM applications
using pattern matching, heuristic scoring, and statistical analysis.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Callable


__version__ = "0.1.0"


@dataclass
class AnalysisResult:
    """Result of prompt injection analysis."""
    is_safe: bool
    threat_score: float
    threats: List[str] = field(default_factory=list)
    matched_patterns: List[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)


INJECTION_PATTERNS = {
    "instruction_override": [
        r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules|directives)",
        r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|context)",
        r"forget\s+(everything|all|what)\s+(above|before|previously)",
        r"override\s+(system|previous|all)\s+(instructions|prompt|rules)",
        r"do\s+not\s+follow\s+(the\s+)?(previous|above|system)",
        r"new\s+instructions?\s*:",
    ],
    "role_manipulation": [
        r"you\s+are\s+now\s+(a|an)\s+",
        r"act\s+as\s+(a|an|if)\s+",
        r"pretend\s+(to\s+be|you\s+are)\s+",
        r"switch\s+to\s+.*mode",
        r"enter\s+(developer|god|admin|sudo|jailbreak|dan)\s*mode",
        r"you\s+are\s+dan",
    ],
    "system_prompt_extraction": [
        r"(show|print|display|reveal|output|repeat|tell)\s+(me\s+)?(your|the)\s+(system\s+)?(prompt|instructions|rules)",
        r"what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions|rules)",
        r"(beginning|start)\s+of\s+(the\s+)?(system|conversation)",
        r"\[system\]",
        r"<\/?system>",
        r"<<SYS>>",
    ],
    "encoding_attack": [
        r"base64[\s:]+(decode|eval|execute)",
        r"hex[\s:]+(decode|eval|execute)",
        r"(?:[A-Za-z0-9+/]{40,}={0,2})",
        r"(?:\\x[0-9a-fA-F]{2}){10,}",
    ],
    "context_manipulation": [
        r"(previous|earlier)\s+(conversation|context|messages?)\s+(said|mentioned|stated)",
        r"the\s+user\s+(previously|already)\s+(said|confirmed|agreed)",
        r"(system|admin|developer)\s+(message|note|override)\s*:",
        r"\[INST\]",
        r"<\|im_start\|>",
    ],
}


class PromptShield:
    """Main prompt injection detection engine."""

    def __init__(self, sensitivity=0.5, custom_patterns=None, block_encoded=True,
                 max_input_length=10000, categories=None):
        self.sensitivity = max(0.0, min(1.0, sensitivity))
        self.block_encoded = block_encoded
        self.max_input_length = max_input_length
        self.categories = categories or list(INJECTION_PATTERNS.keys())
        self._patterns = self._compile_patterns(custom_patterns)

    def _compile_patterns(self, custom=None):
        compiled = {}
        for cat in self.categories:
            if cat in INJECTION_PATTERNS:
                compiled[cat] = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS[cat]]
        if custom:
            compiled.setdefault("custom", [])
            compiled["custom"].extend(re.compile(p, re.IGNORECASE) for p in custom)
        return compiled

    def analyze(self, text):
        """Analyze input text for prompt injection attempts."""
        threats = []
        matched = []
        scores = {}

        if len(text) > self.max_input_length:
            threats.append("excessive_length")
            scores["length"] = 0.8

        for category, patterns in self._patterns.items():
            cat_matches = []
            for pattern in patterns:
                found = pattern.findall(text)
                if found:
                    cat_matches.extend(
                        found if isinstance(found[0], str) else [str(f) for f in found]
                    )
            if cat_matches:
                threats.append(category)
                matched.extend(cat_matches[:3])
                scores[category] = min(1.0, len(cat_matches) * 0.3)

        heuristic = self._heuristic_score(text)
        scores["heuristic"] = heuristic

        threat_score = min(1.0, sum(scores.values()) / max(len(scores), 1)) if scores else 0.0

        return AnalysisResult(
            is_safe=threat_score < self.sensitivity,
            threat_score=round(threat_score, 3),
            threats=threats,
            matched_patterns=matched[:10],
            details=scores,
        )

    def _heuristic_score(self, text):
        """Calculate heuristic risk score based on text characteristics."""
        score = 0.0
        lower = text.lower()

        special_ratio = sum(1 for c in text if not c.isalnum() and c != " ") / max(len(text), 1)
        if special_ratio > 0.3:
            score += 0.2

        if len(text) > 20:
            caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
            if caps_ratio > 0.5:
                score += 0.15

        role_words = ["assistant", "helpful", "harmless", "ethical", "boundaries"]
        if sum(1 for w in role_words if w in lower) >= 2:
            score += 0.2

        if text.count("\n") > 10:
            score += 0.1

        return min(1.0, score)

    def guard(self, func):
        """Decorator to guard a function against prompt injection."""
        def wrapper(prompt, *args, **kwargs):
            result = self.analyze(prompt)
            if not result.is_safe:
                raise PromptInjectionError(
                    f"Prompt injection detected (score: {result.threat_score})",
                    result=result,
                )
            return func(prompt, *args, **kwargs)
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper

    def is_safe(self, text):
        """Quick check - returns True if input appears safe."""
        return self.analyze(text).is_safe


class PromptInjectionError(Exception):
    """Raised when prompt injection is detected."""
    def __init__(self, message, result=None):
        super().__init__(message)
        self.result = result
