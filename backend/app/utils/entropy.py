"""Information-theoretic entropy and character-distribution helpers for DNS analysis."""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(text: str) -> float:
    """Compute base-2 Shannon entropy (bits per character) of a string."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return round(entropy, 4)


def character_distribution_metrics(text: str) -> dict[str, float]:
    """Return digit, hex-character, and non-alphanumeric ratios for a domain label."""
    if not text:
        return {"digit_ratio": 0.0, "hex_ratio": 0.0, "uppercase_ratio": 0.0}
    length = len(text)
    digits = sum(1 for ch in text if ch.isdigit())
    hex_chars = sum(1 for ch in text if ch.lower() in "0123456789abcdef")
    uppers = sum(1 for ch in text if ch.isupper())
    return {
        "digit_ratio": round(digits / length, 4),
        "hex_ratio": round(hex_chars / length, 4),
        "uppercase_ratio": round(uppers / length, 4),
    }
