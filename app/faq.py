from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
import re


FAQ_PATH = Path(__file__).with_name("faq.md")
FAQ_HEADER = "## "
TOKEN_PATTERN = re.compile(r"[\u4e00-\u9fffA-Za-z0-9.%]+")


@dataclass(frozen=True)
class FAQEntry:
    id: str
    question: str
    variants: tuple[str, ...]
    answer: str
    keywords: tuple[str, ...]
    category: str
    language: str


@dataclass(frozen=True)
class FAQMatch:
    entry: FAQEntry
    score: float
    keyword_hits: tuple[str, ...]


def _normalize_text(text: str) -> str:
    return "".join(TOKEN_PATTERN.findall(text.casefold()))


def _tokenize(text: str) -> set[str]:
    normalized = text.casefold()
    return {token for token in TOKEN_PATTERN.findall(normalized) if token}


def _character_overlap_ratio(left: str, right: str) -> float:
    left_chars = set(left)
    right_chars = set(right)
    if not left_chars or not right_chars:
        return 0.0
    return len(left_chars & right_chars) / len(left_chars | right_chars)


def _parse_keywords(raw: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def _parse_variants(raw: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in raw.split("|") if part.strip())


def _parse_entry(block: str) -> FAQEntry:
    lines = [line.strip() for line in block.splitlines() if line.strip()]
    faq_id = lines[0].removeprefix(FAQ_HEADER).strip()
    fields: dict[str, str] = {}
    for line in lines[1:]:
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return FAQEntry(
        id=faq_id,
        question=fields["Question"],
        variants=_parse_variants(fields.get("Variants", "")),
        answer=fields["Answer"],
        keywords=_parse_keywords(fields.get("Keywords", "")),
        category=fields.get("Category", ""),
        language=fields.get("Language", ""),
    )


@lru_cache(maxsize=1)
def load_faq_entries() -> tuple[FAQEntry, ...]:
    text = FAQ_PATH.read_text(encoding="utf-8")
    blocks = [f"{FAQ_HEADER}{block.strip()}" for block in text.split(FAQ_HEADER) if block.strip().startswith("FAQ-")]
    return tuple(_parse_entry(block) for block in blocks)


def match_faq(question: str) -> FAQMatch | None:
    incoming_normalized = _normalize_text(question)
    incoming_tokens = _tokenize(question)
    if not incoming_normalized:
        return None

    best_match: FAQMatch | None = None
    for entry in load_faq_entries():
        normalized_candidates = [_normalize_text(entry.question), *(_normalize_text(variant) for variant in entry.variants)]
        keyword_hits = tuple(keyword for keyword in entry.keywords if _normalize_text(keyword) in incoming_normalized)
        question_match = any(candidate in incoming_normalized or incoming_normalized in candidate for candidate in normalized_candidates)
        candidate_tokens = set(entry.keywords)
        candidate_tokens.update(entry.variants)
        candidate_tokens.add(entry.question)
        token_overlap = len(incoming_tokens & {token for text in candidate_tokens for token in _tokenize(text)})
        character_overlap = max(_character_overlap_ratio(incoming_normalized, candidate) for candidate in normalized_candidates if candidate)

        score = 0.0
        if question_match:
            score += 0.75
        if keyword_hits:
            score += min(0.35, 0.18 * len(keyword_hits))
        if token_overlap:
            score += min(0.2, 0.05 * token_overlap)
        if character_overlap >= 0.45:
            score += min(0.3, character_overlap * 0.4)

        candidate = FAQMatch(entry=entry, score=score, keyword_hits=keyword_hits)
        if best_match is None or candidate.score > best_match.score:
            best_match = candidate

    if best_match is None or best_match.score < 0.75:
        return None
    return best_match
