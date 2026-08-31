"""Confidence expressed the way intelligence work expresses it.

A single number conflates two questions that have to stay apart: how much the
*source* can be relied on, and how much the *assessment* can be believed. The
Admiralty scale keeps them separate — a letter for the source, a digit for the
information — and analysts already read it. ``B2`` says: usually reliable
source, probably true.

The mapping below is deliberately conservative. ``A`` and ``1`` are never
assigned automatically: they mean corroborated, and nothing here corroborates
anything. That is a human's call.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

RELIABILITY_LABELS: dict[str, str] = {
    "A": "completely reliable",
    "B": "usually reliable",
    "C": "fairly reliable",
    "D": "not usually reliable",
    "E": "unreliable",
    "F": "reliability cannot be judged",
}

CREDIBILITY_LABELS: dict[str, str] = {
    "1": "confirmed by other sources",
    "2": "probably true",
    "3": "possibly true",
    "4": "doubtful",
    "5": "improbable",
    "6": "truth cannot be judged",
}

# Calibrated against the range the score can actually reach, not against a
# round number. Several criteria are close to mutually exclusive in practice —
# a name is usually either a lookalike spelling or a brand-plus-keyword
# construction, rarely both — so a textbook case such as lemonde-actu.info
# lands near 0.63 with three of five criteria at their maximum. Demanding 0.7
# would rate almost every genuine finding as merely "possibly true".
PROBABLY_TRUE = 0.6
DOUBTFUL_FLOOR = 0.25


@dataclass(frozen=True, slots=True)
class Confidence:
    """An Admiralty-style rating, with the reasoning for each half."""

    reliability: str
    credibility: str
    reliability_reason: str
    credibility_reason: str

    @property
    def code(self) -> str:
        return f"{self.reliability}{self.credibility}"

    @property
    def label(self) -> str:
        return f"{RELIABILITY_LABELS[self.reliability]}, {CREDIBILITY_LABELS[self.credibility]}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "label": self.label,
            "reliability": self.reliability,
            "reliability_reason": self.reliability_reason,
            "credibility": self.credibility,
            "credibility_reason": self.credibility_reason,
        }


def rate_source(*, has_evidence: bool, has_fingerprint: bool) -> tuple[str, str]:
    """How far the record itself can be relied on.

    Certificate Transparency logs are append-only and publicly auditable, so
    the underlying data is strong. What varies is how much of it reached us: a
    record identified by the certificate's own SHA-256 can be checked against
    the certificate, while an aggregator's listing has to be taken on trust.
    """

    if not has_evidence:
        return "F", "no archived response backs this observation"
    if has_fingerprint:
        return (
            "B",
            "archived response from a Certificate Transparency aggregator, "
            "identifying the certificate by its own SHA-256",
        )
    return (
        "C",
        "archived response from a Certificate Transparency aggregator, "
        "without a certificate fingerprint to check it against",
    )


def rate_information(*, score: float, allowlisted: bool, any_signal: bool) -> tuple[str, str]:
    """How far the impersonation assessment itself can be believed."""

    if allowlisted:
        return "5", "the domain belongs to the watched brand"
    if not any_signal:
        return "6", "no scoring criterion produced a signal"
    if score >= PROBABLY_TRUE:
        return "2", f"score of {score:.2f} across several independent criteria"
    if score >= DOUBTFUL_FLOOR:
        return "3", f"score of {score:.2f}, enough to warrant a look"
    return "4", f"score of {score:.2f}, below what usually warrants attention"


def rate(
    *, score: float, allowlisted: bool, any_signal: bool, has_evidence: bool, has_fingerprint: bool
) -> Confidence:
    reliability, reliability_reason = rate_source(
        has_evidence=has_evidence, has_fingerprint=has_fingerprint
    )
    credibility, credibility_reason = rate_information(
        score=score, allowlisted=allowlisted, any_signal=any_signal
    )
    return Confidence(
        reliability=reliability,
        credibility=credibility,
        reliability_reason=reliability_reason,
        credibility_reason=credibility_reason,
    )
