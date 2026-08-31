"""The composite suspicion score.

The number is never the point. What matters is the breakdown: which criteria
fired, how much each one contributed, and why — in a sentence someone can put
in a report and defend. A score with no breakdown is an opinion with a decimal
point attached.

Weights come from the configuration and are normalised at load time, so a
partial or reweighted configuration still yields a score on a nought-to-one
scale, and the criteria that were disabled are simply absent rather than
silently counted as zero.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ctwatch.config import ScoringConfig
from ctwatch.matching.rules import (
    certificate_age_signal,
    keyword_signal,
    lookalike_signal,
    name_similarity_signal,
    tld_risk_signal,
)
from ctwatch.names import DomainName, to_unicode_label
from ctwatch.publicsuffix import split
from ctwatch.store.models import WatchTarget


@dataclass(frozen=True, slots=True)
class Subject:
    """A domain being assessed, together with what is known about it."""

    name: DomainName
    not_before: datetime | None = None
    issuer: str | None = None
    source: str | None = None
    evidence_id: int | None = None


@dataclass(frozen=True, slots=True)
class Contribution:
    """One criterion's share of the score, and the reason for it."""

    criterion: str
    value: float
    weight: float
    weighted: float
    explanation: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "criterion": self.criterion,
            "value": round(self.value, 4),
            "weight": round(self.weight, 4),
            "weighted": round(self.weighted, 4),
            "explanation": self.explanation,
        }


@dataclass(frozen=True, slots=True)
class Score:
    value: float
    contributions: tuple[Contribution, ...] = ()
    summary: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def strongest(self) -> Contribution | None:
        ranked = [c for c in self.contributions if c.weighted > 0]
        return max(ranked, key=lambda c: c.weighted) if ranked else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "value": round(self.value, 4),
            "summary": self.summary,
            "contributions": [contribution.as_dict() for contribution in self.contributions],
            "metadata": dict(self.metadata),
        }


class Scorer:
    """Turns what is known about a domain into an explained score."""

    def __init__(self, config: ScoringConfig) -> None:
        self._config = config
        self._weights = config.normalized_weights()

    @property
    def config(self) -> ScoringConfig:
        return self._config

    def _signal(
        self,
        criterion: str,
        *,
        subject: Subject,
        target: WatchTarget,
        now: datetime | None,
    ) -> tuple[float, str]:
        candidate = split(subject.name.ascii_name).registrable_label
        reference = split(target.canonical_domain).registrable_label

        if criterion == "levenshtein":
            return name_similarity_signal(candidate, reference)
        if criterion == "homoglyph":
            # Compared on the readable form: the punycode spelling shares no
            # characters with the original, so it would look like a different
            # name entirely.
            return lookalike_signal(to_unicode_label(candidate), reference)
        if criterion == "keyword_combo":
            return keyword_signal(candidate, reference, target.keywords)
        if criterion == "tld_risk":
            return tld_risk_signal(subject.name, self._config)
        if criterion == "cert_age":
            return certificate_age_signal(subject.not_before, now=now)

        msg = f"no rule implements the scoring criterion {criterion!r}"
        raise ValueError(msg)

    def score(self, subject: Subject, *, target: WatchTarget, now: datetime | None = None) -> Score:
        """Assess one domain against one watched brand."""

        contributions: list[Contribution] = []
        for criterion, weight in self._weights.items():
            value, explanation = self._signal(criterion, subject=subject, target=target, now=now)
            bounded = min(1.0, max(0.0, value))
            contributions.append(
                Contribution(
                    criterion=criterion,
                    value=bounded,
                    weight=weight,
                    weighted=bounded * weight,
                    explanation=explanation,
                )
            )

        total = sum(contribution.weighted for contribution in contributions)
        result = Score(
            value=total,
            contributions=tuple(contributions),
            summary="",
            metadata={"target": target.canonical_domain, "brand": target.brand},
        )
        return Score(
            value=result.value,
            contributions=result.contributions,
            summary=_summarise(subject, target, result),
            metadata=result.metadata,
        )


def _summarise(subject: Subject, target: WatchTarget, score: Score) -> str:
    displayed = subject.name.unicode_name
    shown = (
        f"{subject.name.ascii_name} ({displayed})"
        if subject.name.is_idn
        else subject.name.ascii_name
    )
    strongest = score.strongest
    reason = strongest.explanation if strongest else "no criterion fired"
    return f"{shown} scores {score.value:.2f} against {target.canonical_domain}: {reason}"
