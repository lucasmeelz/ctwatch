"""Configuration models and loader.

The configuration file is the single place where an operator declares what is
watched and which external services may be contacted. Nothing here reaches out
to a watched domain: the hosts listed under ``sources`` are the only ones the
network layer will ever accept (see :mod:`ctwatch.net.client`).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

DEFAULT_CONFIG_FILENAME = "ctwatch.yaml"


def _normalize_domain(value: str) -> str:
    return value.strip().lower().rstrip(".")


class StrictModel(BaseModel):
    """Base model that refuses unknown keys, so typos in YAML are loud."""

    model_config = ConfigDict(extra="forbid")


class TargetConfig(StrictModel):
    """A brand to watch, with the domains that legitimately belong to it."""

    brand: str
    canonical_domains: list[str] = Field(min_length=1)
    allowlist: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)

    @field_validator("canonical_domains", "allowlist", mode="after")
    @classmethod
    def _normalize_domains(cls, value: list[str]) -> list[str]:
        return [_normalize_domain(item) for item in value if item.strip()]

    @field_validator("keywords", mode="after")
    @classmethod
    def _normalize_keywords(cls, value: list[str]) -> list[str]:
        return [item.strip().lower() for item in value if item.strip()]


class TldRiskConfig(StrictModel):
    high: list[str] = Field(default_factory=list)
    medium: list[str] = Field(default_factory=list)

    @field_validator("high", "medium", mode="after")
    @classmethod
    def _normalize(cls, value: list[str]) -> list[str]:
        return [item.strip().lower().lstrip(".") for item in value if item.strip()]


class ScoringConfig(StrictModel):
    """Weights and thresholds for the composite suspicion score.

    Weights are normalized at load time so that a partial configuration still
    produces a score expressed on a 0-1 scale.
    """

    tld_risk: TldRiskConfig = Field(default_factory=TldRiskConfig)
    weights: dict[str, float] = Field(
        default_factory=lambda: {
            "levenshtein": 0.3,
            "homoglyph": 0.25,
            "keyword_combo": 0.2,
            "tld_risk": 0.15,
            "cert_age": 0.1,
        }
    )
    review_threshold: float = 0.5

    @field_validator("weights", mode="after")
    @classmethod
    def _positive_weights(cls, value: dict[str, float]) -> dict[str, float]:
        for name, weight in value.items():
            if weight < 0:
                msg = f"scoring weight {name!r} must not be negative"
                raise ValueError(msg)
        if sum(value.values()) <= 0:
            msg = "at least one scoring weight must be greater than zero"
            raise ValueError(msg)
        return value

    def normalized_weights(self) -> dict[str, float]:
        total = sum(self.weights.values())
        return {name: weight / total for name, weight in self.weights.items()}


class CrtShConfig(StrictModel):
    enabled: bool = True
    base_url: str = "https://crt.sh"
    rate_limit_rps: float = 0.5
    timeout_seconds: float = 45.0
    max_attempts: int = 4
    retry_backoff_seconds: float = 1.0
    cache_ttl_seconds: int = 3600


class CertSpotterConfig(StrictModel):
    """Cert Spotter works without a key, at a rate metered per address.

    It is enabled by default because it is markedly more dependable than
    crt.sh and because it returns certificate fingerprints, which crt.sh's
    JSON listing does not. Configure a key for any sustained use.
    """

    enabled: bool = True
    base_url: str = "https://api.certspotter.com"
    api_key_env: str = "CERTSPOTTER_API_KEY"
    rate_limit_rps: float = 1.0
    timeout_seconds: float = 30.0
    max_attempts: int = 4
    retry_backoff_seconds: float = 1.0
    cache_ttl_seconds: int = 3600
    max_pages: int = 10

    def api_key(self) -> str | None:
        return os.environ.get(self.api_key_env) or None


class CertStreamConfig(StrictModel):
    enabled: bool = False
    url: str = "wss://certstream.calidog.io/"
    reconnect_delay_seconds: float = 5.0
    fallback_to_polling: bool = True


class SourcesConfig(StrictModel):
    """Which Certificate Transparency services to use, and in what order.

    ``failover`` asks each source in turn and stops at the first that answers,
    which halves the request budget and keeps a scan working when one service
    is down — the normal state of affairs for crt.sh. ``all`` asks every
    enabled source for every query, which costs more and occasionally surfaces
    a certificate one aggregator has and another does not.
    """

    crtsh: CrtShConfig = Field(default_factory=CrtShConfig)
    certspotter: CertSpotterConfig = Field(default_factory=CertSpotterConfig)
    certstream: CertStreamConfig = Field(default_factory=CertStreamConfig)
    strategy: Literal["failover", "all"] = "failover"
    order: list[str] = Field(default_factory=lambda: ["certspotter", "crtsh"])

    @field_validator("order", mode="after")
    @classmethod
    def _known_sources(cls, value: list[str]) -> list[str]:
        known = {"certspotter", "crtsh"}
        cleaned = [item.strip().lower() for item in value if item.strip()]
        unknown = [item for item in cleaned if item not in known]
        if unknown:
            msg = f"unknown source(s) in `order`: {', '.join(unknown)}"
            raise ValueError(msg)
        return cleaned


class PermutationsConfig(StrictModel):
    """How candidate names are generated for each watched domain."""

    keyboard_layouts: list[str] = Field(default_factory=lambda: ["azerty", "qwerty"])
    extra_tlds: list[str] = Field(default_factory=list)
    include_homoglyphs: bool = True

    @field_validator("extra_tlds", mode="after")
    @classmethod
    def _normalize(cls, value: list[str]) -> list[str]:
        return [item.strip().lower().lstrip(".") for item in value if item.strip()]


class StorageConfig(StrictModel):
    database: Path = Path("ctwatch.db")
    evidence_dir: Path = Path("evidence")


class NetworkConfig(StrictModel):
    """Network policy.

    ``extra_allowed_hosts`` exists for self-hosted mirrors of a supported
    service. It is not a general escape hatch: adding a watched domain here
    would break the passive-only guarantee, so keep it empty unless you run
    your own CT source.
    """

    user_agent: str = "ctwatch/0.1 (+https://github.com/lucasmeelz/ctwatch)"
    extra_allowed_hosts: list[str] = Field(default_factory=list)

    @field_validator("extra_allowed_hosts", mode="after")
    @classmethod
    def _normalize(cls, value: list[str]) -> list[str]:
        return [item.strip().lower() for item in value if item.strip()]


class Config(StrictModel):
    targets: list[TargetConfig] = Field(default_factory=list)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    sources: SourcesConfig = Field(default_factory=SourcesConfig)
    permutations: PermutationsConfig = Field(default_factory=PermutationsConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)

    @model_validator(mode="after")
    def _unique_brands(self) -> Config:
        seen: set[str] = set()
        for target in self.targets:
            key = target.brand.casefold()
            if key in seen:
                msg = f"duplicate target brand: {target.brand!r}"
                raise ValueError(msg)
            seen.add(key)
        return self

    def target_for_domain(self, domain: str) -> TargetConfig | None:
        wanted = _normalize_domain(domain)
        for target in self.targets:
            if wanted in target.canonical_domains:
                return target
        return None


class ConfigError(RuntimeError):
    """Raised when the configuration file is missing or invalid."""


def default_config_path(start: Path | None = None) -> Path:
    return (start or Path.cwd()) / DEFAULT_CONFIG_FILENAME


def load_config(path: Path | None = None) -> Config:
    """Read and validate a configuration file."""

    resolved = path or default_config_path()
    if not resolved.is_file():
        msg = f"configuration file not found: {resolved}. Run `ctwatch init` first."
        raise ConfigError(msg)

    try:
        raw: Any = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        msg = f"configuration file is not valid YAML: {resolved} ({exc})"
        raise ConfigError(msg) from exc

    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        msg = f"configuration file must contain a mapping at the top level: {resolved}"
        raise ConfigError(msg)

    try:
        return Config.model_validate(raw)
    except ValueError as exc:
        msg = f"invalid configuration in {resolved}: {exc}"
        raise ConfigError(msg) from exc
