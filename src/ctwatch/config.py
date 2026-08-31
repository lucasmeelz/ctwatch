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


# Suffixes that turn up disproportionately in impersonation registrations:
# cheap or free, no verification, and in several cases actively news-flavoured.
DEFAULT_HIGH_RISK_TLDS: tuple[str, ...] = (
    "top",
    "xyz",
    "icu",
    "sbs",
    "cfd",
    "info",
    "click",
    "link",
    "live",
    "shop",
    "online",
    "site",
    "news",
    "press",
)
DEFAULT_MEDIUM_RISK_TLDS: tuple[str, ...] = ("net", "org", "co", "io", "me", "biz")


class TldRiskConfig(StrictModel):
    """Suffix risk lists.

    Defaults live here rather than only in the shipped YAML, so that a
    configuration written from scratch still scores suffixes sensibly instead
    of silently treating every one of them as neutral.
    """

    high: list[str] = Field(default_factory=lambda: list(DEFAULT_HIGH_RISK_TLDS))
    medium: list[str] = Field(default_factory=lambda: list(DEFAULT_MEDIUM_RISK_TLDS))

    @field_validator("high", "medium", mode="after")
    @classmethod
    def _normalize(cls, value: list[str]) -> list[str]:
        return [item.strip().lower().lstrip(".") for item in value if item.strip()]


# The criteria a score can be built from. Declared here so that a typo in the
# weights section fails at load time rather than silently dropping a signal.
SCORING_CRITERIA: tuple[str, ...] = (
    "levenshtein",
    "homoglyph",
    "keyword_combo",
    "tld_risk",
    "cert_age",
)


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
        unknown = sorted(set(value) - set(SCORING_CRITERIA))
        if unknown:
            known = ", ".join(SCORING_CRITERIA)
            msg = f"unknown scoring criterion: {', '.join(unknown)}. Known criteria: {known}"
            raise ValueError(msg)
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
    """The live feed of newly issued certificates.

    The public CertStream server is a single point of failure and is often
    unavailable; ``fallback_to_polling`` is what keeps a monitor useful when it
    is. Point ``url`` at a self-hosted server for anything that has to run
    unattended.
    """

    enabled: bool = False
    url: str = "wss://certstream.calidog.io/"
    reconnect_delay_seconds: float = 5.0
    max_reconnect_delay_seconds: float = 300.0
    max_consecutive_failures: int = 5
    fallback_to_polling: bool = True
    polling_interval_seconds: float = 900.0


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


class DnsConfig(StrictModel):
    """Name resolution, over HTTPS.

    Resolving a suspicious name is not contacting it, but a plaintext query
    tells whoever is on the path which names an analyst is looking at. DNS over
    HTTPS removes that leak and keeps the answer archivable as evidence.
    """

    enabled: bool = True
    resolver_url: str = "https://cloudflare-dns.com/dns-query"
    record_types: list[str] = Field(default_factory=lambda: ["A", "AAAA", "NS", "MX"])
    rate_limit_rps: float = 5.0

    @field_validator("record_types", mode="after")
    @classmethod
    def _normalize(cls, value: list[str]) -> list[str]:
        return [item.strip().upper() for item in value if item.strip()]


class RdapConfig(StrictModel):
    """Registration data, read from the registry.

    RDAP servers cannot be listed in advance — several hundred registries each
    run their own — so the hosts are learned from IANA's bootstrap document at
    run time and recorded as having come from there.
    """

    enabled: bool = True
    bootstrap_url: str = "https://data.iana.org/rdap/dns.json"
    rate_limit_rps: float = 1.0


class UrlscanConfig(StrictModel):
    """Third-party rendering of suspicious pages.

    Searching urlscan's archive reveals nothing and needs no key. Submitting a
    page for scanning is a different act — it is a real visit, and a public
    submission is visible to the operator — so it is not done here.
    """

    enabled: bool = True
    api_key_env: str = "URLSCAN_API_KEY"
    limit: int = 10
    rate_limit_rps: float = 0.5

    def api_key(self) -> str | None:
        return os.environ.get(self.api_key_env) or None


class EnrichConfig(StrictModel):
    dns: DnsConfig = Field(default_factory=DnsConfig)
    rdap: RdapConfig = Field(default_factory=RdapConfig)
    urlscan: UrlscanConfig = Field(default_factory=UrlscanConfig)


class ConsoleNotifyConfig(StrictModel):
    enabled: bool = True


class JsonlNotifyConfig(StrictModel):
    enabled: bool = False
    path: Path = Path("alerts.jsonl")


class WebhookNotifyConfig(StrictModel):
    """An HTTPS endpoint to post alerts to.

    The host is added to the outbound allowlist when this is enabled, and
    nowhere else: an operator opting into a webhook is declaring that host, the
    same way they declare a source.
    """

    enabled: bool = False
    url: str = ""
    timeout_seconds: float = 10.0
    min_score: float = 0.0

    @model_validator(mode="after")
    def _needs_a_url(self) -> WebhookNotifyConfig:
        if self.enabled and not self.url.startswith("https://"):
            msg = "a webhook must be enabled with an https:// url"
            raise ValueError(msg)
        return self


class NotifyConfig(StrictModel):
    console: ConsoleNotifyConfig = Field(default_factory=ConsoleNotifyConfig)
    jsonl: JsonlNotifyConfig = Field(default_factory=JsonlNotifyConfig)
    webhook: WebhookNotifyConfig = Field(default_factory=WebhookNotifyConfig)


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
    enrich: EnrichConfig = Field(default_factory=EnrichConfig)
    notify: NotifyConfig = Field(default_factory=NotifyConfig)
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
