from __future__ import annotations

from pathlib import Path

import pytest

from ctwatch.config import Config, ConfigError, load_config

PACKAGE_DEFAULT = (
    Path(__file__).resolve().parents[1] / "src" / "ctwatch" / "data" / "default_config.yaml"
)


def write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "ctwatch.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_shipped_default_config_is_valid() -> None:
    config = load_config(PACKAGE_DEFAULT)
    assert config.targets
    assert all(target.canonical_domains for target in config.targets)


def test_domains_are_normalized(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        """
        targets:
          - brand: "Le Monde"
            canonical_domains: ["  LeMonde.FR. "]
            allowlist: ["LEMONDE-ABONNEMENTS.fr"]
            keywords: [" Actu "]
        """,
    )
    config = load_config(path)
    target = config.targets[0]
    assert target.canonical_domains == ["lemonde.fr"]
    assert target.allowlist == ["lemonde-abonnements.fr"]
    assert target.keywords == ["actu"]


def test_unknown_key_is_rejected(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        """
        targets:
          - brand: "Le Monde"
            canonical_domains: ["lemonde.fr"]
            keyword: ["actu"]
        """,
    )
    with pytest.raises(ConfigError, match="keyword"):
        load_config(path)


def test_duplicate_brand_is_rejected(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        """
        targets:
          - brand: "Le Monde"
            canonical_domains: ["lemonde.fr"]
          - brand: "le monde"
            canonical_domains: ["lemonde.eu"]
        """,
    )
    with pytest.raises(ConfigError, match="duplicate target brand"):
        load_config(path)


def test_missing_file_points_to_init(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="ctwatch init"):
        load_config(tmp_path / "absent.yaml")


def test_empty_file_yields_defaults(tmp_path: Path) -> None:
    config = load_config(write(tmp_path, ""))
    assert config.targets == []
    assert config.sources.crtsh.enabled is True


def test_weights_are_normalized_to_one() -> None:
    config = Config.model_validate({"scoring": {"weights": {"levenshtein": 2.0, "tld_risk": 2.0}}})
    normalized = config.scoring.normalized_weights()
    assert normalized == {"levenshtein": 0.5, "tld_risk": 0.5}


def test_all_zero_weights_are_rejected() -> None:
    with pytest.raises(ValueError, match="greater than zero"):
        Config.model_validate({"scoring": {"weights": {"levenshtein": 0.0}}})


def test_target_lookup_by_domain() -> None:
    config = Config.model_validate(
        {"targets": [{"brand": "Le Monde", "canonical_domains": ["lemonde.fr"]}]}
    )
    assert config.target_for_domain("LEMONDE.fr.") is not None
    assert config.target_for_domain("lefigaro.fr") is None
