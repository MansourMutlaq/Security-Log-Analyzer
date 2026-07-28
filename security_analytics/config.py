"""Validated project configuration loading."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from security_analytics.exceptions import ConfigurationError


class ThresholdWindow(BaseModel):
    """Detection threshold and time-window configuration."""

    model_config = ConfigDict(extra="forbid")

    threshold: int = Field(ge=1)
    window_seconds: int = Field(ge=1)


class UserEnumerationSettings(BaseModel):
    """Invalid-user enumeration correlation settings."""

    model_config = ConfigDict(extra="forbid")

    distinct_user_threshold: int = Field(ge=1)
    window_seconds: int = Field(ge=1)


class SuccessAfterFailureSettings(BaseModel):
    """Successful authentication after repeated failures settings."""

    model_config = ConfigDict(extra="forbid")

    failure_threshold: int = Field(ge=1)
    window_seconds: int = Field(ge=1)


class InterfaceFlapSettings(BaseModel):
    """Interface state-change correlation settings."""

    model_config = ConfigDict(extra="forbid")

    window_seconds: int = Field(ge=1)


class SuspiciousSudoSettings(BaseModel):
    """Commands that require security review."""

    model_config = ConfigDict(extra="forbid")

    keywords: list[str]


class AWSDetectionSettings(BaseModel):
    """Cloud-specific detection settings."""

    model_config = ConfigDict(extra="forbid")

    public_admin_ports: list[int]
    privileged_policies: list[str]


class DetectionSettings(BaseModel):
    """All configurable detection-engine settings."""

    model_config = ConfigDict(extra="forbid")

    linux_brute_force: ThresholdWindow
    linux_user_enumeration: UserEnumerationSettings
    successful_login_after_failures: SuccessAfterFailureSettings
    cisco_interface_flap: InterfaceFlapSettings
    suspicious_sudo: SuspiciousSudoSettings
    aws: AWSDetectionSettings


class ApplicationSettings(BaseModel):
    """Root project configuration model."""

    model_config = ConfigDict(extra="forbid")

    detection: DetectionSettings


def load_settings(
    path: str | Path = "config/detection_rules.yml",
) -> ApplicationSettings:
    """Load and validate detection settings from YAML."""

    config_path = Path(path)

    if not config_path.is_file():
        raise ConfigurationError(
            f"Detection configuration not found: {config_path}"
        )

    try:
        raw_config = yaml.safe_load(
            config_path.read_text(encoding="utf-8")
        )
        return ApplicationSettings.model_validate(raw_config)
    except (yaml.YAMLError, ValueError, TypeError) as exc:
        raise ConfigurationError(
            f"Invalid detection configuration: {config_path}"
        ) from exc