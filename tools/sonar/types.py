from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SonarConfig:
    """Connection settings for SonarCloud API calls."""
    host: str
    org: str
    token: str
