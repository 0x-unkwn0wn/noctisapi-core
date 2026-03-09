from __future__ import annotations

from enum import Enum
from typing import Callable, Optional, Set


class LicenseTier(str, Enum):
    CORE = "core"
    PRO = "pro"


class Feature(str, Enum):
    CASES = "cases"
    CAMPAIGNS = "campaigns"
    REPLAY = "replay"
    ADVANCED_SCORING = "advanced_scoring"
    FILE_PIPELINE = "file_pipeline"
    API_MUTATION = "api_mutation"
    ANALYTICS = "analytics"


_CORE_FEATURES: Set[str] = set()
_PRO_ENABLED_PROVIDER: Optional[Callable[[], bool]] = None


def set_pro_enabled_provider(fn: Optional[Callable[[], bool]]) -> None:
    global _PRO_ENABLED_PROVIDER
    _PRO_ENABLED_PROVIDER = fn


def is_pro_enabled() -> bool:
    if _PRO_ENABLED_PROVIDER is not None:
        try:
            return bool(_PRO_ENABLED_PROVIDER())
        except Exception:
            return False
    return False


def get_license_tier() -> LicenseTier:
    return LicenseTier.PRO if is_pro_enabled() else LicenseTier.CORE


def enabled_features() -> Set[str]:
    if get_license_tier() == LicenseTier.PRO:
        return {
            Feature.CASES.value,
            Feature.CAMPAIGNS.value,
            Feature.REPLAY.value,
            Feature.ADVANCED_SCORING.value,
            Feature.FILE_PIPELINE.value,
            Feature.API_MUTATION.value,
            Feature.ANALYTICS.value,
        }
    return set(_CORE_FEATURES)


def has_feature(feature: str | Feature) -> bool:
    name = feature.value if isinstance(feature, Feature) else str(feature)
    return name in enabled_features()


def feature_flags() -> dict:
    tier = get_license_tier()
    features = sorted(enabled_features())
    return {
        "license_tier": tier.value,
        "license_features": features,
        "pro_enabled": tier == LicenseTier.PRO,
    }

