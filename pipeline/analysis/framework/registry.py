from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .stage import StageFunc


@dataclass(frozen=True)
class StageDefinition:
    name: str
    func: StageFunc
    kind: str = "analysis"  # analysis|diagnostic|reporting
    description: str = ""


_STAGE_REGISTRY: Dict[str, StageDefinition] = {}


def register_stage(
    name: str,
    *,
    kind: str = "analysis",
    description: str = "",
):
    """Decorator to register a stage."""

    def _decorator(fn: StageFunc) -> StageFunc:
        _STAGE_REGISTRY[name] = StageDefinition(name=name, func=fn, kind=kind, description=description)
        return fn

    return _decorator


def get_stage(name: str) -> StageDefinition:
    if name not in _STAGE_REGISTRY:
        raise KeyError(f"Unknown stage: {name}")
    return _STAGE_REGISTRY[name]


def list_stages(kind: Optional[str] = None) -> List[StageDefinition]:
    stages = list(_STAGE_REGISTRY.values())
    stages.sort(key=lambda s: s.name)
    if kind:
        return [s for s in stages if s.kind == kind]
    return stages
