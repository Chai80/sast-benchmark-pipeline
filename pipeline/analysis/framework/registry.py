from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from .stage import StageFunc


@dataclass(frozen=True)
class StageDefinition:
    """Metadata describing a registered stage.

    Notes
    -----
    ``requires`` and ``produces`` define a small contract around the
    :class:`~pipeline.analysis.framework.ArtifactStore`:

    - ``requires``: store keys that should exist before the stage runs.
    - ``produces``: store keys that should exist after the stage runs.

    These are intentionally lightweight so they can be used for:
    - pipeline ordering validation
    - future caching / stage skipping

    They do **not** change stage behavior; they make dependencies explicit.
    """

    name: str
    func: StageFunc

    kind: str = "analysis"  # analysis|diagnostic|reporting
    description: str = ""

    requires: Tuple[str, ...] = ()
    produces: Tuple[str, ...] = ()


_STAGE_REGISTRY: Dict[str, StageDefinition] = {}


def _coerce_keys(keys: Sequence[str] | None) -> Tuple[str, ...]:
    if not keys:
        return ()
    # Keep order stable, drop obvious empties.
    out: List[str] = []
    seen = set()
    for k in keys:
        s = str(k).strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return tuple(out)


def register_stage(
    name: str,
    *,
    kind: str = "analysis",
    description: str = "",
    requires: Sequence[str] | None = None,
    produces: Sequence[str] | None = None,
):
    """Decorator to register a stage."""

    def _decorator(fn: StageFunc) -> StageFunc:
        _STAGE_REGISTRY[name] = StageDefinition(
            name=name,
            func=fn,
            kind=kind,
            description=description,
            requires=_coerce_keys(requires),
            produces=_coerce_keys(produces),
        )
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
