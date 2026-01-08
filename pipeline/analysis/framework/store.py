from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass
class ArtifactStore:
    """In-memory scratchpad for analysis stages.

    Stages should:
    - read inputs from ctx
    - write outputs to ctx.out_dir
    - cache intermediate results in this store to avoid recomputation

    The store is intentionally untyped (Dict[str, Any]) because it functions
    like a small, local "data lake" for one analysis run.
    """

    data: Dict[str, Any] = field(default_factory=dict)

    # Output artifacts written to disk (name -> path)
    artifacts: Dict[str, Path] = field(default_factory=dict)

    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def put(self, key: str, value: Any) -> None:
        self.data[key] = value

    def require(self, key: str) -> Any:
        if key not in self.data:
            raise KeyError(f"Required artifact missing from store: {key}")
        return self.data[key]

    def add_artifact(self, name: str, path: Path) -> None:
        self.artifacts[name] = Path(path)

    def add_warning(self, message: str) -> None:
        self.warnings.append(str(message))

    def add_error(self, message: str) -> None:
        self.errors.append(str(message))

    def artifact_paths_rel(self, base: Optional[Path]) -> Dict[str, str]:
        if base is None:
            return {k: str(v) for k, v in self.artifacts.items()}
        out: Dict[str, str] = {}
        for k, v in self.artifacts.items():
            try:
                out[k] = str(Path(v).resolve().relative_to(Path(base).resolve()))
            except Exception:
                out[k] = str(v)
        return out
