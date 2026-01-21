"""pipeline.scanners

Central registry of supported scanners.

Why this exists
---------------
Several parts of the pipeline need to agree on the *same* scanner facts:
- which scanners are supported (validation)
- which scanners are used by default (CLI defaults)
- human-friendly labels (menus / help text)
- which runner script to execute under ``tools/`` (command building)
- what benchmark tracks a scanner supports (best-effort filtering)

Historically these facts drifted across multiple files (CLI, core, ad-hoc checks).
This module makes the filesystem/execution layer consistent by defining them
*once*.

What belongs here (clean-architecture rule)
------------------------------------------
This registry may contain **small, pure wiring hooks** used by the pipeline to
invoke tools consistently:
- required env vars (fail fast with a good error)
- extra CLI args that are derived from the run request (e.g. Sonar project-key)
- how a tool identifies its target (repo-path/repo-url vs git-ref)

These hooks must remain *pure*:
- no filesystem writes
- no subprocess execution
- no network/API calls

Anything that actually performs scanning, API calls, or parsing belongs in
``tools/``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Set

from pipeline.identifiers import derive_sonar_project_key

try:
    # Python 3.8+ (typing.Literal exists). Keep import local to avoid hard
    # failures if someone runs on an older interpreter.
    from typing import Literal
except Exception:  # pragma: no cover
    Literal = str  # type: ignore


@dataclass(frozen=True)
class ScannerRunContext:
    """Best-effort per-case context used by scanner hooks.

    This is intentionally tiny; add fields only when a scanner integration
    genuinely needs them.
    """

    git_branch: Optional[str] = None
    git_commit: Optional[str] = None


@dataclass(frozen=True)
class ScannerInfo:
    """Static metadata describing one scanner integration."""

    key: str
    label: str
    script: str
    tracks: frozenset[str]

    # How this tool identifies the target repository.
    # - "repo": standard tools that accept --repo-path/--repo-url
    # - "git-ref": tools that use a git slug/reference (e.g. Aikido cloud mode)
    target_mode: "Literal['repo', 'git-ref']" = "repo"

    # Optional env preflight: vars that must exist for the tool to run.
    required_env: tuple[str, ...] = ()

    # Optional pure hook to derive additional CLI args.
    # NOTE: uses a string annotation to avoid importing run_case.RunRequest.
    extra_args_builder: Optional[Callable[["RunRequest", ScannerRunContext], Dict[str, Any]]] = None

    default: bool = True


def _sonar_extra_args(req: "RunRequest", _ctx: ScannerRunContext) -> Dict[str, Any]:
    """Derive Sonar args from the RunRequest.

    Pure function: reads env + request, returns CLI args.
    """

    # Prefer an explicit override (suite/case-level override).
    if getattr(req, "sonar_project_key", None):
        return {"project-key": str(req.sonar_project_key)}

    org = os.environ.get("SONAR_ORG") or ""
    return {"project-key": derive_sonar_project_key(org, str(req.repo_id))}


def _aikido_extra_args(req: "RunRequest", ctx: ScannerRunContext) -> Dict[str, Any]:
    """Derive Aikido args from the RunRequest.

    Aikido's cloud integration identifies repos by a git-ref (owner/repo or URL
    fragment) and optionally a branch when multi-branch scanning is enabled.
    """

    out: Dict[str, Any] = {}

    # Prefer the actual git branch observed in the checkout; fallback to the
    # case's declared branch if present.
    branch = ctx.git_branch or getattr(getattr(req, "case", None), "branch", None)
    if branch:
        out["branch"] = str(branch)

    # Prefer explicit override, otherwise derive from repo_url.
    git_ref = getattr(req, "aikido_git_ref", None)
    if not git_ref:
        try:
            repo_url = getattr(getattr(getattr(req, "case", None), "repo", None), "repo_url", None)
            if repo_url:
                git_ref = str(repo_url).rstrip("/").replace(".git", "")
        except Exception:
            git_ref = None
    if git_ref:
        out["git-ref"] = str(git_ref)

    # Keep per-case repo folder naming stable for downstream analysis.
    try:
        out["repo-name"] = str(req.case.runs_repo_name)
    except Exception:
        pass

    return out


# Canonical registry.
#
# NOTE: dict insertion order is preserved in modern Python, so the order here is
# the order used for DEFAULT_SCANNERS / DEFAULT_SCANNERS_CSV.
SCANNERS: Dict[str, ScannerInfo] = {
    "semgrep": ScannerInfo(
        key="semgrep",
        label="Semgrep",
        script="scan_semgrep.py",
        tracks=frozenset({"sast", "iac", "secrets"}),
        default=True,
    ),
    "snyk": ScannerInfo(
        key="snyk",
        label="Snyk Code",
        script="scan_snyk.py",
        tracks=frozenset({"sast"}),
        default=True,
    ),
    "sonar": ScannerInfo(
        key="sonar",
        label="SonarCloud",
        script="scan_sonar.py",
        tracks=frozenset({"sast"}),
        required_env=("SONAR_ORG", "SONAR_TOKEN"),
        extra_args_builder=_sonar_extra_args,
        default=True,
    ),
    "aikido": ScannerInfo(
        key="aikido",
        label="Aikido",
        script="scan_aikido.py",
        tracks=frozenset({"sast", "sca", "iac", "secrets"}),
        target_mode="git-ref",
        required_env=("AIKIDO_CLIENT_ID", "AIKIDO_CLIENT_SECRET"),
        extra_args_builder=_aikido_extra_args,
        default=True,
    ),
}


# Derived views (kept as plain collections for convenience/compatibility).
SUPPORTED_SCANNERS: Set[str] = set(SCANNERS.keys())

DEFAULT_SCANNERS: List[str] = [k for k, info in SCANNERS.items() if info.default]
DEFAULT_SCANNERS_CSV: str = ",".join(DEFAULT_SCANNERS)

SCANNER_LABELS: Dict[str, str] = {k: info.label for k, info in SCANNERS.items()}
SCANNER_SCRIPTS: Dict[str, str] = {k: info.script for k, info in SCANNERS.items()}

SCANNER_TARGET_MODES: Dict[str, str] = {k: str(info.target_mode) for k, info in SCANNERS.items()}

# Keep the legacy shape: Dict[str, set[str]]
SCANNER_TRACKS: Dict[str, set[str]] = {k: set(info.tracks) for k, info in SCANNERS.items()}
