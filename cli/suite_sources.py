from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cli.ui import choose_from_menu
from pipeline.suites.bundles import safe_name
from pipeline.core import repo_id_from_repo_url, sanitize_sonar_key_fragment
from pipeline.models import CaseSpec, RepoSpec
from pipeline.suites.suite_definition import SuiteCase, SuiteCaseOverrides


def _discover_git_checkouts_under(root: Path) -> List[Path]:
    """Return top-level git checkouts under a root (ignores nested submodules).

    We consider any directory that contains a '.git' entry (file or dir) as a checkout.
    We then drop any candidates that live inside another candidate (submodules).
    """
    root = Path(root).expanduser().resolve()
    if not root.exists():
        return []

    candidates: set[Path] = set()
    for git_entry in root.rglob('.git'):
        try:
            parent = git_entry.parent
        except Exception:
            continue
        if parent == root:
            continue
        candidates.add(parent)

    # Keep only the outermost candidates.
    ordered = sorted(candidates, key=lambda p: len(p.parts))
    kept: list[Path] = []
    for c in ordered:
        if any(parent in kept for parent in c.parents):
            continue
        kept.append(c)

    return sorted(kept, key=lambda p: p.as_posix())


def _case_id_from_pathlike(rel: str) -> str:
    """Derive a stable case_id from a relative path / branch name.

    We use '__' for path separators to avoid collisions between:
      - 'a/b'  -> 'a__b'
      - 'a_b'  -> 'a_b'
    """
    rel = (rel or '').strip().replace('\\\\', '/').strip('/')
    return safe_name(rel.replace('/', '__') or 'case')


def _suite_case_from_repo_path(
    *,
    case_id: str,
    repo_path: Path,
    label: Optional[str] = None,
    branch: Optional[str] = None,
    track: Optional[str] = None,
    tags: Optional[dict] = None,
    overrides: Optional[SuiteCaseOverrides] = None,
) -> SuiteCase:
    """Create a SuiteCase for a local repo path."""
    cid = safe_name(case_id)
    repo_path = Path(repo_path).expanduser().resolve()
    lbl = label or cid
    rn = safe_name(cid)
    repo = RepoSpec(repo_key=None, repo_url=None, repo_path=str(repo_path))
    c = CaseSpec(
        case_id=cid,
        runs_repo_name=rn,
        label=lbl,
        repo=repo,
        branch=branch,
        track=track,
        tags=tags or {},
    )
    return SuiteCase(case=c, overrides=overrides or SuiteCaseOverrides())


def _load_suite_cases_from_csv(csv_path: Path) -> List[SuiteCase]:
    """Load SuiteCase entries from a CSV file.

    Supported formats
    -----------------
    1) With header (recommended):
         case_id,repo_path,label,branch,track,tags_json,sonar_project_key,aikido_git_ref

    2) Without header (positional):
         repo_path
         case_id,repo_path
         case_id,repo_path,label,branch,track,tags_json

    Notes
    -----
    - Blank lines and lines starting with '#' are ignored.
    - tags_json should be a JSON object like: {"set":"core"}
    """
    p = Path(csv_path).expanduser().resolve()
    if not p.exists():
        raise SystemExit(f"Cases CSV not found: {p}")

    rows: list[list[str]] = []
    with p.open('r', encoding='utf-8', newline='') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            if row and row[0].strip().startswith('#'):
                continue
            cleaned = [c.strip() for c in row]
            if all(not c for c in cleaned):
                continue
            rows.append(cleaned)

    if not rows:
        return []

    header = [c.lower() for c in rows[0]]
    has_header = 'repo_path' in header or 'repo_url' in header or 'repo_key' in header

    out: list[SuiteCase] = []

    def parse_tags(raw: str) -> dict:
        if not raw:
            return {}
        try:
            v = json.loads(raw)
            return v if isinstance(v, dict) else {}
        except Exception:
            return {}

    if has_header:
        keys = header
        for r in rows[1:]:
            d = {keys[i]: (r[i] if i < len(r) else '') for i in range(len(keys))}

            case_id = d.get('case_id') or ''
            repo_path = d.get('repo_path') or ''
            repo_url = d.get('repo_url') or ''
            repo_key = d.get('repo_key') or ''

            label = d.get('label') or None
            branch = d.get('branch') or None
            commit = d.get('commit') or None
            track = d.get('track') or None
            tags = parse_tags(d.get('tags') or d.get('tags_json') or '')

            overrides = SuiteCaseOverrides(
                sonar_project_key=(d.get('sonar_project_key') or None),
                aikido_git_ref=(d.get('aikido_git_ref') or None),
            )

            if repo_path:
                rp = Path(repo_path).expanduser().resolve()
                if not case_id:
                    case_id = rp.name
                sc = _suite_case_from_repo_path(
                    case_id=case_id,
                    repo_path=rp,
                    label=label,
                    branch=branch,
                    track=track,
                    tags=tags,
                    overrides=overrides,
                )
                # Patch in commit if present
                if commit:
                    c = sc.case
                    sc = SuiteCase(case=CaseSpec(**{**c.__dict__, 'commit': commit}), overrides=sc.overrides)
                out.append(sc)
                continue

            # URL/key-based case (rare in micro-suites; supported for completeness)
            if repo_url or repo_key:
                if not case_id:
                    case_id = repo_key or repo_id_from_repo_url(repo_url)
                cid = safe_name(case_id)
                lbl = label or cid
                runs_repo_name = safe_name(d.get('runs_repo_name') or cid)
                repo = RepoSpec(repo_key=repo_key or None, repo_url=repo_url or None, repo_path=None)
                case = CaseSpec(
                    case_id=cid,
                    runs_repo_name=runs_repo_name,
                    label=lbl,
                    repo=repo,
                    branch=branch,
                    commit=commit,
                    track=track,
                    tags=tags,
                )
                out.append(SuiteCase(case=case, overrides=overrides))
                continue

        return out

    # Positional mode (no header)
    for r in rows:
        if len(r) == 1:
            repo_path = r[0]
            rp = Path(repo_path).expanduser().resolve()
            out.append(_suite_case_from_repo_path(case_id=rp.name, repo_path=rp, label=rp.name, branch=None))
            continue

        case_id = r[0]
        repo_path = r[1] if len(r) > 1 else ''
        label = r[2] if len(r) > 2 else None
        branch = r[3] if len(r) > 3 else None
        track = r[4] if len(r) > 4 else None
        tags = parse_tags(r[5] if len(r) > 5 else '')

        rp = Path(repo_path).expanduser().resolve()
        out.append(_suite_case_from_repo_path(
            case_id=case_id,
            repo_path=rp,
            label=label,
            branch=branch,
            track=track,
            tags=tags,
        ))

    return out


def _load_suite_cases_from_worktrees_root(worktrees_root: Path) -> List[SuiteCase]:
    root = Path(worktrees_root).expanduser().resolve()
    repos = _discover_git_checkouts_under(root)

    out: list[SuiteCase] = []
    for repo_dir in repos:
        try:
            rel = repo_dir.relative_to(root).as_posix()
        except Exception:
            rel = repo_dir.name
        case_id = _case_id_from_pathlike(rel)
        out.append(_suite_case_from_repo_path(
            case_id=case_id,
            repo_path=repo_dir,
            label=rel,
            branch=rel,
        ))

    return out


def _resolve_repo_for_suite_case_interactive(
    *,
    repo_registry: Dict[str, Dict[str, str]],
) -> Tuple[RepoSpec, str, str]:
    """Resolve a repo target for *one* suite case.

    Returns (repo_spec, label, repo_id).
    """
    source = choose_from_menu(
        "Choose a repo source for this case:",
        {
            "preset": "Pick from preset repos",
            "custom_url": "Enter a custom repo URL",
            "local_path": "Use a local repo path",
        },
    )

    if source == "preset":
        key = choose_from_menu("Choose a preset repo:", {k: v["label"] for k, v in repo_registry.items()})
        entry = repo_registry[key]
        repo_url = entry.get("repo_url")
        label = entry.get("label", key)
        return RepoSpec(repo_key=key, repo_url=repo_url, repo_path=None), label, key

    if source == "custom_url":
        while True:
            url = input("Enter full repo URL (https://... .git or git@...): ").strip()
            if url.startswith(("https://", "http://", "git@")):
                rid = repo_id_from_repo_url(url)
                return RepoSpec(repo_key=None, repo_url=url, repo_path=None), url, rid
            print("That doesn't look like a git URL. Try again.")

    # local_path
    while True:
        path = input("Enter local repo path: ").strip()
        if path:
            p = Path(path).resolve()
            rid = sanitize_sonar_key_fragment(p.name)
            return RepoSpec(repo_key=None, repo_url=None, repo_path=str(p)), p.name, rid
        print("Empty path. Try again.")
