from __future__ import annotations

import csv
import json
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cli.common import parse_csv
from cli.ui import choose_from_menu
from pipeline.suites.bundles import safe_name
from pipeline.identifiers import repo_id_from_repo_url, sanitize_sonar_key_fragment
from pipeline.models import CaseSpec, RepoSpec
from pipeline.suites.suite_definition import SuiteCase, SuiteCaseOverrides

# ---------------------------------------------------------------------------
# Suite source helper: bootstrap worktrees from repo_url + branches
#
# Why this exists:
# - benchmark mode clones a single checkout under repos/<repo_id>
# - suite mode expects multiple local checkouts (one per case/branch)
#
# This helper bridges the gap for branch-per-case suites by creating/updating
# a deterministic worktrees root:
#   repos/worktrees/<repo_id>/_base   (base clone)
#   repos/worktrees/<repo_id>/<branch> (one worktree per branch)
# ---------------------------------------------------------------------------
_OWASP_RANGE_RE = re.compile(r"(?i)^A?(\d{1,2})\s*(?:-|\.\.)\s*A?(\d{1,2})$")
_OWASP_TOKEN_RE = re.compile(r"(?i)^A?(\d{1,2})$")
def _parse_branches_spec(raw: Optional[str]) -> List[str]:
    """Parse a branch specification into a deterministic list.
    - CSV: "A03,A07" or "main,dev"
    - OWASP-style ranges: "A01-A10" or "A01..A10"
    Notes:
    - We only auto-expand ranges when both endpoints are within 1..10.
    - We normalize common remote prefixes like "origin/A03".
    """
    out: List[str] = []
    seen: set[str] = set()
    for tok in parse_csv(raw):
        t = (tok or "").strip()
        if not t:
            continue
        # Normalize pasted unicode dashes.
        t = t.replace("–", "-").replace("—", "-")
        # Strip common remote/ref prefixes.
        for pref in ("refs/remotes/origin/", "refs/heads/", "origin/"):
            if t.startswith(pref):
                t = t[len(pref):]
        # Expand OWASP-ish ranges (safe guard: endpoints 1..10 only).
        expanded: List[str] = []
        m_range = _OWASP_RANGE_RE.match(t)
        if m_range:
            a = int(m_range.group(1))
            b = int(m_range.group(2))
            if 1 <= a <= 10 and 1 <= b <= 10 and str(t).upper().startswith("A"):
                lo, hi = (a, b) if a <= b else (b, a)
                expanded = [f"A{i:02d}" for i in range(lo, hi + 1)]
            else:
                expanded = [t]
        else:
            m_tok = _OWASP_TOKEN_RE.match(t)
            if m_tok and 1 <= int(m_tok.group(1)) <= 10 and str(t).upper().startswith("A"):
                expanded = [f"A{int(m_tok.group(1)):02d}"]
            else:
                expanded = [t]
        for b in expanded:
            b2 = b.strip()
            if not b2:
                continue
            if b2 not in seen:
                seen.add(b2)
                out.append(b2)
    return out
def _run_git(*, cwd: Path, argv: List[str]) -> None:
    """Run a git command and raise a friendly error on failure."""
    cmd = ["git"] + list(argv)
    p = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    if p.returncode != 0:
        out = (p.stdout or "") + (p.stderr or "")
        out = out.strip()
        msg = f"git {' '.join(argv)} failed (cwd={cwd})"
        if out:
            msg += f"\n{out}"
        raise SystemExit(msg)

def _resolve_branch_token_to_origin_branch(token: str, *, origin_branches: List[str]) -> str:
    """Resolve a user token like 'A01' to a real origin branch name.

    Rules (in order):
      1) exact match (token == remote branch)
      2) case-insensitive exact match
      3) if token looks like A01..A10: match aXX boundary-ish (e.g. '...-a01-...')
      4) unique case-insensitive substring match
    """
    t = (token or "").strip()
    if not t:
        raise SystemExit("Empty branch token in --branches")

    # 1) exact match
    if t in origin_branches:
        return t

    t_lower = t.lower()

    # 2) case-insensitive exact match
    for b in origin_branches:
        if b.lower() == t_lower:
            return b

    # 3) A01..A10 special-case matching (handles verbose branch names)
    m = re.fullmatch(r"A(0[1-9]|10)", t.upper())
    if m:
        n = int(m.group(1))
        needle = f"a{n:02d}"
        pat = re.compile(rf"(^|[^0-9a-z]){re.escape(needle)}([^0-9a-z]|$)", re.IGNORECASE)
        matches = [b for b in origin_branches if pat.search(b)]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise SystemExit(
                f"Branch token '{t}' is ambiguous. Matches multiple origin branches: {matches}. "
                f"Pass the full branch name via --branches."
            )

    # 4) unique substring match
    matches = [b for b in origin_branches if t_lower in b.lower()]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise SystemExit(
            f"Could not resolve branch token '{t}' against origin branches. "
            f"Pass the full branch name via --branches."
        )
    raise SystemExit(
        f"Branch token '{t}' is ambiguous. Matches: {matches[:10]}{'...' if len(matches) > 10 else ''}. "
        f"Pass the full branch name via --branches."
    )
def _run_git_capture(*, cwd: Path, argv: List[str]) -> str:
    """Run a git command and return stdout (stripped)."""
    cmd = ["git"] + list(argv)
    p = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    if p.returncode != 0:
        out = (p.stdout or "") + (p.stderr or "")
        out = out.strip()
        msg = f"git {' '.join(argv)} failed (cwd={cwd})"
        if out:
            msg += f"\n{out}"
        raise SystemExit(msg)
    return (p.stdout or "").strip()


def _list_origin_remote_branches(*, base: Path) -> List[str]:
    """Return remote branch names under origin/* (excluding origin/HEAD)."""
    out = _run_git_capture(
        cwd=base,
        argv=["for-each-ref", "--format=%(refname:short)", "refs/remotes/origin"],
    )
    branches: List[str] = []
    for line in (out.splitlines() if out else []):
        s = (line or "").strip()
        if not s or s.endswith("/HEAD"):
            continue
        if s.startswith("origin/"):
            s = s[len("origin/"):]
        branches.append(s)
    # deterministic ordering
    return sorted(set(branches))


def _local_branch_exists(*, base: Path, branch: str) -> bool:
    """Check if refs/heads/<branch> exists."""
    p = subprocess.run(
        ["git", "show-ref", "--verify", f"refs/heads/{branch}"],
        cwd=str(base),
        capture_output=True,
        text=True,
    )
    return p.returncode == 0


def _resolve_remote_branch_for_token(*, token: str, remote_branches: List[str]) -> str:
    """Resolve a user-provided branch token to an origin/* branch.

    Many branch-per-case repos use verbose branch names like
    "owasp2021-a01-calibration-sample" while QA scopes use tokens like "A01".

    Resolution rules (in order):
    1) exact match
    2) case-insensitive exact match
    3) unique token match (case-insensitive) using a boundary-ish heuristic
       (e.g. token A01 matches 'owasp2021-a01-calibration-sample')
    """
    t = (token or "").strip()
    if not t:
        raise SystemExit("Empty branch token provided")

    if t in remote_branches:
        return t

    tl = t.lower()
    for rb in remote_branches:
        if rb.lower() == tl:
            return rb

    # Token/boundary-ish match: treat non-alnum as separators.
    pat = re.compile(r"(^|[^a-z0-9])" + re.escape(tl) + r"([^a-z0-9]|$)")
    matches = [rb for rb in remote_branches if pat.search(rb.lower())]
    if len(matches) == 1:
        return matches[0]

    if len(matches) == 0:
        hint = ", ".join(remote_branches[:15])
        more = "" if len(remote_branches) <= 15 else f" ... (+{len(remote_branches) - 15} more)"
        raise SystemExit(
            f"Could not resolve branch token '{t}' to a remote branch under origin/.\n"
            "Hint: pass --branches with exact remote branch names (or a token that uniquely matches).\n"
            f"Remote branches: {hint}{more}"
        )

    preview = ", ".join(matches[:15])
    more = "" if len(matches) <= 15 else f" ... (+{len(matches) - 15} more)"
    raise SystemExit(
        f"Branch token '{t}' is ambiguous; multiple remote branches matched: {preview}{more}.\n"
        "Hint: pass --branches with exact remote branch names."
    )
def _bootstrap_worktrees_from_repo_url(*, repo_url: str, branches: List[str], worktrees_root: Path) -> Path:
    """Ensure a worktrees root exists for repo_url and contains the requested branches.

    Filesystem-first and idempotent:
    - Creates <worktrees_root> and a base clone at <worktrees_root>/_base if missing.
    - Fetches origin/prunes stale refs.
    - Adds one worktree per requested branch token (directory names are sanitized).
    - Resolves tokens like A01..A10 to actual origin branch names when repos use verbose naming.

    Returns the resolved worktrees_root.
    """
    root = Path(worktrees_root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)

    base = root / "_base"
    if not (base / ".git").exists():
        print(f"📥 cloning repo for suite worktrees: {repo_url} -> {base}")
        p = subprocess.run(["git", "clone", repo_url, str(base)], capture_output=True, text=True)
        if p.returncode != 0:
            out = (p.stdout or "") + (p.stderr or "")
            raise SystemExit(f"git clone failed for {repo_url}:\n{out.strip()}")

    # Keep refs up to date.
    _run_git(cwd=base, argv=["fetch", "origin", "--prune"])
    _run_git(cwd=base, argv=["worktree", "prune"])

    origin_branches = _list_origin_remote_branches(base=base)

    # Deterministic branch ordering.
    unique_tokens = sorted({b.strip() for b in branches if (b or "").strip()})
    for token in unique_tokens:
        wt_dir = root / safe_name(token.replace("/", "__"))

        # If the path exists but isn't a checkout, it may be a partial failed worktree.
        if wt_dir.exists():
            if not (wt_dir / ".git").exists():
                raise SystemExit(
                    f"Worktree path exists but is not a git checkout: {wt_dir}\n"
                    "Remove it and retry."
                )
            continue

        # Resolve token (e.g. 'A01') to an actual remote branch name (possibly verbose).
        resolved = _resolve_branch_token_to_origin_branch(token, origin_branches=origin_branches)
        origin_ref = f"origin/{resolved}"

        # -B makes reruns idempotent: create or reset local branch <token> to point at origin_ref.
        print(f"🌿 worktree add: {token} -> {wt_dir} (from {origin_ref})")
        _run_git(cwd=base, argv=["worktree", "add", "-B", token, str(wt_dir), origin_ref])

    return root

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
