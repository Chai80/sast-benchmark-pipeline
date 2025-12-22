"""tools/sonar/api.py

All SonarCloud HTTP calls live here.

Design goals:
  - Keep network I/O separated from parsing and normalization.
  - Provide best-effort pagination and resilience (return partial results on errors).
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import requests

from .types import SonarConfig


def _auth_headers(cfg: SonarConfig) -> Dict[str, str]:
    return {"Authorization": f"Bearer {cfg.token}"}


def validate_sonarcloud_credentials(cfg: SonarConfig) -> None:
    """Validate token and organization with simple SonarCloud API calls."""
    headers = _auth_headers(cfg)

    resp = requests.get(f"{cfg.host}/api/authentication/validate", headers=headers, timeout=10)
    resp.raise_for_status()
    if not resp.json().get("valid", False):
        raise RuntimeError("SonarCloud token appears to be invalid (valid=false).")

    resp = requests.get(
        f"{cfg.host}/api/organizations/search",
        params={"organizations": cfg.org},
        headers=headers,
        timeout=10,
    )
    resp.raise_for_status()
    orgs = (resp.json() or {}).get("organizations", [])
    if not orgs:
        raise RuntimeError(
            f"No organization found for key '{cfg.org}'. "
            "Double-check SONAR_ORG in the SonarCloud UI."
        )


def wait_for_ce_success(cfg: SonarConfig, project_key: str, timeout_sec: int = 300) -> None:
    """Best-effort wait for Compute Engine to finish the latest analysis."""
    ce_url = f"{cfg.host}/api/ce/component"
    headers = _auth_headers(cfg)
    params = {"component": project_key, "organization": cfg.org}

    start = time.time()
    while True:
        try:
            resp = requests.get(ce_url, params=params, headers=headers, timeout=30)
        except requests.RequestException as e:
            print(f"⚠️ CE request error for {project_key}: {e}")
            return

        if resp.status_code == 404:
            print(f"⚠️ CE: project '{project_key}' not found (404). Skipping wait.")
            return
        if not resp.ok:
            print(f"⚠️ CE status fetch failed: HTTP {resp.status_code} {resp.text[:120]}")
            return

        data = resp.json()
        current = data.get("current")

        if current:
            status = current.get("status")
            if status == "SUCCESS":
                print(f"✅ CE job for {project_key} completed successfully.")
                return
            if status in ("FAILED", "CANCELED"):
                print(f"⚠️ CE job for {project_key} ended with status={status}.")
                return
            print(f"⏳ CE job status={status}, waiting...")
        else:
            print(f"ℹ️ No current CE job for {project_key}, assuming done.")
            return

        if time.time() - start > timeout_sec:
            print(f"⚠️ Timed out waiting for CE job for {project_key}")
            return

        time.sleep(5)


def fetch_all_issues_for_project(cfg: SonarConfig, project_key: str) -> List[Dict[str, Any]]:
    """Fetch all issues for a project via /api/issues/search (paginated)."""
    headers = _auth_headers(cfg)
    all_issues: List[Dict[str, Any]] = []
    page = 1
    page_size = 500

    while True:
        params = {
            "componentKeys": project_key,
            "organization": cfg.org,
            "ps": page_size,
            "p": page,
        }

        try:
            resp = requests.get(
                f"{cfg.host}/api/issues/search",
                params=params,
                headers=headers,
                timeout=30,
            )
        except requests.RequestException as e:
            print(f"⚠️ Issues request error page {page}: {e}. Returning partial results.")
            break

        if resp.status_code == 404:
            print(f"⚠️ Issues search: project '{project_key}' not found (404).")
            break

        if resp.status_code == 400 and "Can return only the first 10000 results" in resp.text:
            print(f"⚠️ Hit SonarCloud 10k issue limit. Returning first {len(all_issues)} issues.")
            break

        if 500 <= resp.status_code < 600:
            print(f"⚠️ Server error {resp.status_code}. Returning partial results.")
            break

        if not resp.ok:
            print(f"⚠️ HTTP {resp.status_code}: {resp.text[:200]!r}. Returning partial results.")
            break

        try:
            data = resp.json()
        except ValueError:
            print("⚠️ Could not decode JSON. Returning partial results.")
            break

        issues = data.get("issues", []) or []
        all_issues.extend(issues)

        if len(issues) < page_size:
            break
        page += 1

    return all_issues


def fetch_rule_show(cfg: SonarConfig, rule_key: str, organization: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Fetch /api/rules/show for a rule_key. Returns JSON dict or None on failure."""
    headers = _auth_headers(cfg)
    params: Dict[str, Any] = {"key": rule_key, "organization": organization or cfg.org}

    try:
        resp = requests.get(f"{cfg.host.rstrip('/')}/api/rules/show", params=params, headers=headers, timeout=15)
    except requests.RequestException as e:
        print(f"⚠️ Failed to fetch rule metadata for {rule_key}: {e}")
        return None

    if resp.status_code == 404:
        print(f"⚠️ Rule {rule_key} not found (404); skipping.")
        return None
    if not resp.ok:
        print(f"⚠️ Rule metadata HTTP {resp.status_code}: {resp.text[:200]!r}")
        return None

    try:
        return resp.json()
    except ValueError:
        print(f"⚠️ Could not decode rules/show JSON for {rule_key}")
        return None
