"""tools/aikido/client.py

Minimal Aikido Public API client helpers.

Adds:
- retry/backoff for transient errors (429 / 5xx)
- optional on-disk caching for expensive endpoints:
  - /repositories/code
  - /issues/export
"""

from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

TOKEN_URL = "https://app.aikido.dev/api/oauth/token"
API_ROOT = "https://app.aikido.dev/api/public/v1"
AIKIDO_TOOL_VERSION = "public-api-v1"

# Tunables (override via env vars)
_HTTP_MAX_RETRIES = int(os.environ.get("AIKIDO_HTTP_MAX_RETRIES", "6"))
_HTTP_BACKOFF_BASE = float(os.environ.get("AIKIDO_HTTP_BACKOFF_BASE", "1.7"))
_HTTP_BACKOFF_CAP = float(os.environ.get("AIKIDO_HTTP_BACKOFF_CAP", "60"))
_CACHE_TTL_SECS_DEFAULT = int(os.environ.get("AIKIDO_CACHE_TTL_SECS", "3600"))  # 1h
_NO_CACHE = os.environ.get("AIKIDO_NO_CACHE", "").lower() in {"1", "true", "yes"}


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    """Parse Retry-After header (seconds). We only handle the integer form."""
    if not value:
        return None
    try:
        return float(int(value.strip()))
    except Exception:
        return None


def _request_json(
    method: str,
    url: str,
    *,
    headers: Dict[str, str],
    data: Optional[Dict[str, Any]] = None,
    timeout: float = 30,
) -> Any:
    """HTTP request with retry/backoff for 429 and 5xx."""
    last_resp: Optional[requests.Response] = None
    last_exc: Optional[Exception] = None

    for attempt in range(_HTTP_MAX_RETRIES + 1):
        try:
            resp = requests.request(method, url, headers=headers, data=data, timeout=timeout)
            last_resp = resp

            if resp.status_code == 429 or resp.status_code >= 500:
                ra = _parse_retry_after(resp.headers.get("Retry-After"))
                backoff = min(_HTTP_BACKOFF_CAP, (_HTTP_BACKOFF_BASE**attempt))
                sleep_s = ra if ra is not None else backoff
                if attempt < 3:
                    print(
                        f"Aikido API {resp.status_code} for {method} {url} "
                        f"(attempt {attempt+1}/{_HTTP_MAX_RETRIES+1}); retrying in {sleep_s:.1f}s"
                    )
                time.sleep(sleep_s)
                continue

            resp.raise_for_status()
            return resp.json()

        except Exception as e:
            last_exc = e
            backoff = min(_HTTP_BACKOFF_CAP, (_HTTP_BACKOFF_BASE**attempt))
            if attempt < _HTTP_MAX_RETRIES:
                if attempt < 3:
                    print(
                        f"Aikido API error for {method} {url} "
                        f"(attempt {attempt+1}/{_HTTP_MAX_RETRIES+1}): {e}; retrying in {backoff:.1f}s"
                    )
                time.sleep(backoff)
                continue
            break

    if last_resp is not None:
        last_resp.raise_for_status()
    raise last_exc or RuntimeError("Aikido API request failed")


def _cache_read(path: Path, *, ttl_seconds: int) -> Optional[Any]:
    if _NO_CACHE:
        return None
    try:
        st = path.stat()
    except FileNotFoundError:
        return None
    except Exception:
        return None

    if ttl_seconds > 0:
        age = time.time() - st.st_mtime
        if age > ttl_seconds:
            return None

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _cache_write(path: Path, obj: Any) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(obj), encoding="utf-8")
        os.replace(tmp, path)
    except Exception:
        return


def get_access_token(client_id: str, client_secret: str) -> str:
    basic = f"{client_id}:{client_secret}".encode("utf-8")
    headers = {
        "Authorization": "Basic " + base64.b64encode(basic).decode("ascii"),
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {"grant_type": "client_credentials"}
    payload = _request_json("POST", TOKEN_URL, headers=headers, data=data, timeout=30)
    return payload["access_token"]


def list_code_repos(
    token: str,
    *,
    cache_dir: Optional[str] = None,
    cache_ttl_seconds: Optional[int] = None,
) -> List[Dict[str, Any]]:
    url = f"{API_ROOT}/repositories/code"
    headers = {"Authorization": f"Bearer {token}"}

    ttl = _CACHE_TTL_SECS_DEFAULT if cache_ttl_seconds is None else int(cache_ttl_seconds)
    cache_path = Path(cache_dir) / "repositories.code.json" if cache_dir else None

    if cache_path is not None:
        cached = _cache_read(cache_path, ttl_seconds=ttl)
        if cached is not None:
            return cached.get("data", cached) if isinstance(cached, dict) else cached

    data = _request_json("GET", url, headers=headers, timeout=30)

    if cache_path is not None:
        _cache_write(cache_path, data)

    return data.get("data", data) if isinstance(data, dict) else data


def export_all_issues(
    token: str,
    *,
    cache_dir: Optional[str] = None,
    cache_ttl_seconds: Optional[int] = None,
) -> List[Dict[str, Any]]:
    url = f"{API_ROOT}/issues/export"
    headers = {"Authorization": f"Bearer {token}"}

    ttl = _CACHE_TTL_SECS_DEFAULT if cache_ttl_seconds is None else int(cache_ttl_seconds)
    cache_path = Path(cache_dir) / "issues.export.json" if cache_dir else None

    if cache_path is not None:
        cached = _cache_read(cache_path, ttl_seconds=ttl)
        if cached is not None:
            return cached.get("data", cached) if isinstance(cached, dict) else cached

    data = _request_json("GET", url, headers=headers, timeout=90)

    if cache_path is not None:
        _cache_write(cache_path, data)

    return data.get("data", data) if isinstance(data, dict) else data


def trigger_aikido_scan(token: str, code_repo_id: str) -> Optional[float]:
    headers = {"Authorization": f"Bearer {token}"}
    scan_url = f"{API_ROOT}/repositories/code/{code_repo_id}/scan"
    try:
        t0 = time.time()
        resp = requests.post(scan_url, headers=headers, timeout=30)
        if resp.status_code == 403:
            print("No permission to trigger scan; using latest existing results.")
            return None
        if resp.status_code == 429:
            ra = _parse_retry_after(resp.headers.get("Retry-After"))
            if ra:
                time.sleep(ra)
            return None
        resp.raise_for_status()
        return time.time() - t0
    except Exception as e:
        print(f"Warning: scan trigger failed: {e}")
        return None
