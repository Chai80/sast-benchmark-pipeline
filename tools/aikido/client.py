"""tools/aikido/client.py

Minimal Aikido Public API client helpers.
"""

from __future__ import annotations

import base64
import time
from typing import Any, Dict, List, Optional

import requests

TOKEN_URL = "https://app.aikido.dev/api/oauth/token"
API_ROOT = "https://app.aikido.dev/api/public/v1"
AIKIDO_TOOL_VERSION = "public-api-v1"


def get_access_token(client_id: str, client_secret: str) -> str:
    basic = f"{client_id}:{client_secret}".encode("utf-8")
    headers = {
        "Authorization": "Basic " + base64.b64encode(basic).decode("ascii"),
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {"grant_type": "client_credentials"}
    resp = requests.post(TOKEN_URL, headers=headers, data=data, timeout=30)
    resp.raise_for_status()
    payload = resp.json()
    return payload["access_token"]


def list_code_repos(token: str) -> List[Dict[str, Any]]:
    url = f"{API_ROOT}/repositories/code"
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return data["data"] if isinstance(data, dict) and "data" in data else data


def export_all_issues(token: str) -> List[Dict[str, Any]]:
    url = f"{API_ROOT}/issues/export"
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    return data["data"] if isinstance(data, dict) and "data" in data else data


def trigger_aikido_scan(token: str, code_repo_id: str) -> Optional[float]:
    headers = {"Authorization": f"Bearer {token}"}
    scan_url = f"{API_ROOT}/repositories/code/{code_repo_id}/scan"
    try:
        t0 = time.time()
        resp = requests.post(scan_url, headers=headers, timeout=30)
        if resp.status_code == 403:
            print("No permission to trigger scan; using latest existing results.")
            return None
        resp.raise_for_status()
        return time.time() - t0
    except Exception as e:
        print(f"Warning: scan trigger failed: {e}")
        return None
