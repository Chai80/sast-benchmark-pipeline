# api/ingest.py

import json
import uuid
from pathlib import Path
from typing import List, Optional, Tuple

from .models import Scan, Finding


def ingest_normalized_scan(
    normalized_path: Path,
    metadata_path: Path,
    target_key: Optional[str] = None,
) -> Tuple[Scan, List[Finding]]:
    """
    Load one normalized JSON + its metadata.json and return:
    - a Scan object
    - a list of Finding objects

    No database, just in-memory objects.
    """

    # Load files
    with normalized_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    with metadata_path.open("r", encoding="utf-8") as f:
        meta = json.load(f)

    # Header info from normalized JSON
    tool = data["tool"]
    tool_version = data["tool_version"]
    target_repo = data["target_repo"]
    scan_header = data["scan"]

    # Runtime from metadata.json (fallback to 0.0 if missing)
    scan_time_seconds = float(meta.get("scan_time_seconds", 0.0))

    # Aggregate severities + build Finding objects
    findings_data = data.get("findings", [])
    high = medium = low = 0
    findings: List[Finding] = []

    # Generate one internal ID for this scan
    scan_id = str(uuid.uuid4())

    for f in findings_data:
        sev = f.get("severity")

        if sev == "HIGH":
            high += 1
        elif sev == "MEDIUM":
            medium += 1
        elif sev == "LOW":
            low += 1

        finding = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            finding_id=f["finding_id"],
            cwe_id=f.get("cwe_id"),
            rule_id=f["rule_id"],
            title=f["title"],
            severity=sev,
            file_path=f.get("file_path"),
            line_number=f.get("line_number"),
            end_line_number=f.get("end_line_number"),
            line_content=f.get("line_content"),
        )
        findings.append(finding)

    # Build the Scan object
    scan = Scan(
        id=scan_id,
        tool=tool,
        tool_version=tool_version,
        target_key=target_key,
        target_repo_name=target_repo["name"],
        target_repo_url=target_repo["url"],
        target_repo_commit=target_repo.get("commit"),
        target_repo_date=target_repo.get("commit_date"),
        run_id=scan_header["run_id"],
        scan_date=scan_header["scan_date"],
        command=scan_header["command"],
        scan_time_seconds=scan_time_seconds,
        total_findings=len(findings),
        high_count=high,
        medium_count=medium,
        low_count=low,
        status="success",
    )

    return scan, findings
