from dataclasses import dataclass
from typing import Optional


@dataclass
class Scan:
    """
    Represents a single SAST scan:
    - One tool (e.g. Semgrep, Snyk, Sonar, Aikido)
    - On one repository at one specific commit
    - Run at a specific time with a specific command
    """

    # -------- Identity / tool info --------

    id: str
    # Internal unique ID for this scan (we generate this, e.g. a UUID string).

    tool: str
    # Which scanner ran: "semgrep", "snyk", "sonar", or "aikido".

    tool_version: str
    # Exact version of the scanner (e.g. "1.1301.0") for reproducibility.

    # -------- Benchmark / target label --------

    target_key: Optional[str]
    # Optional short label for the benchmark target, e.g. "juice_shop".
    # Used for grouping scans in reports; can be None for ad-hoc repos.

    # -------- Repo / commit metadata --------

    target_repo_name: str
    # Short repo name, usually derived from the URL, e.g. "juice-shop".

    target_repo_url: str
    # Git URL that was scanned, e.g. "https://github.com/juice-shop/juice-shop.git".

    target_repo_commit: Optional[str]
    # Git commit SHA that was scanned. None if the commit is unknown.

    target_repo_date: Optional[str]
    # When that commit was authored, as an ISO 8601 string.
    # Example: "2025-11-26T11:38:38+01:00". None if not available.

    # -------- How this scan was run --------

    run_id: str
    # Run folder ID, e.g. "2025120201". Matches the directory under runs/<tool>/<repo>/.

    scan_date: str
    # When the normalized JSON was generated, as an ISO 8601 string.

    command: str
    # Full CLI command used to run the scanner (for debugging / reproducibility).

    # -------- Performance + issue counts --------

    scan_time_seconds: float
    # How long the tool reported the scan took, in seconds (from metadata.json).

    total_findings: int
    # Total number of normalized findings for this scan.

    high_count: int
    # Number of findings with severity HIGH.

    medium_count: int
    # Number of findings with severity MEDIUM.

    low_count: int
    # Number of findings with severity LOW.

    # -------- Lifecycle / status --------

    status: str
    # Current state of the scan:
    # - "queued"   → job created, not started yet
    # - "running"  → scanner currently running
    # - "success"  → finished and results ingested
    # - "failed"   → scan or ingestion failed


@dataclass
class Finding:
    """
    Represents one normalized issue (finding) produced by a scan.
    Each Finding is linked back to exactly one Scan.
    """

    # -------- Identity / linkage back to the scan --------

    id: str
    # Internal unique ID for this finding (we generate this, e.g. a UUID string).

    scan_id: str
    # ID of the Scan this finding belongs to (foreign key to Scan.id).

    finding_id: str
    # Deterministic ID within the scan, usually "<tool>:<rule_id>:<file_path>:<line>".
    # Unique per scan, useful for deduplicating and debugging.

    # -------- Security / rule information --------

    cwe_id: Optional[str]
    # CWE identifier if available, e.g. "CWE-89". None if not provided by the tool.

    rule_id: str
    # Scanner’s rule identifier, e.g. "javascript/Sqli".

    title: str
    # Human-readable description of the issue, e.g. "Unsanitized SQL query...".

    severity: Optional[str]
    # Normalized severity:
    # "HIGH", "MEDIUM", "LOW", or None if the tool’s severity could not be mapped.

    # -------- Where in the code this happens --------

    file_path: Optional[str]
    # Path to the file within the repo, e.g. "routes/search.ts".
    # None if the issue is not tied to a single file.

    line_number: Optional[int]
    # First line number of the issue (1-based). None if the precise line is unknown.

    end_line_number: Optional[int]
    # Last line number of the issue (1-based).
    # Often equal to line_number; None if unknown.

    line_content: Optional[str]
    # Source code at line_number (or a snippet around it).
    # Used for quick context in UIs/exports; None if we didn't capture it.
