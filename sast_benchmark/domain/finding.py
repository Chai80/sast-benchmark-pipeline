"""sast_benchmark.domain.finding

Canonical representation of a *normalized* finding.

This is intentionally **tool-agnostic**. Every tool normalizer should be able to
output findings that can be expressed using this structure.

Why dataclasses instead of untyped dicts?
----------------------------------------
The repository historically used plain ``dict`` objects that follow the schema
documented in :file:`normalized-schema.md`. That works, but it makes schema
drift easy:

* one tool starts emitting a new field name
* another tool omits a field
* downstream analysis silently produces wrong counts

Introducing an explicit domain type provides:

* a single source of truth for required fields
* a central place for light validation
* a predictable conversion boundary to/from JSON

This file is designed to be adopted incrementally. Existing code can continue
to read/write dicts; callers can opt into ``FindingNormalized.from_dict`` and
``FindingNormalized.to_dict`` when ready.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple


def _none_if_empty_str(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, str) and not v.strip():
        return None
    return v


def _safe_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    # bool is a subclass of int; treat as invalid.
    if isinstance(v, bool):
        return None
    try:
        return int(v)
    except Exception:
        return None


def _as_list_of_str(v: Any) -> List[str]:
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        return [str(x) for x in v if x is not None and str(x).strip()]
    return [str(v)] if str(v).strip() else []


@dataclass(frozen=True)
class OwaspTop10Block:
    """OWASP Top 10 block as used in the normalized schema."""

    codes: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "OwaspTop10Block":
        if not isinstance(d, Mapping):
            return cls()
        return cls(
            codes=_as_list_of_str(d.get("codes")),
            categories=_as_list_of_str(d.get("categories")),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "codes": list(self.codes or []),
            "categories": list(self.categories or []),
        }


@dataclass(frozen=True)
class FindingNormalized:
    """Tool-agnostic normalized finding.

    Fields follow :file:`normalized-schema.md`.
    """

    # ---- Identity ----
    finding_id: str

    # ---- Rule + message ----
    rule_id: Optional[str]
    title: Optional[str]
    severity: Optional[str] = None

    # ---- Location ----
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    end_line_number: Optional[int] = None
    line_content: Optional[str] = None

    # ---- Optional normalized classification ----
    issue_type: Optional[str] = None
    vuln_class: Optional[str] = None
    cwe_id: Optional[str] = None
    cwe_ids: List[str] = field(default_factory=list)

    owasp_top_10_2017: Optional[OwaspTop10Block] = None
    owasp_top_10_2021: Optional[OwaspTop10Block] = None
    owasp_top_10_2017_vendor: Optional[OwaspTop10Block] = None
    owasp_top_10_2017_canonical: Optional[OwaspTop10Block] = None
    owasp_top_10_2021_vendor: Optional[OwaspTop10Block] = None
    owasp_top_10_2021_canonical: Optional[OwaspTop10Block] = None

    # ---- Provenance / denormalized ----
    metadata: Optional[Dict[str, Any]] = None
    vendor: Optional[Dict[str, Any]] = None

    # ---- Forward-compat: store unknown keys here ----
    extra: Dict[str, Any] = field(default_factory=dict)

    # Required fields for a minimally useful normalized finding.
    REQUIRED_FIELDS: Tuple[str, ...] = (
        "finding_id",
        "rule_id",
        "title",
    )

    # Fields analysis frequently expects for SAST-style issues.
    RECOMMENDED_FIELDS: Tuple[str, ...] = (
        "file_path",
        "line_number",
        "severity",
    )

    @staticmethod
    def validate_dict(d: Mapping[str, Any]) -> List[str]:
        """Return a list of human-readable problems for this dict.

        This is intentionally lightweight: the pipeline often wants to continue
        running even if one tool output is malformed.
        """
        problems: List[str] = []
        if not isinstance(d, Mapping):
            return ["not_a_mapping"]
        for k in FindingNormalized.REQUIRED_FIELDS:
            if k not in d or d.get(k) in (None, ""):
                problems.append(f"missing:{k}")

        sev = d.get("severity")
        if sev not in (None, "", "HIGH", "MEDIUM", "LOW"):
            problems.append("invalid:severity")

        ln = d.get("line_number")
        if ln is not None and _safe_int(ln) is None:
            problems.append("invalid:line_number")

        eln = d.get("end_line_number")
        if eln is not None and _safe_int(eln) is None:
            problems.append("invalid:end_line_number")

        return problems

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "FindingNormalized":
        """Parse a dict (as emitted in normalized.json) into a dataclass."""
        if not isinstance(d, Mapping):
            raise TypeError(
                f"FindingNormalized.from_dict expected mapping, got {type(d)!r}"
            )

        known_keys = {
            "finding_id",
            "rule_id",
            "title",
            "severity",
            "file_path",
            "line_number",
            "end_line_number",
            "line_content",
            "issue_type",
            "vuln_class",
            "cwe_id",
            "cwe_ids",
            "owasp_top_10_2017",
            "owasp_top_10_2021",
            "owasp_top_10_2017_vendor",
            "owasp_top_10_2017_canonical",
            "owasp_top_10_2021_vendor",
            "owasp_top_10_2021_canonical",
            "metadata",
            "vendor",
        }

        extra = {k: v for k, v in d.items() if k not in known_keys}

        def _owasp_block(key: str) -> Optional[OwaspTop10Block]:
            raw = d.get(key)
            if raw is None:
                return None
            if isinstance(raw, Mapping):
                blk = OwaspTop10Block.from_dict(raw)
                # Treat empty block as None for cleanliness.
                if not blk.codes and not blk.categories:
                    return None
                return blk
            return None

        return cls(
            finding_id=str(d.get("finding_id") or ""),
            rule_id=_none_if_empty_str(d.get("rule_id")),
            title=_none_if_empty_str(d.get("title")),
            severity=_none_if_empty_str(d.get("severity")),
            file_path=_none_if_empty_str(d.get("file_path")),
            line_number=_safe_int(d.get("line_number")),
            end_line_number=_safe_int(d.get("end_line_number")),
            line_content=_none_if_empty_str(d.get("line_content")),
            issue_type=_none_if_empty_str(d.get("issue_type")),
            vuln_class=_none_if_empty_str(d.get("vuln_class")),
            cwe_id=_none_if_empty_str(d.get("cwe_id")),
            cwe_ids=_as_list_of_str(d.get("cwe_ids")),
            owasp_top_10_2017=_owasp_block("owasp_top_10_2017"),
            owasp_top_10_2021=_owasp_block("owasp_top_10_2021"),
            owasp_top_10_2017_vendor=_owasp_block("owasp_top_10_2017_vendor"),
            owasp_top_10_2017_canonical=_owasp_block("owasp_top_10_2017_canonical"),
            owasp_top_10_2021_vendor=_owasp_block("owasp_top_10_2021_vendor"),
            owasp_top_10_2021_canonical=_owasp_block("owasp_top_10_2021_canonical"),
            metadata=d.get("metadata") if isinstance(d.get("metadata"), dict) else None,
            vendor=d.get("vendor") if isinstance(d.get("vendor"), dict) else None,
            extra=extra,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a JSON-serializable dict (normalized schema keys)."""
        out: Dict[str, Any] = {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "end_line_number": self.end_line_number,
            "line_content": self.line_content,
        }

        # Optional classification.
        if self.issue_type is not None:
            out["issue_type"] = self.issue_type
        if self.vuln_class is not None:
            out["vuln_class"] = self.vuln_class
        if self.cwe_id is not None:
            out["cwe_id"] = self.cwe_id
        if self.cwe_ids:
            out["cwe_ids"] = list(self.cwe_ids)

        def _put_owasp(key: str, blk: Optional[OwaspTop10Block]) -> None:
            if blk is None:
                return
            if blk.codes or blk.categories:
                out[key] = blk.to_dict()

        _put_owasp("owasp_top_10_2017", self.owasp_top_10_2017)
        _put_owasp("owasp_top_10_2021", self.owasp_top_10_2021)
        _put_owasp("owasp_top_10_2017_vendor", self.owasp_top_10_2017_vendor)
        _put_owasp("owasp_top_10_2017_canonical", self.owasp_top_10_2017_canonical)
        _put_owasp("owasp_top_10_2021_vendor", self.owasp_top_10_2021_vendor)
        _put_owasp("owasp_top_10_2021_canonical", self.owasp_top_10_2021_canonical)

        if self.metadata is not None:
            out["metadata"] = self.metadata
        if self.vendor is not None:
            out["vendor"] = self.vendor

        # Forward-compat.
        out.update(self.extra or {})

        return out
