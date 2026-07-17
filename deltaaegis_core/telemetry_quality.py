"""DeltaAegis v0.45 telemetry-trust decision, retention, and review runtime."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone
from typing import Any
import uuid


POLICY_SCHEMA_VERSION = "deltaaegis-telemetry-quality-policy-v1"
DECISION_SCHEMA_VERSION = "deltaaegis-telemetry-quality-decision-v1"
POLICY_VERSION = "deltaaegis-v0.45-stage0f"
CAPABILITY_SCHEMA_VERSION = "netsniper-capability-manifest-v1"
HOST_CLASSIFICATION_SCHEMA_VERSION = "netsniper-host-classification-v2"
CLASSIFIER_VERSION = "netsniper-classifier-v2"
STATE_PRECEDENCE = {
    "ACCEPTED": 0,
    "DEGRADED": 1,
    "QUARANTINED": 2,
    "REJECTED": 3,
}
ALLOWED_TRANSITIONS = {
    ("ACCEPTED", "QUARANTINED"),
    ("DEGRADED", "ACCEPTED"),
    ("DEGRADED", "QUARANTINED"),
    ("QUARANTINED", "DEGRADED"),
    ("QUARANTINED", "ACCEPTED"),
}
REQUIRED_COLLECTORS = {"discovery", "tcp_services"}
PUBLIC_DECISION_KEYS = (
    "schema_version",
    "policy_version",
    "bundle_id",
    "bundle_sha256",
    "source_contract",
    "automated_state",
    "current_state",
    "reasons",
    "effects",
    "retention_disposition",
    "review",
    "evaluated_at",
)
PUBLIC_REASON_KEYS = (
    "code",
    "severity",
    "scope",
    "detail",
    "overridable",
)
PUBLIC_REVIEW_KEYS = (
    "status",
    "reviewer",
    "reviewed_at",
    "override_from",
    "override_to",
    "override_reason",
)
REASON_SCOPE_BY_CODE = {
    "bundle_unreadable": "bundle",
    "manifest_missing": "bundle",
    "schema_unrecognized": "bundle",
    "scope_unauthorized": "bundle",
    "run_id_hash_conflict": "bundle",
    "complete_v2_1_contract": "bundle",
    "full_inventory_preserved": "bundle",
    "integrity_verified": "bundle",
    "scope_authorized": "bundle",
    "legacy_v2_compatibility": "bundle",
    "partial_scan": "bundle",
    "unprivileged_scan": "bundle",
    "host_inventory_not_preserved": "bundle",
    "omitted_hosts_reported": "bundle",
    "capability_manifest_inconsistent": "bundle",
    "identity_collision": "host",
    "classification_contract_invalid": "host",
    "classification_review_present": "host",
    "classification_unknown_present": "host",
    "unsupported_classifier_version": "host",
    "collector_failed": "collector",
    "collector_unavailable": "collector",
    "required_collector_failed": "collector",
    "optional_artifact_missing": "artifact",
    "required_artifact_missing": "artifact",
    "required_artifact_invalid": "artifact",
    "path_escape": "artifact",
    "hash_mismatch": "artifact",
    "malformed_inventory_counts": "artifact",
    "negative_evidence_disabled": "policy",
    "manual_review_required": "policy",
}
QUALITY_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS telemetry_quality_decisions (
    decision_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    bundle_digest TEXT NOT NULL,
    manifest_path TEXT NOT NULL,
    retained_manifest_path TEXT NOT NULL DEFAULT '',
    network_scope TEXT NOT NULL DEFAULT '',
    scanner_version TEXT NOT NULL DEFAULT '',
    automated_state TEXT NOT NULL,
    current_state TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    decision_schema_version TEXT NOT NULL,
    reason_codes_json TEXT NOT NULL DEFAULT '[]',
    reasons_json TEXT NOT NULL DEFAULT '[]',
    allowed_effects_json TEXT NOT NULL DEFAULT '[]',
    blocked_effects_json TEXT NOT NULL DEFAULT '[]',
    effect_policy_json TEXT NOT NULL DEFAULT '{}',
    coverage_json TEXT NOT NULL DEFAULT '{}',
    source_contract_json TEXT NOT NULL DEFAULT '{}',
    retention_disposition TEXT NOT NULL,
    evaluated_at TEXT NOT NULL,
    imported_at TEXT,
    import_status TEXT NOT NULL DEFAULT 'PENDING',
    review_required INTEGER NOT NULL DEFAULT 0,
    UNIQUE(run_id, bundle_digest)
);

CREATE INDEX IF NOT EXISTS idx_telemetry_quality_run
    ON telemetry_quality_decisions(run_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_quality_state
    ON telemetry_quality_decisions(current_state, evaluated_at);
CREATE INDEX IF NOT EXISTS idx_telemetry_quality_scope
    ON telemetry_quality_decisions(network_scope, evaluated_at);

CREATE TABLE IF NOT EXISTS telemetry_quality_reviews (
    review_id TEXT PRIMARY KEY,
    decision_id TEXT NOT NULL,
    action TEXT NOT NULL,
    prior_state TEXT NOT NULL,
    resulting_state TEXT NOT NULL,
    reason TEXT NOT NULL,
    actor_user_id TEXT,
    actor_username TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    actor_auth_type TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(decision_id)
        REFERENCES telemetry_quality_decisions(decision_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_telemetry_quality_reviews_decision
    ON telemetry_quality_reviews(decision_id, created_at);
"""


class TelemetryQualityError(RuntimeError):
    """Raised for fail-closed telemetry-quality operations."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def json_object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def json_array(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def receipt_bundle_digest(manifest_path: Path) -> str:
    """Hash unsafe or incomplete bundle content without following symlinks."""

    manifest_path = manifest_path.expanduser()
    root = manifest_path.parent
    digest = hashlib.sha256()
    digest.update(b"deltaaegis-rejection-receipt-v1\0")

    if not root.is_dir():
        digest.update(str(manifest_path).encode("utf-8", errors="surrogateescape"))
        return digest.hexdigest()

    for current_root, directory_names, file_names in os.walk(
        root,
        topdown=True,
        followlinks=False,
    ):
        directory_names.sort()
        file_names.sort()
        current = Path(current_root)
        for name in [*directory_names, *file_names]:
            path = current / name
            try:
                relative = path.relative_to(root)
                metadata = path.lstat()
            except (OSError, ValueError):
                continue
            digest.update(
                str(relative).replace("\\", "/").encode(
                    "utf-8",
                    errors="surrogateescape",
                )
            )
            digest.update(b"\0")
            digest.update(str(metadata.st_mode).encode("ascii"))
            digest.update(b"\0")
            if path.is_symlink():
                digest.update(b"L\0")
                try:
                    target = os.readlink(path)
                except OSError:
                    target = "<unreadable>"
                digest.update(
                    target.encode("utf-8", errors="surrogateescape")
                )
            elif path.is_file():
                digest.update(b"F\0")
                try:
                    with path.open("rb") as handle:
                        for block in iter(
                            lambda: handle.read(1024 * 1024),
                            b"",
                        ):
                            digest.update(block)
                except OSError:
                    digest.update(b"<unreadable>")
            else:
                digest.update(b"D\0")
            digest.update(b"\0")
    return digest.hexdigest()

def bundle_digest(manifest_path: Path) -> str:
    bundle_root = manifest_path.resolve().parent
    digest = hashlib.sha256()
    members = sorted(bundle_root.rglob("*"))
    for item in members:
        if item.is_symlink():
            raise TelemetryQualityError(
                f"bundle contains a symbolic link: {item}"
            )
    for path in (item for item in members if item.is_file()):
        resolved = path.resolve()
        try:
            relative = resolved.relative_to(bundle_root)
        except ValueError as exc:
            raise TelemetryQualityError(
                f"bundle member escapes run root: {path}"
            ) from exc
        digest.update(str(relative).replace("\\", "/").encode("utf-8"))
        digest.update(b"\0")
        with resolved.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        digest.update(b"\0")
    return digest.hexdigest()


def canonical_scope(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        raise TelemetryQualityError("telemetry target scope is missing")
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise TelemetryQualityError(
            f"telemetry target scope is invalid: {text!r}"
        ) from exc
    if not network.is_private:
        raise TelemetryQualityError(
            f"telemetry target scope is not private: {network}"
        )
    return str(network)


def confined_path(bundle_root: Path, value: Any) -> Path:
    raw = str(value or "").strip()
    if not raw:
        raise TelemetryQualityError("bundle artifact path is empty")
    candidate = (bundle_root / raw).resolve()
    try:
        candidate.relative_to(bundle_root.resolve())
    except ValueError as exc:
        raise TelemetryQualityError(
            f"bundle artifact path escapes run root: {raw!r}"
        ) from exc
    return candidate


def load_policy(policy_path: Path) -> dict[str, Any]:
    policy = read_json(policy_path)
    if not isinstance(policy, dict):
        raise TelemetryQualityError("telemetry-quality policy is not a JSON object")
    if policy.get("schema_version") != POLICY_SCHEMA_VERSION:
        raise TelemetryQualityError(
            "unsupported telemetry-quality policy schema: "
            f"{policy.get('schema_version')!r}"
        )
    return policy


def effects_for_state(policy: dict[str, Any], state: str) -> tuple[dict[str, Any], list[str], list[str], str]:
    state_record = json_object(json_object(policy.get("states")).get(state))
    effects = json_object(state_record.get("effects"))
    allowed: list[str] = []
    blocked: list[str] = []
    for name, rule in sorted(effects.items()):
        if str(rule).lower() in {"blocked", "receipt_only"}:
            blocked.append(name)
        else:
            allowed.append(name)
    return effects, allowed, blocked, str(
        state_record.get("retention_disposition") or "audit_metadata_only"
    )


def _reason_map(policy: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("code")): item
        for item in json_array(policy.get("reason_catalog"))
        if isinstance(item, dict) and item.get("code")
    }


def _add_reason(
    reason_codes: list[str],
    reason_details: list[dict[str, Any]],
    policy_reasons: dict[str, dict[str, Any]],
    code: str,
    detail: str | None = None,
) -> None:
    if code in reason_codes:
        return
    catalog = dict(policy_reasons.get(code) or {})
    description = str(
        detail or catalog.get("description") or code
    ).strip()
    reason_codes.append(code)
    reason_details.append(
        {
            "code": code,
            "severity": catalog.get("severity", "warning"),
            "scope": REASON_SCOPE_BY_CODE.get(code, "policy"),
            "detail": description,
            "minimum_state": catalog.get("minimum_state", "DEGRADED"),
            "overridable": bool(catalog.get("overridable", False)),
            # Kept internally for compatibility with the legacy summary text.
            "description": description,
        }
    )


def _most_restrictive_state(
    base_state: str,
    reason_details: list[dict[str, Any]],
) -> str:
    state = base_state
    for item in reason_details:
        candidate = str(item.get("minimum_state") or "DEGRADED").upper()
        if STATE_PRECEDENCE.get(candidate, 3) > STATE_PRECEDENCE.get(state, 3):
            state = candidate
    return state


def _manifest_contract(manifest: dict[str, Any]) -> tuple[str, dict[str, Any], bool]:
    schema = str(manifest.get("schema_version") or "").strip()
    contracts = json_object(manifest.get("contracts"))
    is_v21 = (
        contracts.get("capability_manifest_version") == CAPABILITY_SCHEMA_VERSION
        and contracts.get("host_classification_version")
        == HOST_CLASSIFICATION_SCHEMA_VERSION
    )
    return schema, contracts, is_v21


def _classification_decision(record: dict[str, Any]) -> str:
    family = json_object(record.get("device_family"))
    legacy = json_object(record.get("legacy_projection"))
    return str(
        family.get("decision")
        or legacy.get("decision")
        or ""
    ).strip().lower()


def _stable_identity_values(records: list[dict[str, Any]]) -> dict[tuple[str, str], set[str]]:
    values: dict[tuple[str, str], set[str]] = {}
    for record in records:
        host_id = str(record.get("host_id") or "").strip()
        identity = json_object(record.get("identity"))
        for key in json_array(identity.get("observed_keys")):
            if not isinstance(key, dict) or not key.get("stable"):
                continue
            kind = str(key.get("kind") or "").strip().lower()
            value = str(key.get("value") or "").strip().lower()
            if kind and value:
                values.setdefault((kind, value), set()).add(host_id)
    return values


def _public_reason(item: Any) -> dict[str, Any]:
    source = item if isinstance(item, dict) else {}
    code = str(source.get("code") or "manual_review_required").strip()
    detail = str(
        source.get("detail")
        or source.get("description")
        or code
    ).strip()
    scope = str(
        source.get("scope")
        or REASON_SCOPE_BY_CODE.get(code, "policy")
    ).strip().lower()
    if scope not in {"bundle", "artifact", "collector", "host", "policy"}:
        scope = "policy"
    severity = str(source.get("severity") or "warning").strip().lower()
    if severity not in {"info", "warning", "error", "critical"}:
        severity = "warning"
    return {
        "code": code,
        "severity": severity,
        "scope": scope,
        "detail": detail,
        "overridable": bool(source.get("overridable", False)),
    }


def _public_review(
    decision: dict[str, Any],
    review: dict[str, Any] | None = None,
) -> dict[str, Any]:
    source = review if isinstance(review, dict) else {}
    action = str(source.get("action") or "").strip().upper()
    if source:
        status = "overridden" if action == "OVERRIDE" else "reviewed"
        reviewer = str(source.get("actor_username") or "").strip() or None
        reviewed_at = str(source.get("created_at") or "").strip() or None
        override_from = (
            str(source.get("prior_state") or "").strip().upper() or None
            if action == "OVERRIDE"
            else None
        )
        override_to = (
            str(source.get("resulting_state") or "").strip().upper() or None
            if action == "OVERRIDE"
            else None
        )
        override_reason = (
            str(source.get("reason") or "").strip() or None
            if action == "OVERRIDE"
            else None
        )
    else:
        status = (
            "overridden"
            if str(decision.get("current_state") or "").upper()
            != str(decision.get("automated_state") or "").upper()
            else "not_reviewed"
        )
        reviewer = None
        reviewed_at = None
        override_from = None
        override_to = None
        override_reason = None
    return {
        "status": status,
        "reviewer": reviewer,
        "reviewed_at": reviewed_at,
        "override_from": override_from,
        "override_to": override_to,
        "override_reason": override_reason,
    }


def decision_contract_payload(
    decision: dict[str, Any],
    review: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the exact public v1 decision-schema object.

    Internal ledger identifiers, retained paths, projection metadata, and
    coverage details deliberately remain outside this contract because the
    approved schema disallows additional top-level properties.
    """

    source = decision if isinstance(decision, dict) else {}
    digest = str(
        source.get("bundle_sha256")
        or source.get("bundle_digest")
        or ""
    ).strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        digest = hashlib.sha256(
            str(source.get("manifest_path") or "unreadable-bundle").encode(
                "utf-8"
            )
        ).hexdigest()
    source_contract = json_object(source.get("source_contract"))
    reasons = [
        _public_reason(item)
        for item in json_array(source.get("reasons"))
    ]
    if not reasons:
        reasons = [
            {
                "code": "manual_review_required",
                "severity": "warning",
                "scope": "policy",
                "detail": "No telemetry-quality reason was recorded.",
                "overridable": True,
            }
        ]
    effects = json_object(
        source.get("effects")
        or source.get("effect_policy")
    )
    payload = {
        "schema_version": DECISION_SCHEMA_VERSION,
        "policy_version": str(
            source.get("policy_version") or POLICY_VERSION
        ),
        "bundle_id": str(
            source.get("bundle_id")
            or source.get("run_id")
            or "unknown-bundle"
        ),
        "bundle_sha256": digest,
        "source_contract": {
            "bundle_schema_version": str(
                source_contract.get("bundle_schema_version") or "unknown"
            ),
            "capability_manifest_version": source_contract.get(
                "capability_manifest_version"
            ),
            "host_classification_version": source_contract.get(
                "host_classification_version"
            ),
            "netsniper_version": str(
                source_contract.get("netsniper_version")
                or source.get("scanner_version")
                or "unknown"
            ),
        },
        "automated_state": str(
            source.get("automated_state") or "REJECTED"
        ).upper(),
        "current_state": str(
            source.get("current_state")
            or source.get("automated_state")
            or "REJECTED"
        ).upper(),
        "reasons": reasons,
        "effects": effects,
        "retention_disposition": str(
            source.get("retention_disposition")
            or "audit_metadata_only"
        ),
        "review": _public_review(source, review),
        "evaluated_at": str(source.get("evaluated_at") or utc_now()),
    }
    return {key: payload[key] for key in PUBLIC_DECISION_KEYS}


def evaluate_bundle(
    manifest_path: Path,
    *,
    policy_path: Path,
    authorized_scope: str | None = None,
) -> dict[str, Any]:
    """Evaluate a bundle and return the exact public decision-schema object."""

    record = evaluate_bundle_record(
        manifest_path,
        policy_path=policy_path,
        authorized_scope=authorized_scope,
    )
    return decision_contract_payload(record)
def evaluate_bundle_record(
    manifest_path: Path,
    *,
    policy_path: Path,
    authorized_scope: str | None = None,
) -> dict[str, Any]:
    """Return the internal immutable ledger record for one finalized bundle."""

    manifest_path = manifest_path.expanduser().resolve()
    policy = load_policy(policy_path)
    reason_catalog = _reason_map(policy)
    reason_codes: list[str] = []
    reasons: list[dict[str, Any]] = []
    evaluated_at = utc_now()
    run_id = manifest_path.parent.name
    digest = receipt_bundle_digest(manifest_path)
    manifest: dict[str, Any] = {}
    scope = ""
    scanner_version = ""
    source_contract: dict[str, Any] = {}
    coverage: dict[str, Any] = {
        "full_inventory": False,
        "negative_evidence_allowed": False,
        "requested_collectors": [],
        "completed_collectors": [],
        "failed_collectors": [],
        "unavailable_collectors": [],
    }

    if not manifest_path.is_file():
        _add_reason(reason_codes, reasons, reason_catalog, "manifest_missing")
        base_state = "REJECTED"
    else:
        try:
            digest = bundle_digest(manifest_path)
            raw_manifest = read_json(manifest_path)
            if not isinstance(raw_manifest, dict):
                raise ValueError("outer manifest is not a JSON object")
            manifest = raw_manifest
        except (OSError, ValueError, json.JSONDecodeError, TelemetryQualityError) as exc:
            _add_reason(
                reason_codes,
                reasons,
                reason_catalog,
                "bundle_unreadable",
                str(exc),
            )
            base_state = "REJECTED"
        else:
            run_id = str(manifest.get("scan_id") or run_id).strip() or run_id
            scanner_version = str(manifest.get("scanner_version") or "").strip()
            schema, contracts, is_v21 = _manifest_contract(manifest)
            source_contract = {
                "bundle_schema_version": schema,
                "capability_manifest_version": contracts.get(
                    "capability_manifest_version"
                ),
                "host_classification_version": contracts.get(
                    "host_classification_version"
                ),
                "classifier_version": contracts.get("classifier_version"),
                "taxonomy_version": contracts.get("taxonomy_version"),
                "evidence_profile_version": contracts.get(
                    "evidence_profile_version"
                ),
                "netsniper_version": scanner_version,
            }
            if schema not in {
                "netsniper-run-v1",
                "netsniper-run-v2",
                "netsniper-run-v3",
            }:
                _add_reason(
                    reason_codes,
                    reasons,
                    reason_catalog,
                    "schema_unrecognized",
                )
                base_state = "REJECTED"
            elif is_v21:
                _add_reason(
                    reason_codes,
                    reasons,
                    reason_catalog,
                    "complete_v2_1_contract",
                )
                base_state = "ACCEPTED"
            else:
                _add_reason(
                    reason_codes,
                    reasons,
                    reason_catalog,
                    "legacy_v2_compatibility",
                )
                base_state = "DEGRADED"

            raw_scope = (
                manifest.get("network_scope")
                or manifest.get("target")
                or json_object(manifest.get("quality")).get("network_scope")
            )
            try:
                scope = canonical_scope(raw_scope)
                if authorized_scope is not None:
                    if scope != canonical_scope(authorized_scope):
                        raise TelemetryQualityError(
                            f"bundle scope {scope} does not match authorized "
                            f"scope {authorized_scope}"
                        )
                _add_reason(
                    reason_codes,
                    reasons,
                    reason_catalog,
                    "scope_authorized",
                )
            except TelemetryQualityError as exc:
                _add_reason(
                    reason_codes,
                    reasons,
                    reason_catalog,
                    "scope_unauthorized",
                    str(exc),
                )

            files = json_object(manifest.get("files"))
            bundle_root = manifest_path.parent.resolve()
            resolved_files: dict[str, Path] = {}
            for key, value in sorted(files.items()):
                if not isinstance(value, str) or not value.strip():
                    continue
                try:
                    resolved_files[key] = confined_path(bundle_root, value)
                except TelemetryQualityError as exc:
                    _add_reason(
                        reason_codes,
                        reasons,
                        reason_catalog,
                        "path_escape",
                        str(exc),
                    )

            if is_v21:
                capability_path = resolved_files.get("capability_manifest_json")
                host_path = resolved_files.get("host_classifications_json")
                capability: dict[str, Any] = {}
                host_records: list[dict[str, Any]] = []

                if capability_path is None or not capability_path.is_file():
                    _add_reason(
                        reason_codes,
                        reasons,
                        reason_catalog,
                        "required_artifact_missing",
                        "capability_manifest.json is required for NetSniper v2.1",
                    )
                else:
                    try:
                        value = read_json(capability_path)
                        if not isinstance(value, dict):
                            raise ValueError(
                                "capability manifest is not a JSON object"
                            )
                        capability = value
                    except (OSError, ValueError, json.JSONDecodeError) as exc:
                        _add_reason(
                            reason_codes,
                            reasons,
                            reason_catalog,
                            "required_artifact_invalid",
                            str(exc),
                        )

                if capability:
                    if capability.get("schema_version") != CAPABILITY_SCHEMA_VERSION:
                        _add_reason(
                            reason_codes,
                            reasons,
                            reason_catalog,
                            "capability_manifest_inconsistent",
                            "capability manifest schema version is unsupported",
                        )

                    target = json_object(capability.get("target"))
                    try:
                        capability_scope = canonical_scope(
                            target.get("normalized_scope")
                            or target.get("requested_scope")
                        )
                        if scope and capability_scope != scope:
                            raise TelemetryQualityError(
                                "capability target scope contradicts outer manifest"
                            )
                    except TelemetryQualityError as exc:
                        _add_reason(
                            reason_codes,
                            reasons,
                            reason_catalog,
                            "capability_manifest_inconsistent",
                            str(exc),
                        )

                    artifacts = [
                        item
                        for item in json_array(capability.get("artifacts"))
                        if isinstance(item, dict)
                    ]
                    for artifact in artifacts:
                        artifact_path = artifact.get("path")
                        required = bool(artifact.get("required"))
                        try:
                            path = confined_path(bundle_root, artifact_path)
                        except TelemetryQualityError as exc:
                            _add_reason(
                                reason_codes,
                                reasons,
                                reason_catalog,
                                "path_escape",
                                str(exc),
                            )
                            continue
                        if not path.is_file():
                            _add_reason(
                                reason_codes,
                                reasons,
                                reason_catalog,
                                (
                                    "required_artifact_missing"
                                    if required
                                    else "optional_artifact_missing"
                                ),
                                f"artifact is absent: {artifact_path}",
                            )
                            continue
                        expected_size = artifact.get("size_bytes")
                        if (
                            isinstance(expected_size, int)
                            and expected_size >= 0
                            and path.stat().st_size != expected_size
                        ):
                            _add_reason(
                                reason_codes,
                                reasons,
                                reason_catalog,
                                "hash_mismatch",
                                f"artifact size does not match: {artifact_path}",
                            )
                        expected_hash = str(artifact.get("sha256") or "").lower()
                        if expected_hash and sha256_file(path) != expected_hash:
                            _add_reason(
                                reason_codes,
                                reasons,
                                reason_catalog,
                                "hash_mismatch",
                                f"artifact hash does not match: {artifact_path}",
                            )

                    integrity = json_object(capability.get("integrity"))
                    inventory = json_object(capability.get("inventory"))
                    discovered = inventory.get("discovered_host_count")
                    emitted = inventory.get("emitted_host_count")
                    omitted = inventory.get("omitted_host_count")
                    if not all(
                        isinstance(value, int) and value >= 0
                        for value in (discovered, emitted, omitted)
                    ):
                        _add_reason(
                            reason_codes,
                            reasons,
                            reason_catalog,
                            "malformed_inventory_counts",
                        )
                    else:
                        coverage["discovered_host_count"] = discovered
                        coverage["emitted_host_count"] = emitted
                        coverage["omitted_host_count"] = omitted
                        if omitted > 0:
                            _add_reason(
                                reason_codes,
                                reasons,
                                reason_catalog,
                                "omitted_hosts_reported",
                            )
                        if discovered != emitted + omitted:
                            _add_reason(
                                reason_codes,
                                reasons,
                                reason_catalog,
                                "capability_manifest_inconsistent",
                                "inventory counts are internally inconsistent",
                            )

                    full_inventory = bool(
                        integrity.get("host_inventory_preserved")
                    )
                    coverage["full_inventory"] = full_inventory
                    if full_inventory:
                        _add_reason(
                            reason_codes,
                            reasons,
                            reason_catalog,
                            "full_inventory_preserved",
                        )
                    else:
                        _add_reason(
                            reason_codes,
                            reasons,
                            reason_catalog,
                            "host_inventory_not_preserved",
                        )

                    if (
                        integrity.get("bundle_finalized")
                        and integrity.get("hashes_verified")
                        and integrity.get("manifest_complete")
                    ):
                        _add_reason(
                            reason_codes,
                            reasons,
                            reason_catalog,
                            "integrity_verified",
                        )
                    elif integrity.get("hashes_verified") is False:
                        _add_reason(
                            reason_codes,
                            reasons,
                            reason_catalog,
                            "hash_mismatch",
                            "capability manifest reports failed hash verification",
                        )
                    else:
                        _add_reason(
                            reason_codes,
                            reasons,
                            reason_catalog,
                            "capability_manifest_inconsistent",
                            "bundle finalization or manifest completeness is false",
                        )

                    execution = json_object(capability.get("execution"))
                    status = str(execution.get("status") or "").lower()
                    if status == "partial":
                        _add_reason(
                            reason_codes,
                            reasons,
                            reason_catalog,
                            "partial_scan",
                        )
                    elif status not in {"complete", ""}:
                        _add_reason(
                            reason_codes,
                            reasons,
                            reason_catalog,
                            "required_collector_failed",
                            f"capability execution status is {status!r}",
                        )
                    if str(execution.get("privilege_context") or "").lower() in {
                        "unprivileged",
                        "limited",
                    }:
                        _add_reason(
                            reason_codes,
                            reasons,
                            reason_catalog,
                            "unprivileged_scan",
                        )

                    for collector in json_array(capability.get("collectors")):
                        if not isinstance(collector, dict) or not collector.get(
                            "requested"
                        ):
                            continue
                        collector_id = str(
                            collector.get("collector_id") or ""
                        ).strip()
                        collector_status = str(
                            collector.get("status") or ""
                        ).strip().lower()
                        coverage["requested_collectors"].append(collector_id)
                        if collector_status == "completed":
                            coverage["completed_collectors"].append(collector_id)
                        elif collector_status in {"failed", "error"}:
                            coverage["failed_collectors"].append(collector_id)
                            _add_reason(
                                reason_codes,
                                reasons,
                                reason_catalog,
                                (
                                    "required_collector_failed"
                                    if collector_id in REQUIRED_COLLECTORS
                                    else "collector_failed"
                                ),
                                f"collector {collector_id} reported {collector_status}",
                            )
                        else:
                            coverage["unavailable_collectors"].append(collector_id)
                            _add_reason(
                                reason_codes,
                                reasons,
                                reason_catalog,
                                "collector_unavailable",
                                f"collector {collector_id} reported {collector_status}",
                            )

                if host_path is None or not host_path.is_file():
                    _add_reason(
                        reason_codes,
                        reasons,
                        reason_catalog,
                        "required_artifact_missing",
                        "host_classifications.json is required for NetSniper v2.1",
                    )
                else:
                    try:
                        value = read_json(host_path)
                        if not isinstance(value, list):
                            raise ValueError(
                                "host classification artifact is not an array"
                            )
                        host_records = [
                            item for item in value if isinstance(item, dict)
                        ]
                        if len(host_records) != len(value):
                            raise ValueError(
                                "host classification artifact contains non-object rows"
                            )
                    except (OSError, ValueError, json.JSONDecodeError) as exc:
                        _add_reason(
                            reason_codes,
                            reasons,
                            reason_catalog,
                            "required_artifact_invalid",
                            str(exc),
                        )

                negative_allowed = bool(host_records)
                for record in host_records:
                    if (
                        record.get("schema_version")
                        != HOST_CLASSIFICATION_SCHEMA_VERSION
                    ):
                        _add_reason(
                            reason_codes,
                            reasons,
                            reason_catalog,
                            "classification_contract_invalid",
                            "host classification schema version is unsupported",
                        )
                    if record.get("classifier_version") != CLASSIFIER_VERSION:
                        _add_reason(
                            reason_codes,
                            reasons,
                            reason_catalog,
                            "unsupported_classifier_version",
                        )
                    observation = json_object(record.get("observation_quality"))
                    if observation.get("inventory_complete") is False:
                        _add_reason(
                            reason_codes,
                            reasons,
                            reason_catalog,
                            "host_inventory_not_preserved",
                        )
                    if observation.get("negative_evidence_allowed") is not True:
                        negative_allowed = False
                        _add_reason(
                            reason_codes,
                            reasons,
                            reason_catalog,
                            "negative_evidence_disabled",
                        )
                    if str(
                        observation.get("scan_completeness") or ""
                    ).lower() == "partial":
                        _add_reason(
                            reason_codes,
                            reasons,
                            reason_catalog,
                            "partial_scan",
                        )
                    if json_array(observation.get("failed_collectors")):
                        _add_reason(
                            reason_codes,
                            reasons,
                            reason_catalog,
                            "collector_failed",
                        )
                    if json_array(observation.get("unavailable_collectors")):
                        _add_reason(
                            reason_codes,
                            reasons,
                            reason_catalog,
                            "collector_unavailable",
                        )
                    decision = _classification_decision(record)
                    if decision in {"review", "possible", "ambiguous"}:
                        _add_reason(
                            reason_codes,
                            reasons,
                            reason_catalog,
                            "classification_review_present",
                        )
                    elif decision in {"unknown", ""}:
                        _add_reason(
                            reason_codes,
                            reasons,
                            reason_catalog,
                            "classification_unknown_present",
                        )

                coverage["negative_evidence_allowed"] = (
                    coverage.get("full_inventory", False)
                    and negative_allowed
                    and not coverage["failed_collectors"]
                    and not coverage["unavailable_collectors"]
                )
                if not coverage["negative_evidence_allowed"]:
                    _add_reason(
                        reason_codes,
                        reasons,
                        reason_catalog,
                        "negative_evidence_disabled",
                    )

                for identity, host_ids in _stable_identity_values(
                    host_records
                ).items():
                    if len(host_ids) > 1:
                        _add_reason(
                            reason_codes,
                            reasons,
                            reason_catalog,
                            "identity_collision",
                            "stable identity "
                            f"{identity[0]}:{identity[1]} is shared by "
                            f"{len(host_ids)} hosts",
                        )

    final_state = _most_restrictive_state(base_state, reasons)
    effects, allowed, blocked, retention = effects_for_state(
        policy, final_state
    )
    digest_for_id = digest or hashlib.sha256(
        str(manifest_path).encode("utf-8")
    ).hexdigest()
    decision_id = hashlib.sha256(
        (
            f"{run_id}|{digest_for_id}|{POLICY_VERSION}|"
            f"{DECISION_SCHEMA_VERSION}"
        ).encode("utf-8")
    ).hexdigest()

    return {
        "schema_version": DECISION_SCHEMA_VERSION,
        "decision_id": decision_id,
        "run_id": run_id,
        "bundle_digest": digest,
        "manifest_path": str(manifest_path),
        "network_scope": scope,
        "scanner_version": scanner_version,
        "automated_state": final_state,
        "current_state": final_state,
        "policy_version": str(policy.get("policy_version") or POLICY_VERSION),
        "reason_codes": reason_codes,
        "reasons": reasons,
        "allowed_effects": allowed,
        "blocked_effects": blocked,
        "effect_policy": effects,
        "coverage_capabilities": coverage,
        "source_contract": source_contract,
        "retention_disposition": retention,
        "evaluated_at": evaluated_at,
        "review_required": final_state in {"DEGRADED", "QUARANTINED"},
    }


def ensure_column(
    connection: sqlite3.Connection,
    table: str,
    column: str,
    declaration: str,
) -> None:
    existing = {
        str(row[1])
        for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
    }
    if column not in existing:
        connection.execute(
            f"ALTER TABLE {table} ADD COLUMN {declaration}"
        )


def ensure_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(QUALITY_TABLE_SQL)
    ensure_column(
        connection,
        "snapshots",
        "quality_decision_id",
        "quality_decision_id TEXT",
    )
    ensure_column(
        connection,
        "snapshots",
        "automated_quality_state",
        "automated_quality_state TEXT",
    )
    ensure_column(
        connection,
        "snapshots",
        "current_quality_state",
        "current_quality_state TEXT",
    )
    ensure_column(
        connection,
        "snapshots",
        "bundle_digest",
        "bundle_digest TEXT NOT NULL DEFAULT ''",
    )
    ensure_column(
        connection,
        "snapshots",
        "evidence_retention_path",
        "evidence_retention_path TEXT NOT NULL DEFAULT ''",
    )
    ensure_column(
        connection,
        "snapshots",
        "quality_effects_json",
        "quality_effects_json TEXT NOT NULL DEFAULT '{}'",
    )
    ensure_column(
        connection,
        "snapshots",
        "quality_reasons_json",
        "quality_reasons_json TEXT NOT NULL DEFAULT '[]'",
    )
    ensure_column(
        connection,
        "snapshots",
        "negative_evidence_allowed",
        "negative_evidence_allowed INTEGER NOT NULL DEFAULT 0",
    )


def apply_run_id_conflict(
    connection: sqlite3.Connection,
    decision: dict[str, Any],
    *,
    policy_path: Path,
) -> dict[str, Any]:
    """Reject a run identifier that is already bound to different content."""

    ensure_schema(connection)
    run_id = str(decision.get("run_id") or "")
    digest = str(decision.get("bundle_digest") or "")
    conflict = False

    rows = connection.execute(
        "SELECT bundle_digest FROM telemetry_quality_decisions "
        "WHERE run_id = ?",
        (run_id,),
    ).fetchall()
    ledger_digests = {
        str(row["bundle_digest"] if hasattr(row, "keys") else row[0])
        for row in rows
    }
    if ledger_digests and digest not in ledger_digests:
        conflict = True

    legacy = connection.execute(
        "SELECT bundle_digest, manifest_path FROM snapshots "
        "WHERE scan_id = ?",
        (run_id,),
    ).fetchone()
    if legacy is not None:
        legacy_digest = str(
            legacy["bundle_digest"]
            if hasattr(legacy, "keys")
            else legacy[0]
            or ""
        ).strip()
        legacy_manifest = str(
            legacy["manifest_path"]
            if hasattr(legacy, "keys")
            else legacy[1]
            or ""
        ).strip()

        if not legacy_digest and legacy_manifest:
            legacy_path = Path(legacy_manifest).expanduser()
            if legacy_path.is_file():
                try:
                    legacy_digest = bundle_digest(legacy_path)
                except (OSError, TelemetryQualityError):
                    legacy_digest = ""

        # A pre-v0.45 row without verifiable content must fail closed.  It is
        # unsafe to assume that a newly supplied bundle with the same run ID is
        # the same evidence.
        if not legacy_digest or legacy_digest != digest:
            conflict = True

    if conflict:
        policy = load_policy(policy_path)
        reason_catalog = _reason_map(policy)
        reason_codes = list(decision.get("reason_codes") or [])
        reasons = list(decision.get("reasons") or [])
        _add_reason(
            reason_codes,
            reasons,
            reason_catalog,
            "run_id_hash_conflict",
        )
        state = "REJECTED"
        effects, allowed, blocked, retention = effects_for_state(policy, state)
        decision = dict(decision)
        decision.update(
            {
                "automated_state": state,
                "current_state": state,
                "reason_codes": reason_codes,
                "reasons": reasons,
                "allowed_effects": allowed,
                "blocked_effects": blocked,
                "effect_policy": effects,
                "retention_disposition": retention,
                "review_required": False,
            }
        )
    return decision


def retain_bundle(
    manifest_path: Path,
    *,
    evidence_root: Path,
    decision: dict[str, Any],
) -> str:
    state = str(decision.get("current_state") or "").upper()
    disposition = str(decision.get("retention_disposition") or "")
    if state == "REJECTED" or disposition == "audit_metadata_only":
        return ""

    expected_digest = str(decision.get("bundle_digest") or "").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        raise TelemetryQualityError(
            "trusted or quarantined evidence requires a valid bundle digest"
        )

    store = "quarantine" if state == "QUARANTINED" else "trusted"
    root = evidence_root.expanduser().resolve() / store
    root.mkdir(parents=True, exist_ok=True)
    run_id = str(decision.get("run_id") or "unknown-run")
    destination = root / f"{run_id}-{expected_digest[:16]}"
    if destination.exists():
        retained_manifest = destination / "manifest.json"
        if not retained_manifest.is_file():
            raise TelemetryQualityError(
                f"existing retained evidence is incomplete: {destination}"
            )
        retained_digest = bundle_digest(retained_manifest)
        if retained_digest != expected_digest:
            raise TelemetryQualityError(
                "existing retained evidence does not match its decision digest"
            )
        return str(retained_manifest)

    source_root = manifest_path.resolve().parent
    for item in source_root.rglob("*"):
        if item.is_symlink():
            raise TelemetryQualityError(
                f"source bundle contains a symbolic link: {item}"
            )
    source_digest = bundle_digest(manifest_path)
    if source_digest != expected_digest:
        raise TelemetryQualityError(
            "source bundle changed after quality evaluation"
        )

    temporary = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.", dir=str(root))
    )
    try:
        shutil.rmtree(temporary)
        shutil.copytree(
            source_root,
            temporary,
            symlinks=False,
            ignore_dangling_symlinks=False,
        )
        for item in temporary.rglob("*"):
            if item.is_symlink():
                raise TelemetryQualityError(
                    f"retained evidence contains a symbolic link: {item}"
                )
        retained_manifest = temporary / "manifest.json"
        if not retained_manifest.is_file():
            raise TelemetryQualityError(
                "retained bundle is missing manifest.json after copy"
            )
        retained_digest = bundle_digest(retained_manifest)
        if retained_digest != expected_digest:
            raise TelemetryQualityError(
                "retained bundle digest differs after atomic copy"
            )
        temporary.replace(destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise

    retained_manifest = destination / "manifest.json"
    if not retained_manifest.is_file():
        shutil.rmtree(destination, ignore_errors=True)
        raise TelemetryQualityError(
            "retained bundle is missing manifest.json after copy"
        )
    return str(retained_manifest)


def persist_decision(
    connection: sqlite3.Connection,
    decision: dict[str, Any],
    *,
    retained_manifest_path: str = "",
    import_status: str = "PENDING",
) -> dict[str, Any]:
    ensure_schema(connection)
    values = (
        decision["decision_id"],
        decision["run_id"],
        decision.get("bundle_digest", ""),
        decision.get("manifest_path", ""),
        retained_manifest_path,
        decision.get("network_scope", ""),
        decision.get("scanner_version", ""),
        decision["automated_state"],
        decision["current_state"],
        decision.get("policy_version", POLICY_VERSION),
        decision.get("schema_version", DECISION_SCHEMA_VERSION),
        canonical_json(decision.get("reason_codes", [])),
        canonical_json(decision.get("reasons", [])),
        canonical_json(decision.get("allowed_effects", [])),
        canonical_json(decision.get("blocked_effects", [])),
        canonical_json(decision.get("effect_policy", {})),
        canonical_json(decision.get("coverage_capabilities", {})),
        canonical_json(decision.get("source_contract", {})),
        decision.get("retention_disposition", "audit_metadata_only"),
        decision.get("evaluated_at", utc_now()),
        None,
        import_status,
        1 if decision.get("review_required") else 0,
    )
    connection.execute(
        """
        INSERT INTO telemetry_quality_decisions (
            decision_id, run_id, bundle_digest, manifest_path,
            retained_manifest_path, network_scope, scanner_version,
            automated_state, current_state, policy_version,
            decision_schema_version, reason_codes_json, reasons_json,
            allowed_effects_json, blocked_effects_json,
            effect_policy_json, coverage_json, source_contract_json,
            retention_disposition, evaluated_at, imported_at,
            import_status, review_required
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(run_id, bundle_digest) DO NOTHING
        """,
        values,
    )
    row = connection.execute(
        "SELECT * FROM telemetry_quality_decisions "
        "WHERE run_id = ? AND bundle_digest = ?",
        (decision["run_id"], decision.get("bundle_digest", "")),
    ).fetchone()
    return quality_row_to_dict(row) if row is not None else dict(decision)


def mark_import_status(
    connection: sqlite3.Connection,
    decision_id: str,
    status: str,
    *,
    imported_at: str | None = None,
) -> None:
    connection.execute(
        "UPDATE telemetry_quality_decisions "
        "SET import_status = ?, imported_at = COALESCE(?, imported_at) "
        "WHERE decision_id = ?",
        (str(status), imported_at, decision_id),
    )


def quality_row_to_dict(row: Any) -> dict[str, Any]:
    if row is None:
        return {}
    item = dict(row)
    for source, target, default in (
        ("reason_codes_json", "reason_codes", []),
        ("reasons_json", "reasons", []),
        ("allowed_effects_json", "allowed_effects", []),
        ("blocked_effects_json", "blocked_effects", []),
        ("effect_policy_json", "effect_policy", {}),
        ("coverage_json", "coverage_capabilities", {}),
        ("source_contract_json", "source_contract", {}),
    ):
        try:
            decoded = json.loads(item.get(source) or canonical_json(default))
        except (TypeError, json.JSONDecodeError):
            decoded = default
        item[target] = decoded
    item["review_required"] = bool(item.get("review_required"))
    item["bundle_id"] = str(item.get("run_id") or "")
    item["bundle_sha256"] = str(item.get("bundle_digest") or "")
    item["effects"] = dict(item.get("effect_policy") or {})
    item["decision_contract"] = decision_contract_payload(item)
    return item


def decision_by_id(
    connection: sqlite3.Connection,
    decision_id: str,
) -> dict[str, Any] | None:
    ensure_schema(connection)
    row = connection.execute(
        "SELECT * FROM telemetry_quality_decisions WHERE decision_id = ?",
        (str(decision_id or "").strip(),),
    ).fetchone()
    if row is None:
        return None
    item = quality_row_to_dict(row)
    item["reviews"] = [
        dict(review)
        for review in connection.execute(
            "SELECT * FROM telemetry_quality_reviews "
            "WHERE decision_id = ? ORDER BY rowid",
            (item["decision_id"],),
        ).fetchall()
    ]
    latest_review = item["reviews"][-1] if item["reviews"] else None
    item["decision_contract"] = decision_contract_payload(
        item,
        latest_review,
    )
    item["review"] = dict(item["decision_contract"]["review"])
    return item


def list_decisions(
    connection: sqlite3.Connection,
    *,
    limit: int = 50,
    scope: str | None = None,
    state: str | None = None,
) -> list[dict[str, Any]]:
    ensure_schema(connection)
    clauses: list[str] = []
    params: list[Any] = []
    if scope:
        clauses.append("network_scope = ?")
        params.append(canonical_scope(scope))
    if state:
        clean_state = str(state).strip().upper()
        if clean_state not in STATE_PRECEDENCE:
            raise TelemetryQualityError(
                f"unsupported quality state filter: {state!r}"
            )
        clauses.append("current_state = ?")
        params.append(clean_state)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    safe_limit = max(1, min(int(limit), 500))
    rows = connection.execute(
        "SELECT * FROM telemetry_quality_decisions"
        + where
        + " ORDER BY evaluated_at DESC, decision_id DESC LIMIT ?",
        (*params, safe_limit),
    ).fetchall()
    return [quality_row_to_dict(row) for row in rows]


def quality_summary(
    connection: sqlite3.Connection,
    *,
    scope: str | None = None,
) -> dict[str, Any]:
    ensure_schema(connection)
    clauses = ""
    params: tuple[Any, ...] = ()
    if scope:
        clauses = " WHERE network_scope = ?"
        params = (canonical_scope(scope),)
    rows = connection.execute(
        "SELECT current_state, COUNT(*) AS count "
        "FROM telemetry_quality_decisions"
        + clauses
        + " GROUP BY current_state",
        params,
    ).fetchall()
    counts = {state: 0 for state in STATE_PRECEDENCE}
    for row in rows:
        counts[str(row["current_state"])] = int(row["count"] or 0)
    return {
        "counts": counts,
        "total": sum(counts.values()),
        "review_required": counts["DEGRADED"] + counts["QUARANTINED"],
    }


def _actor_fields(actor: dict[str, Any]) -> tuple[str | None, str, str, str]:
    if not isinstance(actor, dict):
        raise TelemetryQualityError(
            "authenticated dashboard session actor is required"
        )
    auth_type = str(actor.get("auth_type") or "").strip()
    if auth_type != "dashboard_session":
        raise TelemetryQualityError(
            "telemetry-quality review and override require an authenticated "
            "dashboard session"
        )
    username = str(actor.get("username") or "").strip()
    role = str(actor.get("role") or "VIEWER").strip().upper()
    if not username:
        raise TelemetryQualityError("session actor username is missing")
    return actor.get("user_id"), username, role, auth_type


def record_review(
    connection: sqlite3.Connection,
    *,
    decision_id: str,
    action: str,
    reason: str,
    actor: dict[str, Any],
    resulting_state: str | None = None,
) -> dict[str, Any]:
    decision = decision_by_id(connection, decision_id)
    if decision is None:
        raise TelemetryQualityError(
            f"telemetry-quality decision not found: {decision_id}"
        )
    actor_user_id, username, role, auth_type = _actor_fields(actor)
    if role not in {"ANALYST", "ADMIN"}:
        raise TelemetryQualityError(
            "ANALYST or ADMIN role is required for telemetry-quality review"
        )
    clean_reason = str(reason or "").strip()
    if not clean_reason:
        raise TelemetryQualityError("a review reason is required")
    prior = str(decision["current_state"])
    result = str(resulting_state or prior).upper()
    review_id = uuid.uuid4().hex
    created_at = utc_now()
    connection.execute(
        """
        INSERT INTO telemetry_quality_reviews (
            review_id, decision_id, action, prior_state, resulting_state,
            reason, actor_user_id, actor_username, actor_role,
            actor_auth_type, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            review_id,
            decision_id,
            str(action or "ANNOTATE").upper(),
            prior,
            result,
            clean_reason,
            actor_user_id,
            username,
            role,
            auth_type,
            created_at,
        ),
    )
    return {
        "review_id": review_id,
        "decision_id": decision_id,
        "action": str(action or "ANNOTATE").upper(),
        "prior_state": prior,
        "resulting_state": result,
        "reason": clean_reason,
        "actor_username": username,
        "actor_role": role,
        "created_at": created_at,
    }


def override_decision(
    connection: sqlite3.Connection,
    *,
    decision_id: str,
    target_state: str,
    reason: str,
    actor: dict[str, Any],
    policy_path: Path,
) -> dict[str, Any]:
    decision = decision_by_id(connection, decision_id)
    if decision is None:
        raise TelemetryQualityError(
            f"telemetry-quality decision not found: {decision_id}"
        )
    _, _, role, _ = _actor_fields(actor)
    if role != "ADMIN":
        raise TelemetryQualityError(
            "ADMIN role is required for telemetry-quality override"
        )
    prior = str(decision["current_state"]).upper()
    target = str(target_state or "").strip().upper()
    if prior == "REJECTED":
        raise TelemetryQualityError("REJECTED telemetry is non-overridable")
    if (prior, target) not in ALLOWED_TRANSITIONS:
        raise TelemetryQualityError(
            f"override transition is not permitted: {prior} -> {target}"
        )

    policy = load_policy(policy_path)
    effects, allowed, blocked, retention = effects_for_state(policy, target)
    review = record_review(
        connection,
        decision_id=decision_id,
        action="OVERRIDE",
        reason=reason,
        actor=actor,
        resulting_state=target,
    )
    connection.execute(
        """
        UPDATE telemetry_quality_decisions
        SET current_state = ?,
            allowed_effects_json = ?,
            blocked_effects_json = ?,
            effect_policy_json = ?,
            retention_disposition = ?,
            review_required = ?
        WHERE decision_id = ?
        """,
        (
            target,
            canonical_json(allowed),
            canonical_json(blocked),
            canonical_json(effects),
            retention,
            1 if target in {"DEGRADED", "QUARANTINED"} else 0,
            decision_id,
        ),
    )
    updated = decision_by_id(connection, decision_id)
    assert updated is not None
    return {"decision": updated, "review": review}



def transition_retained_bundle(
    connection: sqlite3.Connection,
    *,
    decision: dict[str, Any],
    evidence_root: Path,
) -> str:
    """Move retained evidence between trusted and quarantine stores after override."""

    retained = str(decision.get("retained_manifest_path") or "").strip()
    state = str(decision.get("current_state") or "").upper()
    if not retained or state == "REJECTED":
        return retained

    source_manifest = Path(retained).expanduser().resolve()
    source_dir = source_manifest.parent
    store = "quarantine" if state == "QUARANTINED" else "trusted"
    destination_root = evidence_root.expanduser().resolve() / store
    destination_root.mkdir(parents=True, exist_ok=True)
    destination_dir = destination_root / source_dir.name

    if source_dir == destination_dir:
        return str(source_manifest)

    expected_digest = str(decision.get("bundle_digest") or "").strip()
    source_digest = bundle_digest(source_manifest)
    if expected_digest and source_digest != expected_digest:
        raise TelemetryQualityError(
            "retained source bundle digest no longer matches its ledger"
        )

    if destination_dir.exists():
        destination_manifest = destination_dir / "manifest.json"
        if not destination_manifest.is_file():
            raise TelemetryQualityError(
                f"target evidence directory is incomplete: {destination_dir}"
            )
        destination_digest = bundle_digest(destination_manifest)
        if destination_digest != source_digest:
            raise TelemetryQualityError(
                "existing target evidence differs from retained source"
            )
        shutil.rmtree(source_dir)
        new_manifest = destination_manifest
    else:
        source_dir.replace(destination_dir)
        new_manifest = destination_dir / "manifest.json"

    connection.execute(
        "UPDATE telemetry_quality_decisions "
        "SET retained_manifest_path = ? WHERE decision_id = ?",
        (str(new_manifest), decision["decision_id"]),
    )
    connection.execute(
        "UPDATE snapshots SET evidence_retention_path = ?, manifest_path = ? "
        "WHERE quality_decision_id = ?",
        (str(new_manifest), str(new_manifest), decision["decision_id"]),
    )
    return str(new_manifest)

def update_snapshot_quality_link(
    connection: sqlite3.Connection,
    *,
    scan_id: str,
    decision: dict[str, Any],
    retained_manifest_path: str,
) -> None:
    coverage = json_object(decision.get("coverage_capabilities"))
    connection.execute(
        """
        UPDATE snapshots
        SET quality_decision_id = ?,
            automated_quality_state = ?,
            current_quality_state = ?,
            bundle_digest = ?,
            evidence_retention_path = ?,
            quality_effects_json = ?,
            quality_reasons_json = ?,
            negative_evidence_allowed = ?
        WHERE scan_id = ?
        """,
        (
            decision.get("decision_id"),
            decision.get("automated_state"),
            decision.get("current_state"),
            decision.get("bundle_digest", ""),
            retained_manifest_path,
            canonical_json(decision.get("effect_policy", {})),
            canonical_json(decision.get("reasons", [])),
            1 if coverage.get("negative_evidence_allowed") else 0,
            scan_id,
        ),
    )


def quality_for_scan(
    connection: sqlite3.Connection,
    scan_id: str,
) -> dict[str, Any] | None:
    ensure_schema(connection)
    row = connection.execute(
        """
        SELECT q.*
        FROM telemetry_quality_decisions q
        JOIN snapshots s ON s.quality_decision_id = q.decision_id
        WHERE s.scan_id = ?
        LIMIT 1
        """,
        (scan_id,),
    ).fetchone()
    return quality_row_to_dict(row) if row is not None else None


def report_rows(
    connection: sqlite3.Connection,
    *,
    scope: str | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    try:
        return list_decisions(
            connection,
            limit=limit,
            scope=scope,
        )
    except sqlite3.Error:
        return []


__all__ = [
    "ALLOWED_TRANSITIONS",
    "DECISION_SCHEMA_VERSION",
    "POLICY_VERSION",
    "STATE_PRECEDENCE",
    "TelemetryQualityError",
    "apply_run_id_conflict",
    "bundle_digest",
    "canonical_scope",
    "decision_by_id",
    "decision_contract_payload",
    "ensure_schema",
    "evaluate_bundle",
    "evaluate_bundle_record",
    "list_decisions",
    "mark_import_status",
    "override_decision",
    "persist_decision",
    "quality_for_scan",
    "quality_summary",
    "record_review",
    "report_rows",
    "retain_bundle",
    "transition_retained_bundle",
    "update_snapshot_quality_link",
]
