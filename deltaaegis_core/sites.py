#!/usr/bin/env python3
"""Logical-site storage and scope aggregation boundary for DeltaAegis v0.44."""

from __future__ import annotations

import re
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any

from deltaaegis_core.auth import DeltaAegisError
from deltaaegis_core.ingest import canonical_network_scope


LOGICAL_SITE_ACTIVE = "ACTIVE"
LOGICAL_SITE_ARCHIVED = "ARCHIVED"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_logical_site_id(value: Any) -> str:
    site_id = str(value or "").strip()

    if (
        not site_id
        or len(site_id) > 96
        or re.fullmatch(r"[A-Za-z0-9._:-]+", site_id) is None
    ):
        raise DeltaAegisError(
            "logical site id must be 1-96 characters using "
            "letters, numbers, dot, underscore, colon, or hyphen"
        )

    return site_id


def normalize_logical_site_name(value: Any) -> str:
    name = " ".join(str(value or "").split())

    if not name:
        raise DeltaAegisError("logical site name is required")

    if len(name) > 160:
        raise DeltaAegisError(
            "logical site name must not exceed 160 characters"
        )

    if any(ord(character) < 32 for character in name):
        raise DeltaAegisError(
            "logical site name contains unsupported control characters"
        )

    return name


def normalize_logical_site_description(value: Any) -> str:
    description = str(value or "").strip()

    if len(description) > 2000:
        raise DeltaAegisError(
            "logical site description must not exceed 2000 characters"
        )

    if any(
        ord(character) < 32
        and character not in {"\n", "\r", "\t"}
        for character in description
    ):
        raise DeltaAegisError(
            "logical site description contains unsupported "
            "control characters"
        )

    return description


def logical_site_row_to_dict(
    row: sqlite3.Row | dict[str, Any],
) -> dict[str, Any]:
    item = dict(row)

    return {
        "site_id": str(item.get("site_id") or ""),
        "name": str(item.get("name") or ""),
        "description": str(item.get("description") or ""),
        "status": str(item.get("status") or LOGICAL_SITE_ACTIVE),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
        "archived_at": item.get("archived_at"),
        "member_count": int(item.get("member_count") or 0),
    }


def get_logical_site(
    connection: sqlite3.Connection,
    site_id: Any,
) -> dict[str, Any] | None:
    safe_site_id = normalize_logical_site_id(site_id)
    row = connection.execute(
        """
        SELECT
            s.site_id,
            s.name,
            s.description,
            s.status,
            s.created_at,
            s.updated_at,
            s.archived_at,
            COUNT(m.network_scope) AS member_count
        FROM logical_sites s
        LEFT JOIN logical_site_memberships m
            ON m.site_id = s.site_id
        WHERE s.site_id = ?
        GROUP BY s.site_id
        """,
        (safe_site_id,),
    ).fetchone()

    return logical_site_row_to_dict(row) if row is not None else None


def list_logical_sites(
    connection: sqlite3.Connection,
    include_archived: bool = False,
) -> list[dict[str, Any]]:
    where = "" if include_archived else "WHERE s.status = 'ACTIVE'"
    rows = connection.execute(
        f"""
        SELECT
            s.site_id,
            s.name,
            s.description,
            s.status,
            s.created_at,
            s.updated_at,
            s.archived_at,
            COUNT(m.network_scope) AS member_count
        FROM logical_sites s
        LEFT JOIN logical_site_memberships m
            ON m.site_id = s.site_id
        {where}
        GROUP BY s.site_id
        ORDER BY
            CASE s.status
                WHEN 'ACTIVE' THEN 0
                ELSE 1
            END,
            s.name COLLATE NOCASE,
            s.site_id
        """
    ).fetchall()

    return [logical_site_row_to_dict(row) for row in rows]


def create_logical_site(
    connection: sqlite3.Connection,
    name: Any,
    description: Any = "",
) -> dict[str, Any]:
    safe_name = normalize_logical_site_name(name)
    safe_description = normalize_logical_site_description(description)
    site_id = "site-" + uuid.uuid4().hex[:16]
    now = utc_now()

    try:
        connection.execute(
            """
            INSERT INTO logical_sites (
                site_id,
                name,
                description,
                status,
                created_at,
                updated_at,
                archived_at
            )
            VALUES (?, ?, ?, 'ACTIVE', ?, ?, NULL)
            """,
            (
                site_id,
                safe_name,
                safe_description,
                now,
                now,
            ),
        )
    except sqlite3.IntegrityError as exc:
        raise DeltaAegisError(
            f"logical site name already exists: {safe_name}"
        ) from exc

    site = get_logical_site(connection, site_id)
    if site is None:
        raise DeltaAegisError(
            f"logical site disappeared after creation: {site_id}"
        )

    return site


def rename_logical_site(
    connection: sqlite3.Connection,
    site_id: Any,
    name: Any,
) -> dict[str, Any]:
    safe_site_id = normalize_logical_site_id(site_id)
    safe_name = normalize_logical_site_name(name)

    if get_logical_site(connection, safe_site_id) is None:
        raise DeltaAegisError(
            f"logical site not found: {safe_site_id}"
        )

    try:
        connection.execute(
            """
            UPDATE logical_sites
            SET name = ?, updated_at = ?
            WHERE site_id = ?
            """,
            (safe_name, utc_now(), safe_site_id),
        )
    except sqlite3.IntegrityError as exc:
        raise DeltaAegisError(
            f"logical site name already exists: {safe_name}"
        ) from exc

    site = get_logical_site(connection, safe_site_id)
    if site is None:
        raise DeltaAegisError(
            f"logical site disappeared after rename: {safe_site_id}"
        )

    return site


def update_logical_site_description(
    connection: sqlite3.Connection,
    site_id: Any,
    description: Any,
) -> dict[str, Any]:
    safe_site_id = normalize_logical_site_id(site_id)
    safe_description = normalize_logical_site_description(
        description
    )

    cursor = connection.execute(
        """
        UPDATE logical_sites
        SET description = ?, updated_at = ?
        WHERE site_id = ?
        """,
        (safe_description, utc_now(), safe_site_id),
    )

    if cursor.rowcount == 0:
        raise DeltaAegisError(
            f"logical site not found: {safe_site_id}"
        )

    site = get_logical_site(connection, safe_site_id)
    if site is None:
        raise DeltaAegisError(
            "logical site disappeared after description update: "
            f"{safe_site_id}"
        )

    return site


def archive_logical_site(
    connection: sqlite3.Connection,
    site_id: Any,
) -> dict[str, Any]:
    safe_site_id = normalize_logical_site_id(site_id)
    site = get_logical_site(connection, safe_site_id)

    if site is None:
        raise DeltaAegisError(
            f"logical site not found: {safe_site_id}"
        )

    if site["status"] == LOGICAL_SITE_ARCHIVED:
        return site

    now = utc_now()
    connection.execute(
        """
        UPDATE logical_sites
        SET
            status = 'ARCHIVED',
            archived_at = ?,
            updated_at = ?
        WHERE site_id = ?
        """,
        (now, now, safe_site_id),
    )

    archived = get_logical_site(connection, safe_site_id)
    if archived is None:
        raise DeltaAegisError(
            f"logical site disappeared after archive: {safe_site_id}"
        )

    return archived


def logical_site_member_scopes(
    connection: sqlite3.Connection,
    site_id: Any,
) -> list[str]:
    safe_site_id = normalize_logical_site_id(site_id)

    if get_logical_site(connection, safe_site_id) is None:
        raise DeltaAegisError(
            f"logical site not found: {safe_site_id}"
        )

    return [
        str(row["network_scope"])
        for row in connection.execute(
            """
            SELECT network_scope
            FROM logical_site_memberships
            WHERE site_id = ?
            ORDER BY network_scope
            """,
            (safe_site_id,),
        ).fetchall()
    ]


def logical_site_for_network_scope(
    connection: sqlite3.Connection,
    network_scope: Any,
) -> dict[str, Any] | None:
    safe_scope = canonical_network_scope(str(network_scope or ""))
    row = connection.execute(
        """
        SELECT
            s.site_id,
            s.name,
            s.description,
            s.status,
            s.created_at,
            s.updated_at,
            s.archived_at,
            (
                SELECT COUNT(*)
                FROM logical_site_memberships members
                WHERE members.site_id = s.site_id
            ) AS member_count
        FROM logical_site_memberships m
        JOIN logical_sites s
            ON s.site_id = m.site_id
        WHERE m.network_scope = ?
        """,
        (safe_scope,),
    ).fetchone()

    return logical_site_row_to_dict(row) if row is not None else None


def assign_network_scope_to_logical_site(
    connection: sqlite3.Connection,
    site_id: Any,
    network_scope: Any,
) -> dict[str, Any]:
    safe_site_id = normalize_logical_site_id(site_id)
    safe_scope = canonical_network_scope(str(network_scope or ""))
    site = get_logical_site(connection, safe_site_id)

    if site is None:
        raise DeltaAegisError(
            f"logical site not found: {safe_site_id}"
        )

    if site["status"] != LOGICAL_SITE_ACTIVE:
        raise DeltaAegisError(
            f"logical site is archived: {safe_site_id}"
        )

    existing = connection.execute(
        """
        SELECT site_id
        FROM logical_site_memberships
        WHERE network_scope = ?
        """,
        (safe_scope,),
    ).fetchone()

    if existing is not None:
        existing_site_id = str(existing["site_id"])

        if existing_site_id == safe_site_id:
            raise DeltaAegisError(
                f"network scope is already assigned to logical site "
                f"{safe_site_id}: {safe_scope}"
            )

        raise DeltaAegisError(
            f"network scope {safe_scope} is already assigned to "
            f"logical site {existing_site_id}"
        )

    now = utc_now()
    connection.execute(
        """
        INSERT INTO logical_site_memberships (
            network_scope,
            site_id,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (safe_scope, safe_site_id, now, now),
    )

    return {
        "site_id": safe_site_id,
        "network_scope": safe_scope,
        "created_at": now,
        "updated_at": now,
    }


def remove_network_scope_from_logical_site(
    connection: sqlite3.Connection,
    site_id: Any,
    network_scope: Any,
) -> dict[str, Any]:
    safe_site_id = normalize_logical_site_id(site_id)
    safe_scope = canonical_network_scope(str(network_scope or ""))

    cursor = connection.execute(
        """
        DELETE FROM logical_site_memberships
        WHERE site_id = ? AND network_scope = ?
        """,
        (safe_site_id, safe_scope),
    )

    if cursor.rowcount == 0:
        raise DeltaAegisError(
            f"logical site membership not found: "
            f"{safe_site_id} -> {safe_scope}"
        )

    return {
        "site_id": safe_site_id,
        "network_scope": safe_scope,
        "removed": True,
    }


def snapshot_network_scope(snapshot_or_target) -> str:
    target = getattr(snapshot_or_target, "target", snapshot_or_target)
    return canonical_network_scope(str(target))


def logical_site_member_detail_rows(
    connection: sqlite3.Connection,
    site_id: Any,
) -> list[dict[str, Any]]:
    safe_site_id = normalize_logical_site_id(site_id)
    site = get_logical_site(connection, safe_site_id)

    if site is None:
        raise DeltaAegisError(
            f"logical site not found: {safe_site_id}"
        )

    rows = connection.execute(
        '''
        WITH snapshot_summary AS (
            SELECT
                network_scope,
                COUNT(*) AS snapshots,
                SUM(
                    CASE
                        WHEN quality_status = 'ACCEPTED' THEN 1
                        ELSE 0
                    END
                ) AS accepted_snapshots,
                MAX(created_at) AS latest_scan_at
            FROM snapshots
            GROUP BY network_scope
        )
        SELECT
            m.network_scope,
            m.created_at AS assigned_at,
            m.updated_at AS membership_updated_at,
            COALESCE(s.snapshots, 0) AS snapshots,
            COALESCE(s.accepted_snapshots, 0) AS accepted_snapshots,
            s.latest_scan_at
        FROM logical_site_memberships m
        LEFT JOIN snapshot_summary s
            ON s.network_scope = m.network_scope
        WHERE m.site_id = ?
        ORDER BY m.network_scope
        ''',
        (safe_site_id,),
    ).fetchall()

    return [
        {
            "network_scope": str(row["network_scope"]),
            "assigned_at": row["assigned_at"],
            "membership_updated_at": row[
                "membership_updated_at"
            ],
            "observed": int(row["snapshots"] or 0) > 0,
            "snapshots": int(row["snapshots"] or 0),
            "accepted_snapshots": int(
                row["accepted_snapshots"] or 0
            ),
            "latest_scan_at": row["latest_scan_at"],
        }
        for row in rows
    ]


def logical_site_detail_payload(
    connection: sqlite3.Connection,
    site_id: Any,
) -> dict[str, Any]:
    site = get_logical_site(connection, site_id)

    if site is None:
        raise DeltaAegisError(
            f"logical site not found: "
            f"{normalize_logical_site_id(site_id)}"
        )

    members = logical_site_member_detail_rows(
        connection,
        site["site_id"],
    )

    return {
        "ok": True,
        "site": site,
        "members": members,
        "coverage": {
            "member_scope_count": len(members),
            "observed_scope_count": sum(
                1 for item in members if item["observed"]
            ),
            "unobserved_scope_count": sum(
                1 for item in members if not item["observed"]
            ),
            "snapshot_count": sum(
                int(item["snapshots"]) for item in members
            ),
            "accepted_snapshot_count": sum(
                int(item["accepted_snapshots"])
                for item in members
            ),
        },
    }


def logical_site_list_payload(
    connection: sqlite3.Connection,
    include_archived: bool = False,
) -> dict[str, Any]:
    sites = list_logical_sites(
        connection,
        include_archived=include_archived,
    )

    return {
        "ok": True,
        "include_archived": bool(include_archived),
        "site_count": len(sites),
        "sites": sites,
    }


def query_network_scope_catalog(
    connection: sqlite3.Connection,
    *,
    unassigned_only: bool = False,
) -> list[dict[str, Any]]:
    where = "WHERE m.site_id IS NULL" if unassigned_only else ""

    rows = connection.execute(
        f'''
        WITH all_scopes AS (
            SELECT network_scope
            FROM snapshots
            WHERE network_scope IS NOT NULL
              AND network_scope != ''
            UNION
            SELECT network_scope
            FROM logical_site_memberships
        ),
        snapshot_summary AS (
            SELECT
                network_scope,
                COUNT(*) AS snapshots,
                SUM(
                    CASE
                        WHEN quality_status = 'ACCEPTED' THEN 1
                        ELSE 0
                    END
                ) AS accepted_snapshots,
                MAX(created_at) AS latest_scan_at
            FROM snapshots
            GROUP BY network_scope
        )
        SELECT
            a.network_scope,
            COALESCE(s.snapshots, 0) AS snapshots,
            COALESCE(s.accepted_snapshots, 0) AS accepted_snapshots,
            s.latest_scan_at,
            m.site_id,
            ls.name AS site_name,
            ls.status AS site_status
        FROM all_scopes a
        LEFT JOIN snapshot_summary s
            ON s.network_scope = a.network_scope
        LEFT JOIN logical_site_memberships m
            ON m.network_scope = a.network_scope
        LEFT JOIN logical_sites ls
            ON ls.site_id = m.site_id
        {where}
        ORDER BY
            CASE WHEN s.latest_scan_at IS NULL THEN 1 ELSE 0 END,
            s.latest_scan_at DESC,
            a.network_scope
        '''
    ).fetchall()

    return [
        {
            "network_scope": str(row["network_scope"]),
            "snapshots": int(row["snapshots"] or 0),
            "accepted_snapshots": int(
                row["accepted_snapshots"] or 0
            ),
            "latest_scan_at": row["latest_scan_at"],
            "site_id": row["site_id"],
            "site_name": row["site_name"],
            "site_status": row["site_status"],
            "assigned": bool(row["site_id"]),
        }
        for row in rows
    ]
