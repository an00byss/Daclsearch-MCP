"""DACLSearch MCP Server — query Active Directory ACL databases via natural language."""

import csv
import io
import json
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from typing import Annotated

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import Field

# ── Access mask / flag constants ───────────────────────────────────────────────

ACCESS_MASK_BITS: dict[int, str] = {
    0x00000001: "Create Child",
    0x00000002: "Delete Child",
    0x00000004: "List Children",
    0x00000008: "Self",
    0x00000010: "Read Prop",
    0x00000020: "Write Prop",
    0x00000040: "Delete Tree",
    0x00000080: "List Object",
    0x00000100: "Extended Right",
    0x00010000: "Delete",
    0x00020000: "Read Control",
    0x00040000: "Write Dacl",
    0x00080000: "Write Owner",
    0x00100000: "Synchronize",
    0x01000000: "Access System Security",
    0x000F01FF: "Generic All",
}

ACE_FLAG_BITS: dict[int, str] = {
    0x01: "Object Inherit",
    0x02: "Container Inherit",
    0x04: "No Propagate Inherit",
    0x08: "Inherit Only",
    0x10: "Inherited",
    0x40: "Successful Access",
    0x80: "Failed Access",
}

# Known attack pattern keywords → mask bit(s) to filter on
ATTACK_PATTERNS: dict[str, list[int]] = {
    "dcsync":                [0x00000100],
    "full control":          [0x000F01FF],
    "generic all":           [0x000F01FF],
    "genericall":            [0x000F01FF],
    "write dacl":            [0x00040000],
    "writedacl":             [0x00040000],
    "write owner":           [0x00080000],
    "writeowner":            [0x00080000],
    "write prop":            [0x00000020],
    "writeprop":             [0x00000020],
    "all extended rights":   [0x00000100],
    "laps":                  [0x00000010],
    "shadow credentials":    [0x00000020],
    "rbcd":                  [0x00000020],
    "add member":            [0x00000020],
    "reset password":        [0x00000100],
    "force change password": [0x00000100],
}

# ── Core SQL ───────────────────────────────────────────────────────────────────

_CORE_ACE_QUERY = """
SELECT
    aces.id          AS ace_id,
    ao.dn            AS object_dn,
    ao.name          AS object_name,
    ap.dn            AS principal_dn,
    ap.name          AS principal_name,
    at.name          AS ace_type,
    aces.mask        AS mask,
    aces.flags       AS flags,
    ot.name          AS object_type,
    iot.name         AS inherited_object_type,
    owner.name       AS object_owner
FROM aces
JOIN  ad_object  ao    ON aces.object_id              = ao.id
JOIN  ad_object  ap    ON aces.principal_id            = ap.id
JOIN  ace_type   at    ON aces.type_id                 = at.id
LEFT JOIN object_type ot    ON aces.object_type_id           = ot.id
LEFT JOIN object_type iot   ON aces.inherited_object_type_id = iot.id
LEFT JOIN ad_object   owner ON ao.owner_id                   = owner.id
"""

# ── Helpers ────────────────────────────────────────────────────────────────────

def decode_mask(mask: int) -> list[str]:
    if mask & 0x000F01FF == 0x000F01FF:
        return ["Generic All"]
    composite = {0x000F01FF, 0x00020094, 0x00020028, 0x00020004}
    return [name for bit, name in ACCESS_MASK_BITS.items()
            if bit not in composite and mask & bit]


def decode_flags(flags: int | None) -> list[str]:
    if not flags:
        return []
    return [name for bit, name in ACE_FLAG_BITS.items() if flags & bit]


def _rows_to_dicts(rows: list) -> list[dict]:
    result = []
    for row in rows:
        d = dict(row)
        d["decoded_rights"] = decode_mask(d["mask"])
        d["decoded_flags"] = decode_flags(d["flags"])
        result.append(d)
    return result


def _resolve_db(db_path: str | None) -> str:
    """Return db_path if given, else fall back to DACLSEARCH_DB env var."""
    if db_path and db_path.strip().lower() not in ("null", "none", ""):
        path = db_path.strip()
    else:
        path = os.environ.get("DACLSEARCH_DB")
    if not path:
        raise ToolError(
            "No database specified. Pass db_path or set DACLSEARCH_DB in the MCP server env config."
        )
    resolved = os.path.abspath(os.path.expanduser(path))
    if not os.path.isfile(resolved):
        raise ToolError(
            f"Database file not found: '{resolved}' "
            f"(resolved from '{path}'). Check DACLSEARCH_DB or db_path value."
        )
    return resolved


@contextmanager
def get_db(db_path: str):
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    except sqlite3.OperationalError as e:
        raise ToolError(f"Cannot open database '{db_path}': {e}")


# ── Natural language intent extraction ────────────────────────────────────────

_TARGET_PREP = re.compile(
    r'\b(?:to|on|of|over|for|against)\s+["\']?(.+?)["\']?\s*(?:group|user|object|ou|computer)?\s*$',
    re.IGNORECASE,
)
_SUBJECT_PREP = re.compile(
    r'\b(?:what can|can|rights?\s+(?:of|for)|permissions?\s+(?:of|for))\s+["\']?(.+?)["\']?\b',
    re.IGNORECASE,
)
_WHO_RE    = re.compile(r'\bwho\b', re.IGNORECASE)
_OWNER_RE  = re.compile(r'\bown(?:s|er|ership)\b', re.IGNORECASE)


def _extract_intent(query: str) -> dict:
    q = query.strip()
    intent = {"mode": None, "object_name": None, "principal_name": None, "mask_filters": []}

    q_lower = q.lower()
    for pattern, bits in ATTACK_PATTERNS.items():
        if pattern in q_lower:
            intent["mask_filters"] = bits
            break

    if _OWNER_RE.search(q):
        intent["mode"] = "owner"
        m = _TARGET_PREP.search(q)
        if m:
            intent["object_name"] = m.group(1).strip()
        return intent

    if _WHO_RE.search(q):
        m = _TARGET_PREP.search(q)
        if m:
            intent["object_name"] = m.group(1).strip()
            intent["mode"] = "object"
            return intent

    m = _SUBJECT_PREP.search(q)
    if m:
        intent["principal_name"] = m.group(1).strip()
        intent["mode"] = "principal"
        return intent

    if intent["mask_filters"]:
        intent["mode"] = "mask_global"
        return intent

    intent["object_name"] = q
    intent["mode"] = "object"
    return intent


# ── HTML report template ───────────────────────────────────────────────────────

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>DACLSearch ACL Report</title>
  <style>
    body {{ font-family: monospace; font-size: 13px; background: #1a1a2e; color: #eee; margin: 0; padding: 1em; }}
    h1   {{ color: #e94560; margin-bottom: 0.2em; }}
    p.meta {{ color: #888; margin: 0 0 1em; }}
    table {{ border-collapse: collapse; width: 100%; }}
    thead {{ position: sticky; top: 0; }}
    th   {{ background: #16213e; color: #e94560; text-align: left; padding: 6px 10px; }}
    td   {{ padding: 5px 10px; border-bottom: 1px solid #333; vertical-align: top; }}
    tr:nth-child(even) {{ background: #0f3460; }}
    tr:hover {{ background: #533483; }}
    .denied  {{ color: #ff6b6b; font-weight: bold; }}
    .allowed {{ color: #6bff6b; }}
  </style>
</head>
<body>
  <h1>DACLSearch ACL Report</h1>
  <p class="meta">Database: {db_path} | Generated: {timestamp} | Rows: {row_count}</p>
  <table>
    <thead>
      <tr>
        <th>Object</th><th>Principal</th><th>ACE Type</th>
        <th>Rights</th><th>Flags</th><th>Object Type</th><th>Owner</th>
      </tr>
    </thead>
    <tbody>
{rows_html}
    </tbody>
  </table>
</body>
</html>
"""


def _row_to_html(row: dict) -> str:
    ace_class = "denied" if "Denied" in (row["ace_type"] or "") else "allowed"
    rights = ", ".join(row["decoded_rights"]) or hex(row["mask"])
    flags  = ", ".join(row["decoded_flags"]) or ""
    return (
        f'      <tr>'
        f'<td>{row["object_name"]}</td>'
        f'<td>{row["principal_name"]}</td>'
        f'<td class="{ace_class}">{row["ace_type"]}</td>'
        f'<td>{rights}</td>'
        f'<td>{flags}</td>'
        f'<td>{row["object_type"] or ""}</td>'
        f'<td>{row["object_owner"] or ""}</td>'
        f'</tr>'
    )


# ── FastMCP server ─────────────────────────────────────────────────────────────

mcp = FastMCP(
    name="DACLSearch",
    instructions=(
        "Query Active Directory ACL databases created by DACLSearch. "
        "Each tool accepts an optional db_path. If omitted, the DACLSEARCH_DB environment variable is used. "
        "Use search_acls for natural language questions, get_object_acl to inspect a specific AD object's permissions, "
        "get_principal_permissions to see what a user or group can do, "
        "list_principals to enumerate known AD objects, and "
        "generate_report to export findings as CSV, HTML, or JSON."
    ),
)


@mcp.tool
def list_principals(
    db_path: Annotated[str | None, "Path to DACLSearch SQLite database. Omit to use DACLSEARCH_DB env var."] = None,
    object_class: Annotated[
        str | None,
        Field(
            description="Filter by AD object class: 'user', 'group', 'computer', 'organizationalUnit', etc. Omit for all.",
            default=None,
        ),
    ] = None,
) -> list[dict]:
    """
    List AD principals (users, groups, computers, OUs) stored in the database.

    Use this when the user asks: 'what objects are in the database?', 'list all users',
    'show me all groups', 'what computers are tracked?'.

    Returns each object's name, DN, SID, and object classes.
    """
    db_path = _resolve_db(db_path)
    with get_db(db_path) as conn:
        base_sql = """
            SELECT ao.id, ao.name, ao.dn, ao.sid,
                   GROUP_CONCAT(oc.name, ', ') AS object_classes
            FROM ad_object ao
            LEFT JOIN ad_object_objectclass aoc ON ao.id = aoc.obj_id
            LEFT JOIN ad_objectclass oc          ON aoc.class_id = oc.id
        """
        if object_class:
            sql = base_sql + """
                WHERE ao.id IN (
                    SELECT aoc2.obj_id
                    FROM ad_object_objectclass aoc2
                    JOIN ad_objectclass oc2 ON aoc2.class_id = oc2.id
                    WHERE LOWER(oc2.name) = LOWER(?)
                )
                GROUP BY ao.id ORDER BY ao.name
            """
            rows = conn.execute(sql, (object_class,)).fetchall()
        else:
            sql = base_sql + " GROUP BY ao.id ORDER BY ao.name"
            rows = conn.execute(sql).fetchall()

        return [dict(r) for r in rows]


@mcp.tool
def get_object_acl(
    object_name: Annotated[
        str,
        "Name or partial name of the AD object to inspect (e.g. 'Domain Admins', 'krbtgt', 'Administrator')",
    ],
    db_path: Annotated[str | None, "Path to DACLSearch SQLite database. Omit to use DACLSEARCH_DB env var."] = None,
) -> list[dict]:
    """
    Retrieve all ACEs defined on a specific AD object — who has what rights to it.

    Use this when the user asks: 'who has access to Domain Admins?', 'show the ACL on krbtgt',
    'what permissions are set on the Domain Controllers OU?', 'who can modify the Administrator account?'.

    Returns every ACE: which principal, what right, ACE type (Allow/Deny), decoded permissions,
    inheritance flags, and the object's owner.
    """
    db_path = _resolve_db(db_path)
    with get_db(db_path) as conn:
        sql = _CORE_ACE_QUERY + " WHERE ao.name LIKE ? ORDER BY ap.name"
        rows = conn.execute(sql, (f"%{object_name}%",)).fetchall()
        return _rows_to_dicts(rows)


@mcp.tool
def get_principal_permissions(
    principal_name: Annotated[
        str,
        "Name or partial name of the principal (user, group, computer) whose permissions to retrieve",
    ],
    db_path: Annotated[str | None, "Path to DACLSearch SQLite database. Omit to use DACLSEARCH_DB env var."] = None,
    ace_type: Annotated[
        str,
        Field(
            description="Filter ACE type: 'allowed' for grants only, 'denied' for denials only, 'all' for everything.",
            default="all",
        ),
    ] = "all",
) -> list[dict]:
    """
    List all ACEs where a given principal has been granted or denied rights on any AD object.

    Use this when the user asks: 'what can John Smith do?', 'what rights does Domain Users have?',
    'show write permissions for the helpdesk group', 'what is helpdesk allowed to do?',
    'find all denied ACEs for guest'.

    ace_type 'allowed' returns only Allow/Allowed-Object ACEs.
    ace_type 'denied' returns only Deny/Denied-Object ACEs.
    ace_type 'all' (default) returns everything.
    """
    db_path = _resolve_db(db_path)
    with get_db(db_path) as conn:
        params: list = [f"%{principal_name}%"]
        where = "WHERE ap.name LIKE ?"

        if ace_type.lower() == "allowed":
            where += " AND at.name IN ('Allowed', 'Allowed Object')"
        elif ace_type.lower() == "denied":
            where += " AND at.name IN ('Denied', 'Denied Object')"

        sql = _CORE_ACE_QUERY + f" {where} ORDER BY ao.name"
        rows = conn.execute(sql, params).fetchall()
        return _rows_to_dicts(rows)


@mcp.tool
def search_acls(
    query: Annotated[
        str,
        "Natural language question about AD permissions, e.g. "
        "'who has WriteDACL on Domain Admins', 'what can helpdesk do', "
        "'show DCSync rights', 'who owns krbtgt', 'list GenericAll ACEs'",
    ],
    db_path: Annotated[str | None, "Path to DACLSearch SQLite database. Omit to use DACLSEARCH_DB env var."] = None,
) -> dict:
    """
    Answer natural language questions about AD ACLs by extracting intent and routing to the right query.

    Understands queries like:
    - 'who has write access to Domain Admins?' → ACEs on Domain Admins filtered to Write rights
    - 'what can helpdesk do?' → all ACEs where helpdesk is the principal
    - 'who owns krbtgt?' → owner of the krbtgt object
    - 'who has GenericAll on the domain?' → Generic All ACEs on domain root
    - 'show DCSync rights' → Extended Right ACEs across all objects
    - 'list users with WriteDACL' → WriteDACL ACEs across all objects

    Returns structured ACE results plus a 'query_interpretation' field explaining what was extracted.
    """
    db_path = _resolve_db(db_path)
    intent = _extract_intent(query)
    mode          = intent["mode"]
    object_name   = intent["object_name"]
    principal_name = intent["principal_name"]
    mask_filters  = intent["mask_filters"]

    with get_db(db_path) as conn:
        if mode == "owner":
            name_filter = object_name or query
            sql = """
                SELECT ao.name AS object_name, ao.dn AS object_dn,
                       owner.name AS owner_name, owner.dn AS owner_dn
                FROM ad_object ao
                LEFT JOIN ad_object owner ON ao.owner_id = owner.id
                WHERE ao.name LIKE ?
                ORDER BY ao.name
            """
            rows = [dict(r) for r in conn.execute(sql, (f"%{name_filter}%",)).fetchall()]
            return {
                "query_interpretation": f"Ownership lookup for objects matching '{name_filter}'",
                "results": rows,
            }

        if mode == "object":
            sql = _CORE_ACE_QUERY + " WHERE ao.name LIKE ?"
            params: list = [f"%{object_name}%"]
            if mask_filters:
                placeholders = " OR ".join("(aces.mask & ?) != 0" for _ in mask_filters)
                sql += f" AND ({placeholders})"
                params.extend(mask_filters)
            sql += " ORDER BY ap.name"
            rows = conn.execute(sql, params).fetchall()
            interp = f"Object ACL for '{object_name}'"
            if mask_filters:
                interp += f" filtered to mask bits {[hex(b) for b in mask_filters]}"

        elif mode == "principal":
            sql = _CORE_ACE_QUERY + " WHERE ap.name LIKE ? ORDER BY ao.name"
            rows = conn.execute(sql, (f"%{principal_name}%",)).fetchall()
            interp = f"Principal permissions for '{principal_name}'"

        elif mode == "mask_global":
            placeholders = " OR ".join("(aces.mask & ?) != 0" for _ in mask_filters)
            sql = _CORE_ACE_QUERY + f" WHERE ({placeholders}) ORDER BY ao.name"
            rows = conn.execute(sql, mask_filters).fetchall()
            interp = f"Global mask search for bits {[hex(b) for b in mask_filters]}"

        else:
            # fallback: treat as object name
            sql = _CORE_ACE_QUERY + " WHERE ao.name LIKE ? ORDER BY ap.name"
            rows = conn.execute(sql, (f"%{query}%",)).fetchall()
            interp = f"Fallback object name search for '{query}'"

        return {
            "query_interpretation": interp,
            "results": _rows_to_dicts(rows),
        }


@mcp.tool
def get_group_members(
    group_name: Annotated[str, "Name or partial name of the AD group (e.g. 'Domain Admins', 'Enterprise Admins')"],
    db_path: Annotated[str | None, "Path to DACLSearch SQLite database. Omit to use DACLSEARCH_DB env var."] = None,
) -> list[dict]:
    """
    List members of an Active Directory group using the memberships table.

    Use this when the user asks: 'who is in Domain Admins?', 'list members of Enterprise Admins',
    'what accounts are in the helpdesk group?', 'show me Domain Admins members'.

    Returns each member's name, DN, and SID. Also includes the matched group name
    so you can confirm which group was found when using a partial name.
    """
    db_path = _resolve_db(db_path)
    with get_db(db_path) as conn:
        sql = """
            SELECT
                ag.name  AS group_name,
                ag.dn    AS group_dn,
                ap.name  AS member_name,
                ap.dn    AS member_dn,
                ap.sid   AS member_sid
            FROM memberships m
            JOIN ad_object ag ON m.group_id    = ag.id
            JOIN ad_object ap ON m.principal_id = ap.id
            WHERE ag.name LIKE ?
            ORDER BY ag.name, ap.name
        """
        rows = conn.execute(sql, (f"%{group_name}%",)).fetchall()
        return [dict(r) for r in rows]


@mcp.tool
def get_principal_groups(
    principal_name: Annotated[str, "Name or partial name of the user, computer, or group to look up"],
    db_path: Annotated[str | None, "Path to DACLSearch SQLite database. Omit to use DACLSEARCH_DB env var."] = None,
) -> list[dict]:
    """
    List all groups a given principal (user, computer, or group) is a direct member of.

    Use this when the user asks: 'what groups is jsmith in?', 'which groups does the helpdesk account belong to?',
    'show group membership for Administrator', 'what is user X a member of?'.

    Returns each group's name and DN. For nested/transitive membership, use get_nested_group_members instead.
    """
    db_path = _resolve_db(db_path)
    with get_db(db_path) as conn:
        sql = """
            SELECT
                ap.name  AS principal_name,
                ap.dn    AS principal_dn,
                ag.name  AS group_name,
                ag.dn    AS group_dn,
                ag.sid   AS group_sid
            FROM memberships m
            JOIN ad_object ap ON m.principal_id = ap.id
            JOIN ad_object ag ON m.group_id     = ag.id
            WHERE ap.name LIKE ?
            ORDER BY ap.name, ag.name
        """
        rows = conn.execute(sql, (f"%{principal_name}%",)).fetchall()
        return [dict(r) for r in rows]


@mcp.tool
def get_nested_group_members(
    group_name: Annotated[str, "Name or partial name of the AD group to resolve recursively"],
    db_path: Annotated[str | None, "Path to DACLSearch SQLite database. Omit to use DACLSEARCH_DB env var."] = None,
) -> list[dict]:
    """
    Recursively resolve all transitive members of a group, including members of nested sub-groups.

    Use this when the user asks: 'who has effective membership in Domain Admins?',
    'list all transitive members of Enterprise Admins', 'show nested group members',
    'who ultimately belongs to the IT Admins group?'.

    Unlike get_group_members (direct members only), this follows nested group chains
    using a recursive SQL CTE. Returns every principal reachable through the group hierarchy,
    along with their depth and the path taken to reach them.
    """
    db_path = _resolve_db(db_path)
    with get_db(db_path) as conn:
        # First resolve the group id(s) matching the name
        group_rows = conn.execute(
            "SELECT id, name, dn FROM ad_object WHERE name LIKE ?",
            (f"%{group_name}%",),
        ).fetchall()

        if not group_rows:
            return []

        results = []
        for group in group_rows:
            sql = """
                WITH RECURSIVE members(principal_id, depth, path) AS (
                    SELECT m.principal_id, 1, ag.name
                    FROM memberships m
                    JOIN ad_object ag ON m.group_id = ag.id
                    WHERE m.group_id = ?
                    UNION ALL
                    SELECT m2.principal_id, members.depth + 1,
                           members.path || ' > ' || ag2.name
                    FROM memberships m2
                    JOIN ad_object ag2 ON m2.group_id = ag2.id
                    JOIN members ON m2.group_id = members.principal_id
                    WHERE members.depth < 20
                )
                SELECT DISTINCT
                    ? AS group_name,
                    ap.name  AS member_name,
                    ap.dn    AS member_dn,
                    ap.sid   AS member_sid,
                    members.depth AS depth,
                    members.path  AS via_path
                FROM members
                JOIN ad_object ap ON members.principal_id = ap.id
                ORDER BY members.depth, ap.name
            """
            rows = conn.execute(sql, (group["id"], group["name"])).fetchall()
            results.extend(dict(r) for r in rows)

        return results


@mcp.tool
def database_info(
    db_path: Annotated[str | None, "Path to DACLSearch SQLite database. Omit to use DACLSEARCH_DB env var."] = None,
) -> dict:
    """
    Return a summary of the database contents: row counts per table, available object types,
    ACE types, and object classes. Useful for understanding what is in a database before querying.

    Use this when the user asks: 'what is in this database?', 'how many ACEs are there?',
    'what object types exist?', 'give me a summary of the database', 'what domains are covered?'.
    """
    db_path = _resolve_db(db_path)
    with get_db(db_path) as conn:
        counts = {}
        for table in ("ad_object", "aces", "memberships", "ad_objectclass", "object_type", "ace_type"):
            row = conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()
            counts[table] = row["n"]

        object_classes = [r["name"] for r in conn.execute(
            "SELECT name FROM ad_objectclass ORDER BY name"
        ).fetchall()]

        ace_types = [r["name"] for r in conn.execute(
            "SELECT name FROM ace_type ORDER BY name"
        ).fetchall()]

        object_types = [r["name"] for r in conn.execute(
            "SELECT name FROM object_type ORDER BY name"
        ).fetchall()]

        top_principals = [dict(r) for r in conn.execute("""
            SELECT ap.name AS principal_name,
                   COUNT(*) AS ace_count
            FROM aces a
            JOIN ad_object ap ON a.principal_id = ap.id
            GROUP BY ap.id
            ORDER BY ace_count DESC
            LIMIT 10
        """).fetchall()]

        return {
            "db_path": db_path,
            "row_counts": counts,
            "object_classes": object_classes,
            "ace_types": ace_types,
            "object_types": object_types,
            "top_principals_by_ace_count": top_principals,
        }


@mcp.tool
def generate_report(
    output_format: Annotated[
        str,
        Field(description="Output format: 'csv', 'html', or 'json'", pattern="^(csv|html|json)$"),
    ],
    db_path: Annotated[str | None, "Path to DACLSearch SQLite database. Omit to use DACLSEARCH_DB env var."] = None,
    principal_filter: Annotated[
        str | None,
        Field(
            description="Optional: restrict to ACEs where this principal name (partial match) is the subject.",
            default=None,
        ),
    ] = None,
    object_filter: Annotated[
        str | None,
        Field(
            description="Optional: restrict to ACEs on objects whose name matches this string (partial match).",
            default=None,
        ),
    ] = None,
) -> str:
    """
    Generate a formatted ACL report from the database as a string.

    Use this when the user asks: 'generate a CSV report', 'export ACLs to HTML',
    'give me a JSON dump of all permissions', 'create a report filtered to Domain Admins',
    'export what helpdesk can do as CSV'.

    Returns the complete report as a string. Save it to a file if needed.
    Large databases without filters may produce very large output — use filters when possible.
    """
    db_path = _resolve_db(db_path)
    where_clauses = []
    params: list = []

    if principal_filter:
        where_clauses.append("ap.name LIKE ?")
        params.append(f"%{principal_filter}%")
    if object_filter:
        where_clauses.append("ao.name LIKE ?")
        params.append(f"%{object_filter}%")

    sql = _CORE_ACE_QUERY
    if where_clauses:
        sql += " WHERE " + " AND ".join(where_clauses)
    sql += " ORDER BY ao.name, ap.name"

    with get_db(db_path) as conn:
        rows = _rows_to_dicts(conn.execute(sql, params).fetchall())

    fmt = output_format.lower()

    if fmt == "json":
        return json.dumps(rows, indent=2)

    if fmt == "csv":
        buf = io.StringIO()
        if not rows:
            return ""
        fieldnames = [k for k in rows[0] if k not in ("decoded_rights", "decoded_flags")]
        fieldnames += ["decoded_rights", "decoded_flags"]
        writer = csv.DictWriter(buf, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            flat = dict(row)
            flat["decoded_rights"] = ", ".join(row["decoded_rights"])
            flat["decoded_flags"]  = ", ".join(row["decoded_flags"])
            writer.writerow(flat)
        return buf.getvalue()

    # html
    rows_html = "\n".join(_row_to_html(r) for r in rows)
    return _HTML_TEMPLATE.format(
        db_path=db_path,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        row_count=len(rows),
        rows_html=rows_html,
    )


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run()
