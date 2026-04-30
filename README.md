# DACLSearch MCP Server

An MCP (Model Context Protocol) server that wraps [DACLSearch](https://github.com/cogiceo/DACLSearch) SQLite databases, letting any MCP-compatible AI assistant query Active Directory ACLs in plain English — no SQL, no custom scripts.

---

## Why this exists

DACLSearch is great at the hard part: pulling every ACE out of Active Directory and dropping it into a structured SQLite database. What it doesn't have is a programmatic query layer you can drive from an AI assistant or automation pipeline.

This MCP server fills that gap. Once you've run `daclsearch dump` and have a `.db` file, you can point Claude (or any other MCP client) at it and ask things like:

- *"Who has WriteDACL on Domain Admins?"*
- *"What can the helpdesk group do?"*
- *"Find any accounts with DCSync rights."*
- *"Generate an HTML report of all denied ACEs."*

The AI handles the natural language interpretation; the server handles the database queries. You get answers in seconds instead of digging through an interactive TUI or writing SQL by hand.

---

## What it actually does

| Capability | Details |
|-----------|---------|
| Natural language ACL search | Extracts object/principal names and attack-pattern keywords from your question, routes to the right SQL query |
| Object ACL lookup | All ACEs on a named AD object — who has what right to it |
| Principal permission lookup | All ACEs where a user or group is the subject |
| Principal enumeration | List users, groups, computers, OUs with optional class filter |
| Report export | Full ACL dumps as CSV, HTML (dark-theme, offline-ready), or JSON |
| Default database via environment | Set `DACLSEARCH_DB` in MCP config to avoid passing `db_path` on every call |
| Multi-database support | Pass any `db_path` per call to query multiple databases in one session |
| Read-only safety | Opens every database with SQLite `mode=ro` — the server cannot modify your data |

---

## Prerequisites

- Python 3.10 or later
- A DACLSearch `.db` file (produced by `daclsearch dump`)
- `pip install fastmcp`

---

## Quick start

```bash
# Install
pip install fastmcp

# Run (stdio transport — works with Claude Desktop and most MCP clients)
fastmcp run /opt/claude/Daclsearch-MCP/server.py
```

### Claude Desktop

Add to `~/.config/claude/claude_desktop_config.json` (Linux) or the equivalent on your OS:

```json
{
  "mcpServers": {
    "daclsearch": {
      "command": "python",
      "args": ["/opt/claude/Daclsearch-MCP/server.py"],
      "env": {
        "DACLSEARCH_DB": "/path/to/your/daclsearch.db"
      }
    }
  }
}
```

Restart Claude Desktop. The DACLSearch tools will appear automatically.

### Claude Code (CLI)

```bash
claude mcp add daclsearch python /opt/claude/Daclsearch-MCP/server.py
```

---

## Configuration

### Setting a default database

If you work with a single DACLSearch database most of the time, set `DACLSEARCH_DB` in the MCP config's `env` section. All tools will use it as the default when no `db_path` is provided.

**In Claude Desktop**, update your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "daclsearch": {
      "command": "python",
      "args": ["/opt/claude/Daclsearch-MCP/server.py"],
      "env": {
        "DACLSEARCH_DB": "/opt/daclsearch/corp.db"
      }
    }
  }
}
```

### When a default is set

You can omit `db_path` from tool calls:

```
Who has WriteDACL on Domain Admins?

What can the helpdesk group do?

Generate a JSON report filtered to principal "Domain Admins"
```

### Without a default

Pass `db_path` explicitly (or set `DACLSEARCH_DB` after startup):

```
Who has WriteDACL on Domain Admins? db_path=/opt/daclsearch/corp.db

Get the ACL for Domain Admins from /opt/daclsearch/prod.db
```

### Multiple databases

Even with a default set, you can override it per call by providing `db_path`. This lets you query different databases in a single session without restarting the server.

---

## Tool reference

### `search_acls`

Natural language ACL search. Extracts intent from your question and routes to the right query.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | Yes | Plain English question about AD permissions |
| `db_path` | string | No | Path to DACLSearch SQLite database (uses `DACLSEARCH_DB` if omitted) |

**Example questions:**
- `"who has GenericAll on Domain Admins?"` → object-centric query with Generic All mask filter
- `"what can helpdesk do?"` → principal-centric query for helpdesk group
- `"show DCSync rights"` → Extended Right ACEs across all objects
- `"who owns krbtgt?"` → ownership lookup

---

### `get_object_acl`

All ACEs on a specific AD object — everyone who has any right to it.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `object_name` | string | Yes | Name or partial name of the target object |
| `db_path` | string | No | Path to DACLSearch SQLite database (uses `DACLSEARCH_DB` if omitted) |

**Example:** `get_object_acl("Domain Admins")` (if default DB is set)

**Example with explicit path:** `get_object_acl("Domain Admins", "/opt/daclsearch/corp.db")`

---

### `get_principal_permissions`

All ACEs where a user or group is the principal — everything they can do.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `principal_name` | string | Yes | — | Name or partial name of the principal |
| `db_path` | string | No | `DACLSEARCH_DB` env var | Path to DACLSearch SQLite database |
| `ace_type` | string | No | `"all"` | `"all"`, `"allowed"`, or `"denied"` |

**Example:** `get_principal_permissions("helpdesk")` (if default DB is set)

**Example with explicit path:** `get_principal_permissions("helpdesk", "/opt/daclsearch/corp.db", ace_type="allowed")`

---

### `list_principals`

Enumerate AD objects in the database.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `db_path` | string | No | `DACLSEARCH_DB` env var | Path to DACLSearch SQLite database |
| `object_class` | string | No | `null` | Filter: `"user"`, `"group"`, `"computer"`, `"organizationalUnit"`, etc. |

**Example:** `list_principals()` (if default DB is set, no filters)

**Example with filter:** `list_principals(object_class="computer")` (if default DB is set)

**Example with explicit path:** `list_principals("/opt/daclsearch/corp.db", object_class="computer")`

---

### `generate_report`

Export ACLs as a formatted string (save it to a file yourself).

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `db_path` | string | No | `DACLSEARCH_DB` env var | Path to DACLSearch SQLite database |
| `output_format` | string | Yes | — | `"csv"`, `"html"`, or `"json"` |
| `principal_filter` | string | No | `null` | Optional: restrict to a specific principal (partial match) |
| `object_filter` | string | No | `null` | Optional: restrict to a specific object (partial match) |

**HTML output** is a self-contained dark-themed page with sticky headers and colour-coded Allow/Deny rows. No internet connection required — good for air-gapped environments.

**Warning:** On large databases, omitting both filters will produce very large output. Filter first, export second.

---

### `get_principal_groups`

Reverse membership lookup — what groups a principal belongs to (direct only).

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `principal_name` | string | Yes | — | Name or partial name of the user/computer/group |
| `db_path` | string | No | `DACLSEARCH_DB` | Path to database |

**Example:** `get_principal_groups("jsmith")` (if default DB is set)

**Example with explicit path:** `get_principal_groups("Administrator", "/opt/daclsearch/corp.db")`

---

### `get_nested_group_members`

Recursive transitive group membership via SQL CTE. Returns all members reachable through nested group chains, with `depth` and `via_path` fields showing how they were reached. Depth limit: 20.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `group_name` | string | Yes | — | Name or partial name of the group |
| `db_path` | string | No | `DACLSEARCH_DB` | Path to database |

**Example:** `get_nested_group_members("Domain Admins")` (if default DB is set)

**Example with explicit path:** `get_nested_group_members("Enterprise Admins", "/opt/daclsearch/corp.db")`

---

### `database_info`

Database discovery — returns row counts per table, available object classes, ACE types, object types, and top 10 principals by ACE count.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `db_path` | string | No | `DACLSEARCH_DB` | Path to database |

**Example:** `database_info()` (if default DB is set)

**Example with explicit path:** `database_info("/opt/daclsearch/corp.db")`

---

## Example prompts

These are real things you can type in Claude when the server is connected. The first set assumes `DACLSEARCH_DB` is set in the MCP config; the second set shows explicit `db_path` usage:

**With a default database set:**

```
Who has WriteDACL on Domain Admins?

What can the helpdesk group do?

Show me all denied ACEs

List all computer objects in the database

Generate a JSON report filtered to principal "Domain Admins"

Export an HTML ACL report for krbtgt, save it to /tmp/krbtgt_acl.html

Who has DCSync rights?

Who owns the Administrator account?

What groups is jsmith in?

Show group membership for Administrator

Who has effective membership in Domain Admins?

List all transitive members of Enterprise Admins

What is in this database?

Give me a summary of the database

How many ACEs are there?
```

**With explicit db_path (or when default is not set):**

```
Who has WriteDACL on Domain Admins? db_path=/opt/daclsearch/corp.db

What can the helpdesk group do in /opt/daclsearch/corp.db?

Show me all denied ACEs in /opt/daclsearch/corp.db

List all computer objects in the database at /opt/daclsearch/corp.db

Generate a JSON report filtered to principal "Domain Admins" from /opt/daclsearch/corp.db

Export an HTML ACL report for krbtgt from /opt/daclsearch/corp.db, save it to /tmp/krbtgt_acl.html

Who has DCSync rights in /opt/daclsearch/corp.db?

Who owns the Administrator account? db_path=/opt/daclsearch/corp.db

What groups is jsmith in from /opt/daclsearch/corp.db?

Who has effective membership in Domain Admins in /opt/daclsearch/corp.db?

List all transitive members of Enterprise Admins from /opt/daclsearch/corp.db

What is in the database at /opt/daclsearch/corp.db?
```

---

## Access mask reference

| Hex | Right name |
|-----|-----------|
| `0x00000001` | Create Child |
| `0x00000002` | Delete Child |
| `0x00000004` | List Children |
| `0x00000008` | Self |
| `0x00000010` | Read Prop |
| `0x00000020` | Write Prop |
| `0x00000040` | Delete Tree |
| `0x00000080` | List Object |
| `0x00000100` | Extended Right |
| `0x00010000` | Delete |
| `0x00020000` | Read Control |
| `0x00040000` | Write Dacl |
| `0x00080000` | Write Owner |
| `0x00100000` | Synchronize |
| `0x000F01FF` | Generic All |

ACE flags are decoded the same way: the raw `flags` integer is broken down into `Object Inherit`, `Container Inherit`, `Inherited`, etc.

---

## Attack patterns recognised by `search_acls`

The server recognises common AD attack-path keywords and maps them to the right mask filter automatically:

`dcsync`, `genericall`, `generic all`, `full control`, `writedacl`, `write dacl`, `writeowner`, `write owner`, `write prop`, `all extended rights`, `laps`, `shadow credentials`, `rbcd`, `add member`, `reset password`, `force change password`

---

## Security notes

- The server opens every database **read-only** (`sqlite3 URI mode=ro`). It cannot write to or corrupt your DACLSearch databases.
- The server does not connect to Active Directory. It only reads existing `.db` files.
- No credentials, hashes, or Kerberos tickets are ever passed through this server.
- Report output is returned as a string to the MCP client — nothing is written to disk by the server itself.

---

## Limitations

- `get_principal_groups` returns direct group membership only. For recursive group expansion (groups within groups), use `get_nested_group_members`.
- `get_nested_group_members` recursion depth is capped at 20 levels to prevent runaway queries on circular or deeply nested group hierarchies.
- DCSync detection uses `Extended Right` (mask `0x100`) across all object types. For definitive DCSync confirmation, cross-reference `object_type` values against the DS-Replication-* GUIDs in your schema.
- `search_acls` uses keyword/regex extraction, not NLP. Ambiguous queries fall back to treating the whole query as an object name search. Use `get_object_acl` or `get_principal_permissions` directly when precision matters.

---

## Project structure

```
Daclsearch-MCP/
├── server.py        — FastMCP server (all tools, flat structure)
├── requirements.txt — single dependency: fastmcp
└── README.md        — this file
```
