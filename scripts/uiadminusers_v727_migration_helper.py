#!/usr/bin/env python3

"""
Pelican v7.27 upgrade helper

Starting with Pelican v7.27, Server.UIAdminUsers entries must be usernames.
Entries that are OIDC subjects (for example CILogon identifiers such as
http://cilogon.org/serverA/users/12345) or internal user IDs no longer
grant admin access, so those admins would lose the web UI after the upgrade.

This script tells you what to change before you upgrade. It reads the
server's configuration and its user database, works out which username
each entry refers to, and prints a replacement Server.UIAdminUsers block
plus the entries you must settle by hand. It also warns about user rows
that would stop v7.27.0 from starting (duplicate usernames, issue #3824).
It only reads; it never changes the configuration or the database.

HOW TO RUN

Run it on the server host, as the same user and with the same environment
as the server, so that it sees the same configuration.

  python3 uiadminusers_v727_migration_helper.py

  Other options: see --help

READING THE OUTPUT

Each entry is tagged (KEEP, REPLACE, NO MATCH, RETIRED, ...) with the
reason, followed by a "Suggested configuration for v7.27" block you can
paste into your configuration and a list of entries that need manual
attention. Exit status: 0 nothing to change, 1 changes or manual attention
needed, 2 error.

Needs Python 3.6 or newer. PyYAML is optional: without it, settings saved
from the web UI (Server.WebConfigFile) are not read and a warning says so.
"""

import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:
    yaml = None

# A row of the users table, keyed by column name.
Row = Dict[str, Any]

# Sub prefix of rows written by the GHSA-rpfr-x88x-xwcw mitigation script.
# No identity provider asserts such a sub, so nobody can log in as the row.
PLACEHOLDER_SUB_PREFIX = "__PROTECTIVE_PLACEHOLDER__"

# The built-in admin account is granted admin regardless of configuration.
BUILTIN_ADMIN = "admin"

DUPLICATE_ISSUE = "issue #3824"
DUPLICATE_FIX = "PR #3828"
DUPLICATE_FIX_RELEASE = "v7.27.1"

# Index created by the last of v7.27's users-table migrations
# (20260812000000_global_unique_username.sql); the server's own
# duplicate-username code looks for the same name.
# A users table with the deleted_at column but without this index was
# left by a v7.27 migration that stopped before that step,
# which is what issue #3824 does.
UNIQUE_USERNAME_INDEX = "idx_user_username_live"

# States of the users table's v7.27 migration, as load_users reports them.
NOT_MIGRATED = "not migrated"
FULLY_MIGRATED = "fully migrated"
PARTLY_MIGRATED = "stopped before the unique-username step"

SCRIPT_NAME = "uiadminusers_v727_migration_helper.py"

# Configuration files that the Pelican and OSDF RPMs install for their
# systemd units. Each unit starts the server with `--config <this file>`
# after loading /etc/sysconfig/<unit>, so a `config dump` run without
# `--config` reads a different configuration on such a host.
PACKAGED_CONFIG_DIR = "/etc/pelican"
PACKAGED_UNITS = [
    f"{prefix}-{server_type}"
    for prefix in ("pelican", "osdf")
    for server_type in ("origin", "cache", "director", "registry")
]

# Mirrors identifierPattern in database/identifiers.go (v7.27).
# v7.27 does not create users whose usernames fail it,
# but usernames from v7.26 are kept as they are.
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{1,63}$")

# Leading date and time of the formats SQLite and GORM write, e.g.
# "2026-10-16 00:00:00", "2026-10-16T00:00:00.123Z", "2026-10-16 00:00:00+00:00".
TIMESTAMP_PATTERN = re.compile(r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2}(?:\.\d+)?)")


def is_valid_identifier(name: str) -> bool:
    return bool(IDENTIFIER_PATTERN.fullmatch(name)) and ".." not in name


def fail(message: str) -> None:
    # Flush first so that the error follows the progress lines
    # when stdout is a pipe or a file.
    sys.stdout.flush()
    print(f"Error: {message}", file=sys.stderr)


def parse_config_dump(text: str) -> Dict[str, Any]:
    """
    Extracts the JSON object from `config dump -o json` output,
    skipping any log lines that precede it.
    """
    decoder = json.JSONDecoder()
    start = text.find("{")
    while start != -1:
        try:
            obj, _ = decoder.raw_decode(text, start)
            if isinstance(obj, dict) and "Server" in obj:
                return obj
        except json.JSONDecodeError:
            pass
        start = text.find("{", start + 1)
    raise ValueError("no configuration JSON object found in the output")


def load_config(args: argparse.Namespace, pelican_args: List[str]) -> Dict[str, Any]:
    if args.config_json:
        with open(args.config_json, encoding="utf-8") as f:
            return parse_config_dump(f.read())

    cmd = [args.pelican, "config", "dump", "-o", "json"] + pelican_args
    try:
        # Avoids capture_output and text, which need Python 3.7, so that
        # the script runs on EL8's Python 3.6.
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=False,
        )
    except OSError as e:
        raise RuntimeError(f"failed to run {args.pelican}: {e}") from e
    if proc.returncode != 0:
        raise RuntimeError(
            f"{' '.join(cmd)} exited with status {proc.returncode}:\n{proc.stderr.strip()}"
        )
    return parse_config_dump(proc.stdout)


def warn_if_packaged_config_ignored(pelican_args: List[str]) -> None:
    """
    Warns when the host has the RPMs' per-unit configuration files but
    `config dump` is about to read the default location instead.
    That would hide a Server.UIAdminUsers set in the unit file or in
    /etc/sysconfig/<unit>, and the report would wrongly say that nothing
    needs to change.
    """
    for arg in pelican_args:
        # --config names the file; --service (v7.27+) picks the unit file.
        if arg in ("--config", "--service", "-s") or arg.startswith(("--config=", "--service=")):
            return
    if any(os.environ.get(f"{prefix}_CONFIG") for prefix in ("PELICAN", "OSDF", "STASH")):
        return
    found = [
        unit
        for unit in PACKAGED_UNITS
        if os.path.exists(os.path.join(PACKAGED_CONFIG_DIR, unit + ".yaml"))
    ]
    if not found:
        return

    unit = found[0] if len(found) == 1 else "<unit>"
    prog = os.path.basename(sys.argv[0])
    if prog in ("", "-"):
        prog = SCRIPT_NAME
    lines = [
        "Warning: no --config was given, so the configuration is read from the default "
        "location, not from the packaged unit file(s) on this host:",
    ]
    lines += [f"  {os.path.join(PACKAGED_CONFIG_DIR, u + '.yaml')}" for u in found]
    lines += [
        "If the server runs from one of the packaged systemd units, rerun as",
        f"  set -a; . /etc/sysconfig/{unit} 2>/dev/null; set +a",
        f"  python3 {prog} -- --config {PACKAGED_CONFIG_DIR}/{unit}.yaml",
        "or the report may miss the Server.UIAdminUsers the server actually uses.",
    ]
    print("\n".join(lines), file=sys.stderr)


def flatten_keys(doc: Any, prefix: str = "") -> Dict[str, Any]:
    """
    Flattens a YAML document to lowercase dotted keys, the way the server
    (viper) does, so that both `Server: {UIAdminUsers: ...}` and
    `Server.UIAdminUsers: ...` yield the key "server.uiadminusers".
    """
    flat = {}
    if isinstance(doc, dict):
        for key, value in doc.items():
            full = prefix + str(key).lower()
            if isinstance(value, dict):
                flat.update(flatten_keys(value, full + "."))
            else:
                flat[full] = value
    return flat


def load_web_config(path: Optional[str]) -> Dict[str, Any]:
    """
    Returns the web UI's configuration file as lowercase dotted keys
    (the server matches them case-insensitively),
    with null values omitted (the server treats them as unset).
    """
    if not path or not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if not text.strip():
        return {}
    if yaml is None:
        print(
            f"Warning: PyYAML is not installed, so {path} was not read; "
            "settings saved from the web UI may be missing.",
            file=sys.stderr,
        )
        return {}

    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ValueError(f"failed to parse {path}: {e}") from e
    return {k: v for k, v in flatten_keys(doc).items() if v is not None}


def normalize_entries(value: Any) -> List[str]:
    """
    Returns Server.UIAdminUsers as a list of strings.
    The server reads a plain string as a whitespace-separated list.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return value.split()
    if isinstance(value, list):
        return [str(entry) for entry in value]
    raise ValueError(f"Server.UIAdminUsers has an unexpected value: {value!r}")


def load_users(db_path: str) -> Tuple[List[Row], List[Row], str]:
    """
    Returns the live rows and the soft-deleted rows of the users table,
    and the state of the table's v7.27 migration: NOT_MIGRATED if it has
    no deleted_at column, FULLY_MIGRATED if it also has the unique-username
    index, and PARTLY_MIGRATED if it has the column but not the index
    (v7.27's migrations each commit on their own, so a failure in the
    unique-username step leaves the earlier steps in place).
    """
    uri = "file:" + urllib.parse.quote(db_path) + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
        if not columns:
            raise RuntimeError(f"{db_path} has no users table")
        if "deleted_at" not in columns:
            migration = NOT_MIGRATED
        else:
            indexes = {row[1] for row in conn.execute("PRAGMA index_list(users)")}
            migration = FULLY_MIGRATED if UNIQUE_USERNAME_INDEX in indexes else PARTLY_MIGRATED
        fields = ["id", "username", "sub", "issuer", "created_at"]
        fields += [c for c in ("last_login_at", "deleted_at") if c in columns]
        # The same order as the duplicate-username cleanup reads rows in,
        # so that ties in rank_rows resolve the same way.
        query = f"SELECT {', '.join(fields)} FROM users ORDER BY username, id"
        live, deleted = [], []
        for values in conn.execute(query):
            row = dict(zip(fields, values))
            row.setdefault("last_login_at", None)
            row.setdefault("deleted_at", None)
            (deleted if row["deleted_at"] else live).append(row)
    finally:
        conn.close()
    return live, deleted, migration


def is_placeholder(row: Row) -> bool:
    return str(row["sub"]).startswith(PLACEHOLDER_SUB_PREFIX)


def describe(row: Row, with_time: bool = False) -> str:
    text = f"id={row['id']} username={row['username']!r} issuer={row['issuer']!r} sub={row['sub']!r}"
    if with_time:
        text += f" created={row['created_at']}"
        if row["last_login_at"]:
            text += f" last_login={row['last_login_at']}"
    if row["deleted_at"]:
        text += f" deleted={row['deleted_at']}"
    return text


def timestamp_key(value: Any) -> str:
    """Normalizes a stored timestamp for comparison; unknown formats compare as text."""
    if not value:
        return ""
    match = TIMESTAMP_PATTERN.match(str(value))
    if match:
        return match.group(1) + " " + match.group(2)
    return str(value)


def rank_rows(rows: List[Row], local_issuer: str) -> List[Row]:
    """
    Orders rows the way the duplicate-username cleanup of PR #3828 does,
    survivor first: the row on the current Server.ExternalWebUrl, then a
    non-placeholder, then the latest login, then the newest row.
    Ties keep the table order (username, id).
    """
    ranked = list(rows)
    # Stable sorts, least significant key first.
    ranked.sort(key=lambda r: timestamp_key(r["created_at"]), reverse=True)
    ranked.sort(key=lambda r: timestamp_key(r["last_login_at"]), reverse=True)
    ranked.sort(
        key=lambda r: (
            not (local_issuer and r["issuer"] == local_issuer),
            is_placeholder(r),
            r["last_login_at"] is None,
        )
    )
    return ranked


def predict_cleanup(
    live_rows: List[Row], local_issuer: str
) -> Dict[str, Tuple[Optional[Row], List[Row]]]:
    """
    Predicts what the duplicate-username cleanup does to each username
    it touches: the row it keeps (None when it creates a fresh built-in
    admin row instead) and the rows it soft-deletes.

    Only a row whose sub is "admin" can stay the built-in admin;
    every other row named "admin" is retired even if it is the only one.
    """
    by_username: Dict[str, List[Row]] = {}
    for row in live_rows:
        by_username.setdefault(row["username"], []).append(row)

    cleanup = {}
    for username, rows in by_username.items():
        if username == BUILTIN_ADMIN:
            candidates = rank_rows([r for r in rows if r["sub"] == BUILTIN_ADMIN], local_issuer)
            kept = candidates[0] if candidates else None
            if len(rows) > 1 or kept is None:
                cleanup[username] = (kept, [r for r in rows if r is not kept])
        elif len(rows) > 1:
            ranked = rank_rows(rows, local_issuer)
            cleanup[username] = (ranked[0], ranked[1:])
    return cleanup


def print_cleanup(
    cleanup: Dict[str, Tuple[Optional[Row], List[Row]]], local_issuer: str
) -> None:
    duplicated = [
        u for u, (kept, retired) in cleanup.items() if len(retired) + (kept is not None) > 1
    ]
    print("User rows the v7.27 upgrade cannot keep as they are:")
    if duplicated:
        print(
            "  Usernames held by more than one live row make v7.27.0 refuse to start "
            f"({DUPLICATE_ISSUE}: the global-unique-username migration fails)."
        )
    print(
        f"  The fix in {DUPLICATE_FIX_RELEASE} ({DUPLICATE_FIX}) keeps one row per username and "
        "soft-deletes the others, which re-enroll as new users at their next login."
    )
    if local_issuer:
        print(f"  Predicted outcome, preferring rows on Server.ExternalWebUrl {local_issuer!r}:")
    else:
        print("  Predicted outcome (Server.ExternalWebUrl is unknown, so it is not preferred):")
    for username in sorted(cleanup):
        kept, retired = cleanup[username]
        print(f"  {username!r}:")
        if kept is not None:
            print(f"    keep    {describe(kept, with_time=True)}")
        for row in retired:
            print(f"    retire  {describe(row, with_time=True)}")
        if username != BUILTIN_ADMIN:
            continue
        if kept is None:
            print(
                "    no row has sub 'admin', so v7.27.0 cannot create its built-in admin "
                f"(password login fails); {DUPLICATE_FIX_RELEASE} and later create a fresh row"
            )
        elif local_issuer and kept["issuer"] != local_issuer:
            print(
                "    the kept row is not on the current Server.ExternalWebUrl, so v7.27.0 cannot "
                "create its built-in admin there (password login fails); "
                f"{DUPLICATE_FIX_RELEASE} and later move the row to {local_issuer!r}"
            )
    print(
        "  To resolve by hand before upgrading to v7.27.0: delete placeholder rows, rename the other "
        "rows marked retire\n  (e.g. UPDATE users SET username = username || '-' || id WHERE id = '...'), "
        "and make sure the kept 'admin' row\n  has the current Server.ExternalWebUrl as its issuer. "
        "Back up the database first; never delete a real user's row."
    )
    print()


def classify(
    entry: str,
    real_rows: List[Row],
    placeholder_rows: List[Row],
    deleted_rows: List[Row],
    by_username: Dict[str, List[Row]],
    cleanup: Dict[str, Tuple[Optional[Row], List[Row]]],
) -> Tuple[str, List[str], List[str], bool]:
    """
    Resolves one Server.UIAdminUsers entry against the users table.

    Returns (verdict, notes, usernames, attention),
    where `usernames` are the values that should replace the entry in v7.27
    and `attention` says whether the operator must resolve something by hand.
    """
    notes: List[str] = []
    usernames: List[str] = []
    attention = False

    if entry == BUILTIN_ADMIN:
        notes.append("built-in admin account; still an admin in v7.27")
        if BUILTIN_ADMIN in cleanup:
            notes.append("the built-in admin row changes at the upgrade (see the user-row section above)")
        return "KEEP", notes, [entry], False

    name_rows = by_username.get(entry, [])
    if len(name_rows) == 1:
        notes.append(f"matches the username of {describe(name_rows[0])}")
        usernames.append(entry)
        if entry in cleanup:
            # A placeholder row shares the username; the real row is predicted to win.
            notes.append("a placeholder row also holds this username (see the user-row section above)")
    elif len(name_rows) > 1:
        notes.append(f"matches the username of {len(name_rows)} live rows:")
        notes.extend("  " + describe(r) for r in name_rows)
        kept, _ = cleanup[entry]
        notes.append(
            f"only the row predicted to survive the cleanup ({kept['id']}) keeps this username; "
            "the others re-enroll under a new username, which this entry does not match "
            "(see the user-row section above)"
        )
        usernames.append(entry)
        attention = True

    # Matches by user ID or OIDC subject, grouped by username
    # so that rows sharing a username are discussed once.
    matched: Dict[str, List[Row]] = {}
    for row in real_rows:
        if entry in (row["id"], row["sub"]) and row["username"] != entry:
            matched.setdefault(row["username"], []).append(row)
    for username, rows in matched.items():
        for row in rows:
            field = "id" if row["id"] == entry else "sub"
            notes.append(f"matches the {field} of {describe(row)}")
        if username not in cleanup:
            usernames.append(username)
            continue
        kept, _ = cleanup[username]
        attention = True
        if kept is not None and any(r["id"] == kept["id"] for r in rows):
            notes.append(
                f"username {username!r} is held by more than one live row, but the matched row "
                f"{kept['id']} is predicted to survive the cleanup, so the entry becomes {username!r} "
                "(see the user-row section above)"
            )
            if len({r["issuer"] for r in rows}) > 1:
                notes.append(
                    "these rows share one subject under different issuers, and only the row under "
                    "the issuer the user logs in with today is reachable; if the predicted survivor "
                    "is not that row, the reachable account re-enrolls under a new username instead"
                )
            usernames.append(username)
        else:
            notes.append(
                f"username {username!r} is held by more than one live row, and the matched row is "
                "predicted to be soft-deleted; that account re-enrolls under a new username at its "
                "next login, so replace this entry by hand after that login "
                "(see the user-row section above)"
            )

    if not name_rows and not matched:
        retired = [r for r in deleted_rows if entry in (r["username"], r["id"], r["sub"])]
        if retired:
            for row in retired:
                notes.append(f"matches only the soft-deleted row {describe(row)}")
            notes.append(
                "a soft-deleted account re-enrolls as a new user at its next login, "
                "under its old username if that is still free, otherwise under a new one"
            )
            taken = set(by_username) | {r["username"] for r in placeholder_rows}
            free = []
            for row in retired:
                if row["username"] not in taken and row["username"] not in free:
                    free.append(row["username"])
            if free:
                notes.append("kept provisionally; confirm the username after the user's next login")
                return "RETIRED", notes, free, True
            notes.append(
                "the old username is taken, so the account gets a new username; "
                "replace this entry by hand after the user's next login"
            )
            return "RETIRED", notes, [], True
        if not is_valid_identifier(entry):
            notes.append("matches no user")
            notes.append(
                "not a valid v7.27 username, so it can never grant admin in v7.27"
            )
            return "NO MATCH", notes, [], True
        if any(r["username"] == entry for r in placeholder_rows):
            # v7.27 usernames are unique across issuers,
            # so the placeholder keeps any real user from taking this one.
            notes.append(
                "matches no user, and a GHSA-rpfr-x88x-xwcw placeholder row holds this username"
            )
            notes.append(
                "no user can take this username in v7.27 until the placeholder row is removed"
            )
            return "NO MATCH", notes, [entry], True
        notes.append("matches no user (the user may not have logged in yet)")
        notes.append(
            "kept as a username; if it is an OIDC subject or user ID instead, replace it by hand"
        )
        return "NO MATCH", notes, [entry], False

    for username in usernames:
        if not is_valid_identifier(username):
            notes.append(
                f"username {username!r} is not a valid v7.27 username; "
                "v7.27 still matches it but logs an error saying that it cannot"
            )

    if attention and not usernames:
        verdict = "MANUAL"
    elif usernames == [entry]:
        verdict = "KEEP"
    elif name_rows:
        verdict = "KEEP+ADD"
    else:
        verdict = "REPLACE"
    if attention and usernames:
        verdict += " (PARTIAL)"
    return verdict, notes, usernames, attention


def main() -> int:
    argv = sys.argv[1:]
    pelican_args = []
    if "--" in argv:
        split = argv.index("--")
        argv, pelican_args = argv[:split], argv[split + 1 :]

    parser = argparse.ArgumentParser(
        description="Report how Server.UIAdminUsers must change for Pelican v7.27.",
        epilog="Arguments after `--` are passed through to `pelican-server config dump`.",
        # Otherwise, `--config` without a preceding `--`
        # is taken as `--config-json`.
        allow_abbrev=False,
    )
    parser.add_argument(
        "--pelican",
        help="Path to the pelican-server binary (default: %(default)s)",
        default="pelican-server",
    )
    parser.add_argument(
        "--config-json",
        help="Read the output of `pelican-server config dump -o json` from this file "
        "instead of running pelican-server",
    )
    parser.add_argument(
        "--db",
        help="Path to the server's SQLite database (default: Server.DbLocation)",
    )
    args = parser.parse_args(argv)

    try:
        if not args.config_json:
            warn_if_packaged_config_ignored(pelican_args)
        cfg = load_config(args, pelican_args)
        server = cfg.get("Server") or {}
        web_config_path = server.get("WebConfigFile")
        web = load_web_config(web_config_path)
        entries = normalize_entries(web.get("server.uiadminusers", server.get("UIAdminUsers")))
        db_path = args.db or web.get("server.dblocation", server.get("DbLocation"))
        local_issuer = str(web.get("server.externalweburl", server.get("ExternalWebUrl")) or "")

        print(f"Server.UIAdminUsers: {json.dumps(entries)}")
        if "server.uiadminusers" in web:
            print(
                f"(set from the web UI in {web_config_path}, which the server applies over "
                "every other configuration source, including environment variables)"
            )
        if not entries:
            print("Server.UIAdminUsers is not set; nothing needs to change.")
            return 0
        if not db_path:
            raise RuntimeError("Server.DbLocation is not set; pass --db")

        print(f"Database: {db_path}")
        live_rows, deleted_rows, migration = load_users(db_path)
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as e:
        fail(str(e))
        return 2

    if migration == FULLY_MIGRATED:
        print("Note: the database has been fully migrated to v7.27.")
    elif migration == PARTLY_MIGRATED:
        print(
            "Note: the v7.27 migration of the database stopped before the unique-username step "
            f"(the users table has the deleted_at column but not the {UNIQUE_USERNAME_INDEX} index)."
        )
    print()

    real_rows = [r for r in live_rows if not is_placeholder(r)]
    placeholder_rows = [r for r in live_rows if is_placeholder(r)]
    by_username: Dict[str, List[Row]] = {}
    for row in real_rows:
        by_username.setdefault(row["username"], []).append(row)

    cleanup = predict_cleanup(live_rows, local_issuer)
    if cleanup:
        print_cleanup(cleanup, local_issuer)

    unique_entries: List[str] = []
    repeated: List[str] = []
    for entry in entries:
        if entry in unique_entries:
            if entry not in repeated:
                repeated.append(entry)
        else:
            unique_entries.append(entry)

    suggested: List[str] = []
    needs_attention: List[str] = []
    for entry in unique_entries:
        verdict, notes, usernames, attention = classify(
            entry, real_rows, placeholder_rows, deleted_rows, by_username, cleanup
        )
        print(f"[{verdict}] {entry}")
        for note in notes:
            print(f"    {note}")
        if usernames and usernames != [entry]:
            print(f"    -> use: {', '.join(usernames)}")
        print()
        for username in usernames:
            if username not in suggested:
                suggested.append(username)
        if attention:
            needs_attention.append(entry)

    print("Suggested configuration for v7.27:")
    print()
    print("Server:")
    print("  UIAdminUsers:")
    for username in suggested:
        print(f"    - {json.dumps(username)}")
    print()

    if repeated:
        print(f"Entries listed more than once: {', '.join(repeated)}; each is needed only once.")
        print()
    if needs_attention:
        print("Entries that need manual attention (see above):")
        for entry in needs_attention:
            print(f"  - {entry}")
        print()
    if cleanup:
        print(
            "Resolve the user rows listed above before upgrading to v7.27.0, "
            f"or upgrade straight to {DUPLICATE_FIX_RELEASE} or later, which includes {DUPLICATE_FIX}."
        )
        print()

    if suggested == entries and not needs_attention and not cleanup:
        print("No changes are needed.")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
