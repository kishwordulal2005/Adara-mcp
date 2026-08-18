#!/usr/bin/env python3
"""
cve_enrichment.py — Live CVE Lookup Module
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Queries every source in parallel for a CVE or service/version:

  1. Vulners.com       — /api/v3/search/id/ + lucene software search
  2. NVD / NIST        — REST API v2.0 (free, optional key: 5 → 50 req/30s)
  3. Exploit-DB        — searchsploit CLI (Kali) + live /search endpoint
                         + official CSV mirror (47k entries)
  4. PoC repos         — nomi-sec/PoC-in-GitHub, ycdxsb, trickest/cve,
                         GitHub Search API (star-sorted)
  5. Sploitus          — RSS exploit feed (latest entries only)
  6. Metasploit+Nuclei — rapid7 module metadata + projectdiscovery cves.json
  7. Vulhub Docker     — pre-built vulnerable environments

Used by adara_mcp_server.py — registers lookup_cve, lookup_multiple_cves,
search_service_cves, search_service_cves_deep, enrich_scan_cves,
download_poc as MCP tools:

    from cve_enrichment import register_cve_tools
    register_cve_tools(mcp)

Standalone CLI:
    python3 cve_enrichment.py --cve CVE-2021-44228
    python3 cve_enrichment.py --poc CVE-2021-44228
    python3 cve_enrichment.py --software vsftpd --version 2.3.4

Config (env vars, no defaults baked into source):
    VULNERS_API_KEY  — required for Vulners ID + software lookups
    NVD_API_KEY      — optional; raises NVD limit 5 req/30s → 50 req/30s
    GITHUB_API_TOKEN — optional; raises GitHub API rate limits (10/min → 30/min)
"""

import asyncio
import csv
import json
import os
import re
import shutil
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx
from loguru import logger
from rich import box
from rich.console import Console
from rich.markup import escape as _markup_escape
from rich.table import Table

# Windows-safe console — cp1252/ISO-8859-1 terminals raise UnicodeEncodeError
# on characters outside the codepage; strip them before printing.
_SAFE_ENCODING = None
if sys.stdout.encoding and sys.stdout.encoding.upper() in ("CP1252", "ISO-8859-1", "WINDOWS-1252"):
    _SAFE_ENCODING = sys.stdout.encoding

def _ascii_safe(text: str) -> str:
    """Strip or replace characters that can't be encoded in the terminal
    codepage — including pipes/daemons where sys.stdout.encoding is None
    (an unsanitized print would raise UnicodeEncodeError mid-tool-call)."""
    enc = _SAFE_ENCODING or sys.stdout.encoding or "ascii"
    try:
        return text.encode(enc, errors='replace').decode(enc)
    except (LookupError, TypeError):
        return text

def _safe_print(*args, **kwargs):
    """Print with encoding-safe text."""
    safe_args = [_ascii_safe(str(a)) for a in args]
    print(*safe_args, **kwargs)

console = Console()
_orig_print = console.print
def _safe_console_print(*args, **kwargs):
    try:
        _orig_print(*args, **kwargs)
    except UnicodeEncodeError:
        safe_args = [_ascii_safe(str(a)) for a in args]
        print(*safe_args)
console.print = _safe_console_print

# ─────────────────────────────────────────────
# API keys (from environment only — never bake keys into source)
# ─────────────────────────────────────────────
VULNERS_API_KEY = os.environ.get("VULNERS_API_KEY", "")
NVD_API_KEY     = os.environ.get("NVD_API_KEY", "")
_GITHUB_TOKEN   = os.environ.get("GITHUB_API_TOKEN", "")

_warned_no_vulners_key = False
def _warn_no_vulners_key():
    """One-time warning — Vulners is skipped without a key, NVD still covers."""
    global _warned_no_vulners_key
    if not _warned_no_vulners_key:
        _warned_no_vulners_key = True
        logger.warning("VULNERS_API_KEY not set — Vulners lookups skipped (NVD covers). "
                       "export VULNERS_API_KEY=... to enable")

# ─────────────────────────────────────────────
# Rate-limit helpers
# ─────────────────────────────────────────────
_nvd_last_call  = 0.0
NVD_DELAY_NO_KEY  = 7.0   # 5 req/30s → safe delay
NVD_DELAY_WITH_KEY = 0.7  # 50 req/30s → safe delay
# FIX: rate limiter was race-prone — parallel lookups (asyncio.gather over
# many CVEs) all read the same _nvd_last_call, computed 0 wait, and bursted
# past NVD's 5 req/30s limit (HTTP 403 + temp IP ban). Lock makes check+wait
# atomic per event loop.
_nvd_rate_lock = asyncio.Lock()

async def _nvd_rate_limit():
    global _nvd_last_call
    delay = NVD_DELAY_WITH_KEY if NVD_API_KEY else NVD_DELAY_NO_KEY
    async with _nvd_rate_lock:
        wait = delay - (time.monotonic() - _nvd_last_call)
        if wait > 0:
            await asyncio.sleep(wait)
        _nvd_last_call = time.monotonic()


# ─────────────────────────────────────────────
# TTL cache — the Metasploit module DB (~1.5MB) and Nuclei cves.json
# (~35MB) get re-downloaded AND re-parsed on every lookup; a single
# lookup_cve_all fetches them twice (once in its own gather, once inside
# lookup_poc_all). 12h TTL keeps them fresh without the bandwidth burn.
# ─────────────────────────────────────────────
_CACHE_TTL   = 12 * 3600
_FAIL_TTL    = 300          # FIX: transient fetch failures are cached short-term
_CACHE_MAX   = 5000         # FIX: unbounded key growth (per-CVE EPSS/CPE keys)
_FETCH_FAILED = object()    # cached-failure marker (distinct from _MISS/None)
_cache:      Dict[str, Any]  = {}
_inflight:   Dict[str, Any]  = {}
_MISS        = object()   # sentinel: cached-negative (None) vs not-cached

def _cache_get(key: str, ttl: float = _CACHE_TTL):
    hit = _cache.get(key)
    if hit:
        entry_ttl = hit[2] if len(hit) > 2 else ttl
        if time.monotonic() - hit[0] < (entry_ttl or ttl):
            return hit[1]
    return _MISS

def _cache_put(key: str, value: Any, ttl: Optional[float] = None):
    _cache[key] = (time.monotonic(), value, ttl)
    # FIX: bound the cache — per-CVE EPSS/CPE keys accumulate forever
    # (resident set was growing without bound across a long engagement).
    # FIFO eviction of the oldest ~10% when over the cap.
    if len(_cache) > _CACHE_MAX:
        for k in list(_cache)[:_CACHE_MAX // 10]:
            _cache.pop(k, None)

async def _cached_fetch(key: str, fetcher, ttl: float = _CACHE_TTL,
                        fail_ttl: float = _FAIL_TTL):
    """Return cached value, or fetch once — concurrent callers await the
    same in-flight task instead of duplicating the request. Cache is only
    populated on success; failures leave no stale entry. The fetch task
    runs to completion even if every awaiter is cancelled (shield), and
    the inflight entry lives until the task finishes, so a timed-out
    caller can never trigger a re-download storm.
    FIX: fetch FAILURES are now cached (fail_ttl, default 5 min) — an
    outage of raw.githubusercontent/NVD previously re-triggered the same
    120s doomed fetch on EVERY lookup (each caller's budget expired on
    the shielded task → mass 'Lookup timed out' storms for the whole
    session). A cached failure re-raises without re-fetching."""
    hit = _cache_get(key, ttl)
    if hit is not _MISS:
        if hit is _FETCH_FAILED:
            raise RuntimeError(f"cached fetch failure for {key} (retry in ~{fail_ttl}s)")
        return hit
    task = _inflight.get(key)
    if task is not None:
        return await asyncio.shield(task)

    async def _run():
        try:
            val = await fetcher()
            _cache_put(key, val, ttl)
            return val
        except Exception as e:
            _cache_put(key, _FETCH_FAILED, fail_ttl)
            raise
        finally:
            _inflight.pop(key, None)

    task = asyncio.ensure_future(_run())
    _inflight[key] = task
    return await asyncio.shield(task)


# ─────────────────────────────────────────────
# Result dataclass
# ─────────────────────────────────────────────
@dataclass
class CVEResult:
    cve_id:       str
    description:  str = ""
    cvss_score:   Optional[float] = None
    cvss_severity: str = ""
    epss_score:   Optional[float] = None   # Vulners only
    published:    str = ""
    exploits:     List[Dict] = field(default_factory=list)
    references:   List[str]  = field(default_factory=list)
    wild_exploited: bool = False           # Vulners / NVD KEV
    cisa_kev:     bool = False             # NVD KEV catalog
    msf_module:   str = ""                 # Exploit-DB/searchsploit
    edb_ids:      List[str] = field(default_factory=list)
    source:       str = ""


# ─────────────────────────────────────────────
# 1. VULNERS.COM  (v3 with X-Api-Key header — 2026 update)
# ─────────────────────────────────────────────
async def lookup_vulners_cve(cve_id: str) -> Optional[CVEResult]:
    """
    Vulners v3 /search/id/ — requires X-Api-Key header (2026 change).
    Returns CVSS, EPSS, exploit references, wildExploited.
    If no key, returns None (NVD will cover).
    """
    if not VULNERS_API_KEY:
        _warn_no_vulners_key()
        return None

    url = "https://vulners.com/api/v3/search/id/"
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(url,
                params={"id": cve_id, "references": "true"},
                headers={"X-Api-Key": VULNERS_API_KEY})
            r.raise_for_status()
            data = r.json()
    except Exception as e:
        logger.warning(f"Vulners lookup failed for {cve_id}: {e}")
        return None

    if data.get("result") != "OK":
        return None

    docs = data.get("data", {}).get("documents", {})
    rec  = docs.get(cve_id) or next(iter(docs.values()), None)
    if not rec:
        return None

    # CVSS
    metrics = rec.get("metrics", {})
    cvss    = metrics.get("cvss", {})
    epss_list = metrics.get("epss", [{}])
    epss_val  = epss_list[0].get("epss") if epss_list else None

    # Exploit references live in the document's own references array
    # (data.references doesn't exist in the v3 /search/id/ schema)
    rec_refs = rec.get("references") or []
    exploits = []
    for ref in rec_refs:
        if ref.get("type") in ("exploit", "metasploit"):
            exploits.append({
                "id":    ref.get("id",""),
                "title": ref.get("title",""),
                "type":  ref.get("type",""),
            })

    return CVEResult(
        cve_id        = cve_id,
        description   = rec.get("description", rec.get("short_description", "")),
        cvss_score    = cvss.get("score"),
        cvss_severity = cvss.get("severity", ""),
        epss_score    = epss_val,
        published     = rec.get("published", ""),
        exploits      = exploits,
        references    = [r.get("href","") for r in rec_refs if r.get("href")][:5],
        wild_exploited = rec.get("exploitation", {}).get("wildExploited", False),
        source        = "vulners.com",
    )


async def search_vulners_software(software: str, version: str,
                                   max_results: int = 10) -> List[Dict]:
    """
    Search Vulners for CVEs matching a software name + version.
    Uses /api/v3/search/lucene with X-Api-Key header.
    If no API key, skips (NVD + GitHub PoC will cover).
    """
    if not VULNERS_API_KEY:
        _warn_no_vulners_key()
        return []

    url  = "https://vulners.com/api/v3/search/lucene/"
    query = f'"{software}" AND "{version}" type:cve order:cvss' if version else f'"{software}" type:cve order:cvss'
    body = {"query": query, "skip": 0, "size": max_results,
            "fields": ["id","title","description","cvss","cvelist","published"]}

    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.post(url, json=body,
                             headers={"X-Api-Key": VULNERS_API_KEY,
                                      "Content-Type": "application/json"})
            r.raise_for_status()
            data = r.json()
    except Exception as e:
        logger.warning(f"Vulners software search failed: {e}")
        return []

    if data.get("result") != "OK":
        return []

    raw   = data.get("data", {})
    items = raw.get("search", raw.get("vulnerabilities", []))
    results = []
    for item in items:
        src  = item.get("_source", item)
        cvss = src.get("cvss", src.get("metrics", {}).get("cvss", {}))
        results.append({
            "cve_id":      src.get("id",""),
            "title":       src.get("title",""),
            "description": (src.get("description") or "")[:300],
            "cvss_score":  cvss.get("score") if isinstance(cvss, dict) else cvss,
            "published":   src.get("published",""),
            "source":      "vulners.com",
        })
    return results


# ─────────────────────────────────────────────
# 2. NVD / NIST
# ─────────────────────────────────────────────
async def lookup_nvd_cve(cve_id: str) -> Optional[CVEResult]:
    """
    NVD REST API v2.0 — completely free, no key required.
    Optional free API key from nvd.nist.gov/developers/request-an-api-key
    raises rate limit from 5/30s → 50/30s.
    """
    await _nvd_rate_limit()
    url     = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers: Dict[str, str] = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get(url, headers=headers)
            r.raise_for_status()
            data = r.json()
    except Exception as e:
        logger.warning(f"NVD lookup failed for {cve_id}: {e}")
        return None

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None

    cve = vulns[0].get("cve", {})

    # English description
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

    # CVSS — prefer v3.1 → v3.0 → v2
    cvss_score    = None
    cvss_severity = ""
    for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        ml = cve.get("metrics", {}).get(mk, [])
        if ml:
            cv            = ml[0].get("cvssData", {})
            cvss_score    = cv.get("baseScore")
            cvss_severity = cv.get("baseSeverity", "")
            break

    cisa_kev = bool(cve.get("cisaExploitAdd"))
    refs     = [r.get("url","") for r in cve.get("references",[]) if r.get("url")]

    return CVEResult(
        cve_id        = cve_id,
        description   = desc,
        cvss_score    = cvss_score,
        cvss_severity = cvss_severity,
        published     = cve.get("published",""),
        references    = refs[:5],
        # FIX: KEV membership ≠ confirmed wild exploitation. NVD's
        # cisaExploitAdd only says CISA tracks it; wild_exploited is derived
        # exclusively from Vulners' exploitation.wildExploited (real exploit
        # activity data). KEV stays visible via its own cisa_kev flag.
        wild_exploited = False,
        cisa_kev      = cisa_kev,
        source        = "nvd.nist.gov",
    )


async def search_nvd_software(keyword: str, max_results: int = 10) -> List[Dict]:
    """NVD keyword search — free. Retries with version tokens stripped:
    keywordSearch ANDs every term, so "apache httpd 2.4.49" as a phrase
    matches nothing while "apache httpd" hits plenty."""
    results = await _nvd_keyword_search(keyword, max_results)
    if not results and " " in keyword and any(ch.isdigit() for ch in keyword):
        stripped = " ".join(t for t in keyword.split() if not re.search(r"\d", t))
        if stripped and stripped != keyword.strip():
            logger.debug(f"NVD keyword retry: {keyword!r} -> {stripped!r}")
            results = await _nvd_keyword_search(stripped, max_results)
    return results


async def _nvd_keyword_search(keyword: str, max_results: int) -> List[Dict]:
    await _nvd_rate_limit()
    url     = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage={max_results}"
    headers: Dict[str, str] = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get(url, headers=headers)
            r.raise_for_status()
            data = r.json()
    except Exception as e:
        logger.warning(f"NVD keyword search failed: {e}")
        return []

    results = []
    for entry in data.get("vulnerabilities", []):
        cve  = entry.get("cve", {})
        desc = next((d["value"] for d in cve.get("descriptions",[]) if d.get("lang")=="en"), "")
        cvss_score = None
        for mk in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
            ml = cve.get("metrics",{}).get(mk,[])
            if ml:
                cvss_score = ml[0].get("cvssData",{}).get("baseScore")
                break
        results.append({
            "cve_id":      cve.get("id",""),
            "description": desc[:300],
            "cvss_score":  cvss_score,
            "published":   cve.get("published",""),
            "cisa_kev":    bool(cve.get("cisaExploitAdd")),
            "source":      "nvd.nist.gov",
        })
    return results


# Vendor/product map for the NVD CPE dictionary (part:a). Falls back to a
# dictionary search when a software name isn't listed here.
_CPE_VENDOR_TABLE = {
    "openssh":   ("openbsd",   "openssh"),
    "apache":    ("apache",    "http_server"),
    "httpd":     ("apache",    "http_server"),
    "vsftpd":    ("vsftpd_project", "vsftpd"),
    "nginx":     ("nginx",     "nginx"),
    "samba":     ("samba",     "samba"),
    "dnsmasq":   ("the_kelleys","dnsmasq"),
    "bind":      ("isc",       "bind"),
    "proftpd":   ("proftpd",   "proftpd"),
    "exim":      ("exim",      "exim"),
    "postfix":   ("postfix",   "postfix"),
    "mysql":     ("oracle",    "mysql"),
    "mariadb":   ("mariadb",   "mariadb"),
    "php":       ("php",       "php"),
    "tomcat":    ("apache",    "tomcat"),
    "squid":     ("squid-cache","squid"),
    "openssl":   ("openssl",   "openssl"),
    "curl":      ("haxx",      "curl"),
    "redis":     ("redis",     "redis"),
    "bash":      ("gnu",       "bash"),
    "git":       ("git",       "git"),
    "java":      ("oracle",    "jdk"),
    "python":    ("python",    "python"),
    "docker":    ("docker",    "docker"),
    "kubernetes":("kubernetes","kubernetes"),
}


def _cpe_matches_for(vuln: Dict, product: str) -> List[Dict]:
    """All cpeMatch entries targeting the product in a vulnerability.
    NVD v2.0 uses criteria/cpe23Uri/cpeName as the CPE key, and the
    enumerated version lives inside that string (field 5)."""
    out = []
    for config in vuln.get("configurations", []):
        for node in config.get("nodes", []):
            for m in node.get("cpeMatch", []):
                uri = m.get("criteria") or m.get("cpe23Uri") or m.get("cpeName") or ""
                parts = uri.split(":")
                if len(parts) > 5 and parts[4] == product:
                    m2 = dict(m)
                    if not m2.get("version") and parts[5] not in ("*", "-"):
                        m2["version"] = parts[5]
                    out.append(m2)
    return out


def _ver_in_cpe_range(t: tuple, m: Dict) -> bool:
    """True if target version falls inside a cpeMatch entry's range.
    Explicit enumerated versions ('1.2') match exactly; '*' or '-' versions
    use the four versionStart/versionEnd bounds. No bounds + '*' = all
    versions; no bounds + explicit version = that version only."""
    ver = m.get("version", "*")
    explicit = ver not in ("*", "-")
    if explicit and _norm_version(ver) == t:
        return True
    start_i = m.get("versionStartIncluding")
    start_x = m.get("versionStartExcluding")
    end_i   = m.get("versionEndIncluding")
    end_x   = m.get("versionEndExcluding")
    has_bounds = any(v for v in (start_i, start_x, end_i, end_x))
    if explicit and not has_bounds:
        return False
    if start_i and _norm_version(start_i) != (0,) and t < _norm_version(start_i):
        return False
    if start_x and _norm_version(start_x) != (0,) and t <= _norm_version(start_x):
        return False
    if end_i and _norm_version(end_i) != (0,) and t > _norm_version(end_i):
        return False
    if end_x and _norm_version(end_x) != (0,) and t >= _norm_version(end_x):
        return False
    return True


async def _find_cpe_prefix(software: str) -> Optional[str]:
    """'openssh' -> 'cpe:2.3:a:openbsd:openssh' via table or CPE dictionary."""
    key = f"cpe_prefix:{software.lower()}"
    cached = _cache_get(key)
    if cached is not _MISS:
        # FIX: a cached failure marker must not be returned as a real prefix
        return None if cached is _FETCH_FAILED else cached
    parts = software.lower().split()
    # FIX: empty/whitespace software raised IndexError on .split()[0] —
    # escaped from the try block and killed the whole search call
    table = _CPE_VENDOR_TABLE.get(parts[0]) if parts else None
    prefix = f"cpe:2.3:a:{table[0]}:{table[1]}" if table else None
    if not prefix:
        await _nvd_rate_limit()
        try:
            async with httpx.AsyncClient(timeout=20) as c:
                r = await c.get("https://services.nvd.nist.gov/rest/json/cpes/2.0",
                                params={"keywordSearch": software, "resultsPerPage": 20})
                r.raise_for_status()
                data = r.json()
            best = None
            for p in data.get("products", []):
                cpe = p.get("cpe", {})
                name = cpe.get("cpeName", "")
                if not name.startswith("cpe:2.3:a:"):
                    continue
                title = " ".join(t.get("title","") for t in cpe.get("titles",[])
                                 if t.get("lang") == "en").lower()
                if software.lower() in title or software.lower() in name:
                    best = name.split(":")
                    break
            if best:
                prefix = f"cpe:2.3:a:{best[3]}:{best[4]}"
        except Exception as e:
            logger.warning(f"NVD CPE dictionary search failed: {e}")
            # FIX: a transient blip must not degrade CPE matching for 12h —
            # failure is cached short-term only
            _cache_put(key, _FETCH_FAILED, _FAIL_TTL)
            return None
    _cache_put(key, prefix)
    return prefix


async def _nvd_cpe_paginate(cache_key: str, cpe_prefix: str) -> List[Dict]:
    """Background pagination for _nvd_cpe_search (shielded). Caches only
    when complete — partial pages must NOT be cached as complete, that
    would silently drop CVEs for every search until TTL expiry."""
    product = cpe_prefix.split(":")[4]
    all_items: List[Dict] = []
    start = 0
    complete = False
    for _ in range(25):   # max-page guard — a stuck page would spin forever
        await _nvd_rate_limit()
        try:
            async with httpx.AsyncClient(timeout=30) as c:
                r = await c.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                                params={"virtualMatchString": cpe_prefix,
                                        "resultsPerPage": 2000,
                                        "startIndex": start})
                r.raise_for_status()
                data = r.json()
        except Exception as e:
            logger.warning(f"NVD CPE search failed: {e}")
            break
        for entry in data.get("vulnerabilities", []):
            cve = entry.get("cve", {})
            desc = next((d["value"] for d in cve.get("descriptions",[])
                         if d.get("lang") == "en"), "")
            cvss_score = None
            for mk in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
                ml = cve.get("metrics", {}).get(mk, [])
                if ml:
                    cvss_score = ml[0].get("cvssData", {}).get("baseScore")
                    break
            all_items.append({
                "cve_id":      cve.get("id",""),
                "description": desc[:300],
                "cvss_score":  cvss_score,
                "published":   cve.get("published",""),
                "cisa_kev":    bool(cve.get("cisaExploitAdd")),
                "source":      "nvd.nist.gov (CPE)",
                "_cpe_matches": _cpe_matches_for(cve, product),
            })
        start += len(data.get("vulnerabilities", []))
        if data.get("totalResults") is None:
            # FIX: NVD omitting totalResults (or a non-200 JSON) used to make
            # page 1 look "complete" — cached as authoritative, silently
            # dropping every later page. Treat as incomplete.
            logger.warning(f"NVD CPE response missing totalResults for {cpe_prefix} "
                           f"— page {_}, not cached as complete")
            break
        if start >= data.get("totalResults", 0):
            complete = True
            break
    if complete:
        _cache_put(cache_key, all_items)
    else:
        # FIX: a hard failure (raised, not just partial) gets a short-lived
        # failure marker so the NEXT caller doesn't immediately re-paginate
        # up to 25 pages against a down NVD — matches _cached_fetch's
        # _FAIL_TTL semantics. Partial-but-not-empty results are reused for
        # 5 min too (better than re-paginating from scratch each call); a
        # fully-empty incomplete run caches nothing.
        if not all_items:
            logger.warning(f"NVD CPE search incomplete for {cpe_prefix} "
                           f"({len(all_items)} items) — not cached")
        else:
            _cache_put(cache_key, all_items, _FAIL_TTL)
            logger.warning(f"NVD CPE search partial for {cpe_prefix} "
                           f"({len(all_items)} items) — cached 5min, re-paginate later")
    return all_items


_nvd_cpe_tasks: Dict[str, asyncio.Task] = {}


async def _nvd_cpe_search(cpe_prefix: str, target: tuple, family: str,
                          max_results: int) -> List[Dict]:
    """All CVEs for a product whose affected ranges cover the target version.
    virtualMatchString is exact per CPE entry, so results carry version
    bounds — far more accurate than keyword guessing."""
    cache_key = f"nvd_cpe:{cpe_prefix}"
    cached = _cache_get(cache_key)
    if cached is _FETCH_FAILED:
        return []   # FIX: cached failure marker — don't re-paginate a down NVD
    if cached is _MISS:
        # FIX: pagination runs as a SHIELDED background task — a caller
        # cancelled mid-pagination (batch timeout) previously killed the
        # loop, cached nothing, and the NEXT caller re-paginated up to
        # 25 pages (7s throttle + 30s HTTP each). Now the first task
        # finishes in the background, caches, and later callers hit it.
        task = _nvd_cpe_tasks.get(cache_key)
        if task is None or task.done():
            task = asyncio.ensure_future(_nvd_cpe_paginate(cache_key, cpe_prefix))
            _nvd_cpe_tasks[cache_key] = task
            task.add_done_callback(
                lambda t, k=cache_key: _nvd_cpe_tasks.pop(k, None)
                if _nvd_cpe_tasks.get(k) is t else None)
        try:
            all_items = await asyncio.shield(task)
        except Exception as e:
            logger.warning(f"NVD CPE search failed: {e}")
            all_items = []
    else:
        all_items = cached

    if target and target != (0,):
        kept = [i for i in all_items
                if any(_ver_in_cpe_range(target, m) for m in i.get("_cpe_matches", []))]
        if not kept:
            kept = _family_filter(all_items, family)
        items = kept
    else:
        items = all_items
    out = [dict(i) for i in items]
    for i in out:
        i.pop("_cpe_matches", None)
    # FIX: raw float() lambda crashed when NVD returned cvss_score as str
    return sorted(out, key=_cvss_sort_key)[:max_results]


# ─────────────────────────────────────────────
# 3. EXPLOIT-DB  (searchsploit + JSON endpoint)
# ─────────────────────────────────────────────
async def lookup_exploitdb_cve(cve_id: str) -> Optional[CVEResult]:
    """
    Two-pronged Exploit-DB lookup:
      A) searchsploit --cve <num> --json  — uses local Kali DB, fastest
      B) https://www.exploit-db.com/search?cve=<num>&json=true  — live fallback
    """
    cve_num = cve_id.replace("CVE-","").replace("cve-","")
    exploits  = []
    edb_ids   = []
    msf_module = ""

    # ── A: searchsploit (offline-capable, Kali built-in)
    try:
        proc = await asyncio.create_subprocess_exec(
            "searchsploit", "--cve", cve_num, "--json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
        except asyncio.TimeoutError:
            # wait_for cancels the coroutine but NOT the child — kill it,
            # or every timed-out lookup orphans a searchsploit process
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            await proc.wait()
            raise
        if stdout:
            ss_data = json.loads(stdout.decode())
            for ex in ss_data.get("RESULTS_EXPLOIT", []):
                edb_id = str(ex.get("EDB-ID",""))
                title  = ex.get("Title","")
                path   = ex.get("Path","")
                exploits.append({"edb_id": edb_id, "title": title, "path": path})
                edb_ids.append(edb_id)
    except FileNotFoundError:
        logger.debug("searchsploit not on PATH — using live API + CSV mirror")
    except asyncio.TimeoutError:
        logger.debug("searchsploit timed out")
    except Exception as e:
        logger.debug(f"searchsploit: {e}")

    # ── B: Live Exploit-DB JSON API (fallback or extra coverage)
    if not exploits:
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True) as c:
                r = await c.get(
                    "https://www.exploit-db.com/search",
                    params={"cve": cve_num, "json": "true"},
                    headers={"Accept": "application/json",
                             "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
                             "X-Requested-With": "XMLHttpRequest"},
                )
                if r.status_code == 200:
                    # Handle non-JSON responses (Cloudflare may block)
                    try:
                        jdata = r.json()
                        for ex in jdata.get("data", []):
                            edb_id = str(ex.get("id",""))
                            title  = ex.get("description","")
                            if isinstance(title, list):  # ['52506', 'React Server...']
                                title = re.sub(r'^\d+\s+', '', " ".join(str(t) for t in title))
                            exploits.append({
                                "edb_id": edb_id,
                                "title":  title,
                                "url":    f"https://www.exploit-db.com/exploits/{edb_id}",
                            })
                            edb_ids.append(edb_id)
                    except (ValueError, json.JSONDecodeError):
                        # Not JSON — Cloudflare blocked us, skip gracefully
                        pass
        except Exception as e:
            logger.debug(f"Exploit-DB live: {e}")

    # ── B2: official exploitdb CSV mirror (live API sits behind a JS
    # challenge on many networks) — match CVE id/number in the codes column
    if not exploits:
        seen_edb = set(edb_ids)
        try:
            await _edb_rows()   # loads + builds the inverted CVE index
            rows = _edb_cve_index.get(cve_id.lower(), []) + \
                   _edb_cve_index.get(cve_num.lower(), [])
            for row in rows:
                edb_id = str(row.get("id", ""))
                if edb_id in seen_edb:  # same exploit from the live API already
                    continue
                seen_edb.add(edb_id)
                exploits.append({
                    "edb_id": edb_id,
                    "title":  (row.get("description") or "")[:120],
                    "url":    f"https://www.exploit-db.com/exploits/{edb_id}",
                })
                edb_ids.append(edb_id)
                if len(exploits) >= 8:
                    break
        except Exception as e:
            logger.debug(f"Exploit-DB CSV: {e}")

    if not exploits:
        return None

    return CVEResult(
        cve_id     = cve_id,
        exploits   = exploits,
        edb_ids    = edb_ids,
        msf_module = msf_module,
        source     = "exploit-db.com",
    )


# Official exploitdb mirror (GitLab — the GitHub org mirror is gone).
# ~1.5MB / 47k rows, cached 12h. CVE IDs live in the semicolon-separated
# `codes` column; description/file cover keyword search.
EDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

_edb_cve_index: Dict[str, List[dict]] = {}

def _build_edb_index(rows: list) -> None:
    """Invert the 47k-row CSV once at load time: codes-token -> [rows].
    Turns the per-CVE linear full-table scan into an O(1) dict lookup."""
    global _edb_cve_index
    idx: Dict[str, List[dict]] = {}
    for row in rows:
        for tok in (row.get("codes") or "").lower().split(";"):
            tok = tok.strip()
            if not tok or len(tok) < 9:   # 'CVE-2021-44228' / '2021-44228'
                continue
            idx.setdefault(tok, []).append(row)
            if tok.startswith("cve-") and len(tok) > 4:
                idx.setdefault(tok[4:], []).append(row)
    _edb_cve_index = idx

async def _edb_rows() -> list:
    async def _fetch_csv() -> list:
        # FIX: 90s > lookup budget (see _fetch_msf) — 45s keeps it inside.
        async with httpx.AsyncClient(timeout=45) as c:
            r = await c.get(EDB_CSV_URL, headers={"User-Agent": "Mozilla/5.0"})
            r.raise_for_status()
            rows = list(csv.DictReader(r.text.splitlines()))
            _build_edb_index(rows)
            return rows
    return await _cached_fetch("edb_csv", _fetch_csv)


def _edb_row_has_cve(row, cve_id: str, cve_num: str) -> bool:
    """Match CVE id (CVE-2021-44228) or number (2021-44228) in the codes column."""
    codes = (row.get("codes") or "").lower()
    for tok in codes.split(";"):
        tok = tok.strip()
        if tok == cve_id.lower() or tok == cve_num.lower():
            return True
    return False


async def search_exploitdb_keyword(keyword: str, max_results: int = 10) -> List[Dict]:
    """Exploit-DB search by keyword — tries searchsploit first, then live API."""
    results = []

    # searchsploit (local, fast)
    try:
        proc = await asyncio.create_subprocess_exec(
            "searchsploit", keyword, "--json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        # FIX: wait_for cancels the coroutine but NOT the child — kill it
        # (same orphan bug the --cve path had; a hung searchsploit leaked a
        # perl process per call, and bulk lookups spawn up to ~200 of them)
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            await proc.wait()
            raise
        if stdout:
            ss_data = json.loads(stdout.decode())
            for ex in ss_data.get("RESULTS_EXPLOIT", [])[:max_results]:
                results.append({
                    "edb_id": str(ex.get("EDB-ID","")),
                    "title":  ex.get("Title",""),
                    "type":   ex.get("Type",""),
                    "date":   ex.get("Date",""),
                    "source": "exploit-db (searchsploit)",
                })
            if results:
                return results
    except Exception as e:
        logger.debug(f"searchsploit keyword: {e}")

    # Live API fallback — full query, then version-stripped retry
    results = await _exploitdb_live_search(keyword, max_results)
    if not results and " " in keyword and any(ch.isdigit() for ch in keyword):
        stripped = " ".join(t for t in keyword.split() if not re.search(r"\d", t))
        if stripped and stripped != keyword.strip():
            logger.debug(f"Exploit-DB keyword retry: {keyword!r} -> {stripped!r}")
            results = await _exploitdb_live_search(stripped, max_results)
    return results


async def _exploitdb_live_search(keyword: str, max_results: int) -> List[Dict]:
    results = []
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as c:
            r = await c.get(
                "https://www.exploit-db.com/search",
                params={"q": keyword, "json": "true"},
                headers={"Accept": "application/json",
                         "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
                         "X-Requested-With": "XMLHttpRequest"},
            )
            if r.status_code == 200:
                try:
                    jdata = r.json()
                    for ex in jdata.get("data", [])[:max_results]:
                        edb_id = str(ex.get("id",""))
                        title  = ex.get("description","")
                        if isinstance(title, list):  # ['52506', 'React Server...']
                            title = re.sub(r'^\d+\s+', '', " ".join(str(t) for t in title))
                        results.append({
                            "edb_id": edb_id,
                            "title":  title,
                            "url":    f"https://www.exploit-db.com/exploits/{edb_id}",
                            "source": "exploit-db.com",
                        })
                    if results:
                        return results
                except (ValueError, json.JSONDecodeError):
                    pass  # Cloudflare/JS-challenge blocked — CSV mirror below
    except Exception as e:
        logger.debug(f"Exploit-DB keyword: {e}")

    # the live search endpoint often sits behind a JS challenge (307) —
    # fall back to the official exploitdb CSV mirror (cached 12h)
    kw = keyword.lower()
    try:
        for row in await _edb_rows():
            hay = ((row.get("description") or "") + " " + (row.get("file") or "")).lower()
            if kw in hay:
                edb_id = str(row.get("id", ""))
                results.append({
                    "edb_id": edb_id,
                    "title":  (row.get("description") or "")[:120],
                    "url":    f"https://www.exploit-db.com/exploits/{edb_id}",
                    "source": "exploit-db (csv mirror)",
                })
                if len(results) >= max_results:
                    break
    except Exception as e:
        logger.debug(f"Exploit-DB CSV: {e}")
    return results


# ─────────────────────────────────────────────
# Combined parallel lookup
# ─────────────────────────────────────────────
def _strip_version_patch(version: str) -> str:
    """'8.2p1'/'8.2a3'/'2.4.49-1' -> '8.2'/'8.2'/'2.4.49'.
    Keyword engines AND every token and tokenize letter-suffixed versions
    badly ('8.2p1' matches nothing while '8.2' matches '8.2p1'), so query
    the version family and filter the results instead."""
    v = re.sub(r'(?i)[\-_.]?(?:p\d*|[a-z]\d*|rel(?:ease)?\d*|-\d+)\s*$', '', version.strip())
    return v.rstrip('.')


def _norm_version(v: str) -> tuple:
    """'8.2p1' -> (8,2,1); '2.4.49' -> (2,4,49). Numeric tokens only.
    FIX: strip a trailing distro/patch suffix first — '2.4.49-1' previously
    parsed as (2,4,49,1) and failed the explicit-version equality in
    _ver_in_cpe_range against a clean target (2,4,49), silently dropping
    affected CVEs. Suffix must be pure '-' + digits (optionally dotted)."""
    v = re.sub(r'-\d+(?:\.\d+)*$', '', v)
    nums = tuple(int(t) for t in re.findall(r'\d+', v))
    return nums if nums else (0,)


_CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,}$', re.I)

def _valid_cve_id(s: str) -> bool:
    """FIX: garbage CVE ids (CVE-2021-x, 'foo', timestamps) previously went
    straight to sploitus/searchsploit/GitHub search — 3 wasted remote calls
    per bad id. NVD uses 4+ digits in the sequence (CVE-2021-44228)."""
    return bool(_CVE_RE.match((s or "").strip()))


# NVD/Exploit-DB descriptions state the FIXED version ('through 8.3p1',
# 'before 8.4', '8.2 and earlier', '5.7 through 8.4'), so matching the
# literal family misses most affected CVEs — parse the affected range.
_BOUNDARY_RES = [
    (re.compile(r'(?:before|prior\s+to)\s+(v[\d][\w.\-]*|[\d][\w.\-]*)', re.I), "<"),
    (re.compile(r'(?:through|up\s+to)\s+(v[\d][\w.\-]*|[\d][\w.\-]*)', re.I), "<="),
    (re.compile(r'([\d][\w.\-]*)\s+and\s+earlier', re.I), "<="),
    (re.compile(r'<=\s*([\d][\w.\-]*)', re.I), "<="),
    (re.compile(r'<\s*([\d][\w.\-]*)', re.I), "<"),
]


def _desc_affects(desc: str, target: tuple) -> bool:
    """True if a description's affected version range covers the target."""
    if not target or target == (0,):
        return True
    for rx, op in _BOUNDARY_RES:
        for m in rx.finditer(desc):
            ver = m.group(1)
            if re.match(r'^\d{4}-?\d{2}', ver):  # dates ('2001-02-08'), not versions
                continue
            b = _norm_version(ver)
            if b == (0,):
                continue
            if (op == "<" and target < b) or (op == "<=" and target <= b):
                return True
    return False


def _family_filter(items: List[Dict], family: str, fallback: bool = True) -> List[Dict]:
    """Keep items whose description/title mentions the version family or whose
    affected range covers it. '8.2' matches '8.2p1' (literal) and 'through 8.3p1'
    (range) but not '8.25'. With fallback=True (description-based sources) returns
    all items when nothing matches; with fallback=False (title-only sources like
    Exploit-DB) returns only exact hits."""
    target = _norm_version(family)
    pats = [re.escape(t) + r'(?![\d.])' for t in family.split() if re.search(r'\d', t)]
    if not pats:
        return items
    rx = re.compile('|'.join(pats), re.I)
    kept = [i for i in items
            if rx.search(f"{i.get('description','')} {i.get('title','')}")
            or _desc_affects(f"{i.get('description','')} {i.get('title','')}", target)]
    return kept if (kept or not fallback) else items


def _merge_cve_lists(*lists) -> List[Dict]:
    """Merge CVE result lists, family-results first, dedup by cve_id."""
    merged: List[Dict] = []
    for src in lists:
        if not isinstance(src, list):
            continue
        for item in src:
            if not any(i.get("cve_id") == item.get("cve_id") for i in merged):
                merged.append(item)
    return merged


def _split_service_version(svc: str) -> tuple:
    """'OpenSSH 8.9p1 Ubuntu' -> ('openssh', '8.9p1'); 'vsftpd 2.3.4' -> ('vsftpd', '2.3.4').
    Service banners include the version in the string; handing it to the
    versioned search (CPE ranges) instead of keyword-guessing the whole
    banner makes service enrichment accurate."""
    parts = svc.strip().lower().split()
    for idx in range(len(parts) - 1, -1, -1):
        if re.search(r'\d', parts[idx]):
            return (" ".join(parts[:idx]), parts[idx])
    return (svc.strip().lower(), "")


async def search_service_cves_all(software: str, version: str = "",
                                   max_results: int = 8) -> Dict:
    """Search all 3 databases for CVEs affecting software+version. Runs in parallel.

    Versioned queries use the NVD CPE engine (exact affected-version ranges)
    instead of keyword guessing, which misses CVEs whose descriptions use
    different wording ('httpd' vs 'HTTP Server'). Without a version the
    keyword path is used, unchanged.
    """
    family = _strip_version_patch(version)
    query  = f"{software} {family}".strip()

    tasks = [
        search_vulners_software(software, family, max_results),
        search_exploitdb_keyword(query, max_results),
    ]
    nvd_path = "keyword"
    if version:
        cpe_prefix = await _find_cpe_prefix(software)
        if cpe_prefix:
            nvd_path = "cpe"
            tasks.append(_nvd_cpe_search(cpe_prefix, _norm_version(family),
                                         family, max_results))
        else:
            tasks.append(search_nvd_software(query, max_results))
            if family != software:
                tasks.append(search_nvd_software(software, max(200, max_results)))
    else:
        tasks.append(search_nvd_software(query, max_results))

    vulners_res, edb_res, nvd_res, *nvd_broad = await asyncio.gather(*tasks, return_exceptions=True)
    vulners_items = vulners_res if isinstance(vulners_res, list) else []
    edb_items     = edb_res     if isinstance(edb_res, list) else []
    nvd_items     = _merge_cve_lists(nvd_res, nvd_broad[0] if nvd_broad else None)

    if version and nvd_path != "cpe":
        vulners_items = _family_filter(vulners_items, family)
        nvd_items     = _family_filter(nvd_items, family)
        edb_items     = _family_filter(edb_items, family, fallback=False)
    elif version:
        vulners_items = _family_filter(vulners_items, family)
        edb_items     = _family_filter(edb_items, family, fallback=False)

    results = {
        "query":        query,
        "vulners":      vulners_items[:max_results],
        "nvd":          nvd_items[:max_results],
        "exploit_db":   edb_items[:max_results],
    }
    all_cve_ids: List[str] = []
    for src in (results["vulners"], results["nvd"]):
        for item in src:
            cid = item.get("cve_id","")
            if cid and cid not in all_cve_ids:
                all_cve_ids.append(cid)
    results["unique_cves"]    = all_cve_ids
    results["total_exploits"] = len(results["exploit_db"])
    return results


async def search_service_cves_all_deep(software: str, version: str = "",
                                       max_results: int = 8,
                                       top_cves: int = 5) -> Dict:
    top_cves = min(max(int(top_cves), 0), 10)   # each deep-dive is a full multi-source lookup — unbounded = minutes of NVD slots
    """Search all sources for CVEs affecting software+version, then deep-dive
    the top-N CVEs with full enrichment (PoC repos, exploits, Metasploit,
    Nuclei, Vulhub Docker, EPSS/KEV). Returns the base result plus
    deep_cves: [full lookup_cve_all dicts] and deep_count."""
    result = await search_service_cves_all(software, version, max_results)
    result["deep"] = False

    seen: List[str] = []
    candidates: List[Dict] = []
    for src in list(result.get("vulners") or []) + list(result.get("nvd") or []):
        cid = (src.get("cve_id") or "").upper()
        if cid and cid not in seen:
            seen.append(cid)
            candidates.append(src)
    for ex in result.get("exploit_db") or []:
        m = _CVE_MENTION_RE.search(ex.get("title") or "")
        if m:
            cid = m.group(0).upper()
            if cid not in seen:
                seen.append(cid)
                candidates.append({"cve_id": cid})

    candidates.sort(key=_cvss_sort_key)
    top = candidates[:top_cves]
    if not top:
        return result

    console.print(f"[cyan]Deep-dive:[/] enriching top {len(top)} CVE(s) with PoC/exploit data...")
    deep_budget = 60.0 + len(top) * 8.0
    deep = await asyncio.gather(*[lookup_cve_all(c["cve_id"], timeout=deep_budget) for c in top],
                                return_exceptions=True)
    result["deep"]       = True
    result["deep_cves"]  = [d for d in deep if isinstance(d, dict) and d.get("cve_id")]
    result["deep_count"] = len(result["deep_cves"])
    return result


# ─────────────────────────────────────────────
# Display
# ─────────────────────────────────────────────
def _cvss_sort_key(item: Any) -> float:
    """Sort key for CVE dicts — Vulners can return cvss_score as str,
    and unary minus on a str raises TypeError that kills whole MCP calls."""
    try:
        return -float(item.get("cvss_score") or 0)
    except (TypeError, ValueError, AttributeError):
        return 0.0


def _epss_pct(epss) -> str:
    """Format EPSS score safely — Vulners may return it as str or None."""
    if epss is None:
        return "N/A"
    try:
        return f"{float(epss) * 100:.1f}%"
    except (TypeError, ValueError):
        return "N/A"


def _risk_summary(cve: Dict) -> str:
    parts = []
    score = cve.get("cvss_score")
    sev   = (cve.get("cvss_severity") or "").upper()
    if score:  parts.append(f"CVSS {score} ({sev})")
    epss = cve.get("epss_score")
    if epss is not None: parts.append(f"EPSS {_epss_pct(epss)}")
    if cve.get("cisa_kev"):      parts.append("[KEV] CISA KEV")
    if cve.get("wild_exploited"): parts.append("[WILD] exploited in wild")
    if cve.get("exploits"):      parts.append(f"{len(cve['exploits'])} exploit(s)")
    if cve.get("msf_module"):    parts.append("MSF available")
    return " | ".join(parts) if parts else "No critical indicators"

def _safe_str(val: Any, maxlen: int = 0) -> str:
    """Convert a value to string safely, handling lists from API.
    FIX: escapes rich markup — a '[' in a service banner/description
    previously raised MarkupError and killed the whole tool call."""
    s = str(val) if not isinstance(val, str) else val
    s = _markup_escape(s)
    return s[:maxlen] if maxlen else s

def _safe_plain(val: Any) -> str:
    return _ascii_safe(str(val)) if not isinstance(val, str) else _ascii_safe(val)

def print_cve_card(cve: Dict):
    """Display CVE card using safe ASCII-only output."""
    sev   = (cve.get("cvss_severity") or "").upper()
    epss_str = _epss_pct(cve.get("epss_score"))
    kev_str = "YES" if cve.get("cisa_kev") else "No"
    poc_count = len(cve.get("poc_repos", []))
    desc = _safe_plain(cve.get("description",""))[:300]
    bar = "=" * 60
    _safe_print(f"+{bar}+")
    _safe_print(f"| [CVE] {cve.get('cve_id','')}")
    _safe_print(f"+{bar}+")
    _safe_print(f"  CVSS:     {cve.get('cvss_score','N/A')} ({sev})")
    _safe_print(f"  EPSS:     {epss_str}")
    _safe_print(f"  CISA KEV: {kev_str}")
    _safe_print(f"  Published: {str(cve.get('published',''))[:10]}")
    _safe_print(f"  Sources:  {', '.join(_safe_plain(s) for s in (cve.get('sources') or []))}")
    if poc_count:
        _safe_print(f"  PoC Repos: {poc_count} found")
    _safe_print(f"")
    _safe_print(f"  {desc}")
    _safe_print(f"+{bar}+")
    if cve.get("exploits"):
        _safe_print(f"  Public Exploits:")
        for ex in cve["exploits"][:6]:
            eid = ex.get("edb_id","") or ex.get("id","")
            title = ex.get("title","")
            if isinstance(title, list):  # ['52506', 'React Server...']
                title = re.sub(r'^\d+\s+', '', " ".join(str(t) for t in title))
            _safe_print(f"    EDB-{eid}: {_safe_plain(title)[:60]}")
    if cve.get("msf_module"):
        rank = cve.get("msf_rank")
        _safe_print(f"  Metasploit: {_safe_plain(cve['msf_module'])}"
                    + (f" (Rank: {rank})" if rank else ""))
    if cve.get("nuclei_template"):
        _safe_print(f"  Nuclei: nuclei -t {cve['nuclei_template']} [-u <target>]")
    elif cve.get("nuclei_url"):
        _safe_print(f"  Nuclei: {cve['nuclei_url']}")
    poc_repos = cve.get("poc_repos", [])
    if poc_repos:
        shown = min(len(poc_repos), 10)
        _safe_print(f"  Top PoC Repos ({shown} shown):")
        for i, repo in enumerate(poc_repos[:shown], 1):
            lang = repo.get("language", "") or ""
            desc = _safe_plain(repo.get("description",""))[:70]
            _safe_print(f"    PoC #{i}: {repo.get('full_name','')} ({repo.get('stars',0)} stars) [{lang}]")
            _safe_print(f"           Clone URL: {_safe_plain(repo.get('html_url',''))}")
            if desc:
                _safe_print(f"           Desc:      {desc}")
    if cve.get("docker_env", {}).get("found"):
        _safe_print(f"  Docker: vulhub/{_safe_plain(cve['docker_env']['path'])}")

def print_service_results(data: Dict):
    all_items = (data.get("vulners") or []) + (data.get("nvd") or [])
    seen, unique = set(), []
    for x in all_items:
        cid = x.get("cve_id","")
        if cid and cid not in seen:
            seen.add(cid)
            unique.append(x)
    if unique:
        t = Table(title=f"CVEs — {_markup_escape(data.get('query',''))}",
                  box=box.ROUNDED, header_style="bold cyan", show_lines=True)
        t.add_column("CVE", style="yellow", width=18)
        t.add_column("CVSS", justify="center", width=6)
        t.add_column("Description", max_width=55)
        t.add_column("Published", width=12)
        t.add_column("Source", width=14, style="dim")
        for item in sorted(unique, key=_cvss_sort_key)[:15]:
            s = item.get("cvss_score")
            ss = f"[red]{s}[/]" if isinstance(s, (int, float)) and s >= 7 else \
                 (f"[yellow]{s}[/]" if s else "N/A")
            t.add_row(_safe_str(item.get("cve_id","")), ss,
                      _safe_str(item.get("description",""), 55),
                      _safe_str(item.get("published",""), 10),
                      _safe_str(item.get("source","")))
        console.print(t)
    if data.get("exploit_db"):
        t2 = Table(title="Exploit-DB", box=box.SIMPLE_HEAD, header_style="bold red")
        t2.add_column("EDB-ID", style="yellow", width=8)
        t2.add_column("Title")
        for ex in data["exploit_db"][:8]:
            t2.add_row(_safe_str(ex.get("edb_id","")),
                       _safe_str(ex.get("title",""), 70))
        console.print(t2)


# ─────────────────────────────────────────────
# MCP rendering helpers
# ─────────────────────────────────────────────
def _flatten_cve_result(cve: Dict) -> Dict:
    """
    Convert a full CVE result dict into a flat, MCP-renderer-safe structure.
    Replaces list-of-dicts fields (exploits, references, sources, edb_ids) with
    scalar counts + newline-joined preview strings so MCP never sees a bare list.
    """
    exploits = cve.get("exploits", []) or []
    references = cve.get("references", []) or []
    sources = cve.get("sources", []) or []
    edb_ids = cve.get("edb_ids", []) or []

    exploit_lines = []
    for ex in exploits[:6]:
        eid = ex.get("edb_id", "") or ex.get("id", "")
        raw_title = ex.get("title", "")
        if isinstance(raw_title, list):
            # FIX: empty list crashed here (IndexError on raw_title[0])
            title = str(raw_title[-1] if len(raw_title) > 1
                        else (raw_title[0] if raw_title else ""))[:60]
        else:
            title = str(raw_title)[:60]
        etype = ex.get("type", "exploit")
        exploit_lines.append(f"EDB-{eid}: {title} [{etype}]")

    epss = cve.get("epss_score")
    epss_str = _epss_pct(epss)

    poc_repos_raw = cve.get("poc_repos", [])
    poc_lines = []
    for i, repo in enumerate(poc_repos_raw[:10], 1):
        fn = repo.get("full_name", "")
        stars = repo.get("stars", 0)
        lang = repo.get("language", "")
        lang_str = f" [{lang}]" if lang else ""
        poc_lines.append(f"  PoC #{i}: {fn} ({stars} stars){lang_str}")
        url = repo.get("html_url", "")
        if url:
            poc_lines.append(f"     Clone URL: {url}")
        desc = (repo.get("description") or "")[:80]
        if desc:
            poc_lines.append(f"     Desc: {_ascii_safe(desc)}")

    docker = cve.get("docker_env", {})

    return {
        "cve_id":          cve.get("cve_id", ""),
        "description":     _ascii_safe((cve.get("description") or "")[:400]),
        "cvss_score":      cve.get("cvss_score"),
        "cvss_severity":   cve.get("cvss_severity", ""),
        "epss_score":      epss,
        "epss_pct":        epss_str,
        "published":       cve.get("published", ""),
        "cisa_kev":        cve.get("cisa_kev", False),
        "wild_exploited":  cve.get("wild_exploited", False),
        "msf_module":      cve.get("msf_module", ""),
        "msf_rank":        cve.get("msf_rank", ""),
        "risk_summary":    cve.get("risk_summary", ""),
        "exploit_count":   len(exploits),
        "reference_count": len(references),
        "edb_ids":         ", ".join(str(e) for e in edb_ids[:10]),
        "sources":         ", ".join(sources),
        "exploits_preview": "\n".join(exploit_lines) if exploit_lines else "None found",
        "references_preview": "\n".join(references[:5]) if references else "None",
        "poc_count":       len(poc_repos_raw),
        "poc_total":       cve.get("poc_total", len(poc_repos_raw)),
        "poc_repos_preview": "\n".join(poc_lines) if poc_lines else "None found",
        "metasploit_module": cve.get("msf_module", ""),
        "nuclei_template": cve.get("nuclei_template", ""),
        "nuclei_url":      cve.get("nuclei_url", ""),
        "docker_available": docker.get("found", False),
        "docker_path":     docker.get("path", ""),
        "docker_setup":    _ascii_safe(docker.get("setup_steps", "")),
    }


def _flatten_service_cve_result(data: Dict) -> Dict:
    """
    Flatten a search_service_cves result into MCP-safe scalars.
    The original has {vulners: [...], nvd: [...], exploit_db: [...]} which
    are lists of dicts — MCP renderers choke on these at the top level.
    """
    vulners_items  = data.get("vulners", []) or []
    nvd_items      = data.get("nvd", []) or []
    exploit_items  = data.get("exploit_db", []) or []
    unique_cves    = data.get("unique_cves", []) or []

    def _summarize_cve_list(items, limit=10):
        lines = []
        for item in items[:limit]:
            cid   = item.get("cve_id", "")
            score = item.get("cvss_score", "N/A")
            desc  = (item.get("description") or "")[:80]
            lines.append(f"{cid} [CVSS {score}]: {desc}")
        return "\n".join(lines) if lines else "None found"

    def _summarize_exploits(items, limit=5):
        lines = []
        for item in items[:limit]:
            eid   = item.get("edb_id", "") or item.get("id", "")
            title = (item.get("title") or item.get("description") or "")[:70]
            lines.append(f"EDB-{eid}: {title}")
        return "\n".join(lines) if lines else "None"

    return {
        "query":              data.get("query", ""),
        "unique_cve_count":   len(unique_cves),
        "unique_cve_ids":     ", ".join(unique_cves[:20]),
        "total_exploits":     data.get("total_exploits", len(exploit_items)),
        "vulners_count":      len(vulners_items),
        "nvd_count":          len(nvd_items),
        "exploit_db_count":   len(exploit_items),
        "vulners_summary":    _summarize_cve_list(vulners_items),
        "nvd_summary":        _summarize_cve_list(nvd_items),
        "exploits_summary":   _summarize_exploits(exploit_items),
        "deep_dive_count":    data.get("deep_count", 0),
        # FIX: return structured deep_cves (was preview-string only) — each
        # entry trimmed to lean scalars so the list stays context-safe; the
        # human-friendly preview remains as a convenience field.
        "deep_cves": [
            {
                "cve_id":         c.get("cve_id", ""),
                "cvss_score":     c.get("cvss_score", "N/A"),
                "severity":       c.get("cvss_severity") or c.get("severity"),
                "exploit_count":  len(c.get("exploits") or []),
                "poc_total":      c.get("poc_total", 0),
                "msf_module":     bool(c.get("msf_module")),
                "nuclei_template": bool(c.get("nuclei_template")),
                "cisa_kev":       bool(c.get("cisa_kev")),
                "docker_env":     bool((c.get("docker_env") or {}).get("found")),
                "description":    (c.get("description") or "")[:160],
                "references":     [r for r in (c.get("references") or [])][:5],
            }
            for c in (data.get("deep_cves") or [])
        ],
        "deep_cves_preview":  "\n".join(
            f"{c.get('cve_id')}: CVSS {c.get('cvss_score','N/A')} | "
            f"{len(c.get('exploits') or [])} exploit(s) | "
            f"{c.get('poc_total', 0)} PoC repos | "
            f"MSF {'Yes' if c.get('msf_module') else 'No'} | "
            f"Nuclei {'Yes' if c.get('nuclei_template') else 'No'} | "
            f"KEV {'Yes' if c.get('cisa_kev') else 'No'} | "
            f"Docker {'Yes' if (c.get('docker_env') or {}).get('found') else 'No'}"
            for c in (data.get("deep_cves") or [])
        ) or "None",
    }


# ─────────────────────────────────────────────
# Scan-output extraction (shared by enrich_scan_cves + CLI --scan)
# ─────────────────────────────────────────────
_SCAN_SERVICE_RE = re.compile(r'\d+/\w+\s+open\s+\S+\s+([A-Za-z][^\r\n]{3,60})', re.MULTILINE)
_CVE_MENTION_RE  = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)
_SERVER_HEADER_RE = re.compile(r'^\s*Server:\s*([A-Za-z][^\r\n]{2,60})\s*$', re.MULTILINE)
# distro/build suffix on banners: 'OpenSSH 8.9p1 Ubuntu 3ubuntu0.6',
# 'Apache httpd 2.4.29 (Unix) DAV/2' — not part of the upstream version
_BANNER_CRUFT_RE = re.compile(r'\s+(?:Ubuntu|Debian|Unix|Linux|DAV/\d+)(?:\s+\S+)?\s*$')

def _trim_banner_cruft(svc: str) -> str:
    """Strip banner noise from a service string before searching.

    Raw captures include parentheticals ('((Ubuntu))', '(Unix)', possibly
    nested) and distro/build suffixes ('Ubuntu 3ubuntu0.6', 'DAV/2') that
    corrupted the Vulners/NVD keyword search. Parentheticals are removed
    iteratively to unwrap nesting; then the distro tail goes.
    """
    prev = None
    while prev != svc:
        prev = svc
        svc = re.sub(r'\s*\([^)]*\)\s*', ' ', svc).strip()
    svc = re.sub(r'[()]', ' ', svc)  # sweep leftovers from nested groups
    svc = _BANNER_CRUFT_RE.sub('', svc).strip()
    return re.sub(r'\s+', ' ', svc)

def _extract_scan_services(text: str) -> List[str]:
    """Pull service+version strings from nmap/nikto/banner output."""
    services = []
    for m in _SCAN_SERVICE_RE.finditer(text):
        svc = _trim_banner_cruft(m.group(1).strip()[:60])
        if svc and svc not in services:
            services.append(svc)
    # nikto/curl banner dumps: 'Server: Apache/2.4.29 (Ubuntu)' headers
    # (nmap-style lines are absent there — previously those pastes
    # "found nothing" despite the docstring promising banner support)
    for m in _SERVER_HEADER_RE.finditer(text):
        svc = _trim_banner_cruft(m.group(1).strip()[:60])
        if svc and svc not in services:
            services.append(svc)
    return services


def _extract_inline_cves(text: str) -> List[str]:
    return sorted(set(re.findall(_CVE_MENTION_RE, text)))


# ─────────────────────────────────────────────
# MCP registration
# ─────────────────────────────────────────────
def register_cve_tools(mcp):
    """
    Add CVE enrichment tools to an existing FastMCP instance.

    In adara_mcp_server.py, inside setup_mcp():
        from cve_enrichment import register_cve_tools
        register_cve_tools(mcp)
    """

    @mcp.tool(name="lookup_cve")
    async def lookup_cve(cve_id: str) -> Dict:
        """
        Look up a CVE across ALL sources simultaneously:
          • NVD/NIST     — Authoritative CVSS, CISA KEV catalog status
          • Vulners.com  — CVSS, EPSS, wild-exploitation flag (needs API key)
          • Exploit-DB   — Public exploits (searchsploit + live API + CSV mirror)
          • PoC repos    — nomi-sec, ycdxsb, trickest/cve, GitHub Search API
          • Metasploit + Nuclei templates, Sploitus, Vulhub Docker env

        Args:
            cve_id: e.g. "CVE-2021-44228" or just "2021-44228"
        """
        try:
            cid = cve_id.upper().strip()
            if not cid.startswith("CVE-"):
                cid = f"CVE-{cid}"
            console.print(f"[cyan]CVE lookup:[/] {_markup_escape(cid)} -> all sources")
            result = await lookup_cve_all(cid)
            print_cve_card(result)
            return _flatten_cve_result(result)
        except Exception as e:
            return {"error": str(e), "type": type(e).__name__}

    @mcp.tool(name="lookup_multiple_cves")
    async def lookup_multiple_cves(cve_ids: List[str]) -> Dict:
        """
        Look up multiple CVEs in parallel across all sources.
        Results sorted by CVSS score, highest first.
        Args:
            cve_ids: e.g. ["CVE-2021-44228", "CVE-2017-0144", "CVE-2014-6271"]
        """
        try:
            if not isinstance(cve_ids, list):
                return {"error": "cve_ids must be a list", "count": 0}
            if len(cve_ids) > 15:
                return {"error": "Max 15 CVEs at once", "count": 0, "cve_ids": cve_ids}
            # FIX: filter malformed ids up front (each one previously burned
            # a scaled bulk budget AND fired 3 doomed remote calls)
            bad = [c for c in cve_ids if not _valid_cve_id(c)]
            good = [c for c in cve_ids if _valid_cve_id(c)]
            if bad:
                logger.warning(f"lookup_multiple_cves: skipping {len(bad)} malformed ids: {bad}")
            if not good:
                return {"error": "No valid CVE ids supplied", "count": 0,
                        "invalid_ids": bad}
            console.print(f"[cyan]Bulk lookup:[/] {len(good)} CVEs in parallel"
                          + (f" (skipped {len(bad)} malformed)" if bad else ""))
            # scale the per-lookup budget with concurrency — NVD serializes
            # no-key requests 7s apart, so late-starting CVEs need headroom
            bulk_timeout = 60.0 + len(good) * 8.0
            results = await asyncio.gather(*[lookup_cve_all(c, timeout=bulk_timeout)
                                             for c in good],
                                           return_exceptions=True)
            # FIX: "Lookup timed out" is a false-negative — never rank it as
            # a result (it sorts with cvss None and poisons the summary)
            valid   = sorted(
                [r for r in results
                 if isinstance(r, dict) and r.get("risk_summary") != "Lookup timed out"
                 and not r.get("error")],
                key=_cvss_sort_key)
            timed_out = [r for r in results
                         if isinstance(r, dict) and r.get("risk_summary") == "Lookup timed out"]
            for r in valid:
                print_cve_card(r)
            summary_lines = [
                f"{r.get('cve_id','?')}: CVSS {r.get('cvss_score','N/A')} | {r.get('risk_summary','')[:80]}"
                for r in valid
            ]
            cve_detail_lines: List[str] = []
            for r in valid:
                flat = _flatten_cve_result(r)
                cve_detail_lines.append(
                    f"--- {flat['cve_id']} ---\n"
                    f"Description: {flat['description'][:120]}\n"
                    f"CVSS: {flat['cvss_score']} ({flat['cvss_severity']}) | EPSS: {flat['epss_pct']}\n"
                    f"CISA KEV: {'Yes' if flat['cisa_kev'] else 'No'} | Published: {flat['published']}\n"
                    f"Exploits: {flat['exploit_count']} | MSF: {flat['msf_module'] or 'None'}\n"
                    f"Sources: {flat['sources']}"
                )
            return {
                "count": len(valid),
                "cve_ids_queried": ", ".join(good),
                "timed_out_count": len(timed_out),
                "timed_out_ids": ", ".join(r.get("cve_id","") for r in timed_out)
                                  or "none",
                "invalid_ids": bad or [],
                "results_summary": "\n".join(summary_lines),
                "cves_detail": "\n\n".join(cve_detail_lines),
                "highest_cvss": valid[0].get("cvss_score") if valid else None,
                "highest_cve": valid[0].get("cve_id") if valid else None,
            }
        except Exception as e:
            return {"error": str(e), "type": type(e).__name__}

    @mcp.tool(name="search_service_cves")
    async def search_service_cves(software: str, version: str = "",
                                   max_results: int = 8) -> Dict:
        """
        Search all sources for CVEs affecting a service + version.
        Versioned queries use NVD's CPE engine (exact affected-version
        ranges). All searches run simultaneously.

        Args:
            software:    e.g. "vsftpd", "apache httpd", "openssh", "samba"
            version:     e.g. "2.3.4", "2.4.49" (leave blank to search all versions)
            max_results: Max results per source
        """
        try:
            console.print(f"[cyan]Service CVE search:[/] {_markup_escape(software)} {_markup_escape(version)}")
            result = await search_service_cves_all(software, version, max_results)
            print_service_results(result)
            return _flatten_service_cve_result(result)
        except Exception as e:
            return {"error": str(e), "type": type(e).__name__}

    @mcp.tool(name="search_service_cves_deep")
    async def search_service_cves_deep(software: str, version: str = "",
                                       max_results: int = 15,
                                       top_cves: int = 5) -> Dict:
        """
        Deep service+version CVE search. Finds all CVEs affecting the exact
        service+version (NVD CPE ranges), then fully enriches the top CVEs:
        PoC repos, exploits, Metasploit module, Nuclei template, Vulhub
        Docker env, EPSS, CISA KEV.

        Args:
            software:    e.g. "openssh", "apache httpd", "vsftpd"
            version:     e.g. "8.2p1", "2.4.49" (blank = all versions)
            max_results: Max CVE results per source
            top_cves:    How many top CVEs to fully enrich (default 5)
        """
        try:
            console.print(f"[cyan]Deep service CVE search:[/] "
                          f"{_markup_escape(software)} {_markup_escape(version)}")
            result = await search_service_cves_all_deep(software, version,
                                                        max_results, top_cves)
            print_service_results(result)
            for cve in result.get("deep_cves") or []:
                print_cve_card(cve)
            return _flatten_service_cve_result(result)
        except Exception as e:
            return {"error": str(e), "type": type(e).__name__}

    @mcp.tool(name="enrich_scan_cves")
    async def enrich_scan_cves(raw_scan_output: str, target: str = "") -> Dict:
        """
        Paste raw nmap / nikto / banner output here and get a full CVE report.
        Extracts all service+version strings and inline CVE mentions,
        then queries all sources for each one simultaneously.

        Args:
            raw_scan_output: Raw text from nmap -sCV, nikto, curl banners, etc.
            target:          Optional target IP/host to tag findings
        """
        try:
            services = _extract_scan_services(raw_scan_output)[:25]
            inline_cves = _extract_inline_cves(raw_scan_output)

            if not services and not inline_cves:
                return {"message": "No services or CVEs found in output",
                        "tip": "Use nmap -sCV for version detection"}

            console.print(f"[cyan]Enriching:[/] {len(services)} services + {len(inline_cves)} inline CVEs")
            all_results: Dict[str, Any] = {"services": {}, "inline_cves": {}, "target": target}

            # FIX: a single 120s wait_for over a 4-service batch discarded
            # completed results and capped wall time at 7 x 120s = 14 min.
            # Now each service gets its own 75s budget (partial results are
            # KEPT), plus a hard overall budget of 240s so the MCP 300s
            # ceiling can't be blown — remaining services are skipped with
            # a self-documenting warning.
            loop = asyncio.get_running_loop()
            wall_start = loop.time()
            for i in range(0, len(services), 4):
                if loop.time() - wall_start > 240:
                    logger.warning(f"enrich_scan_cves: overall budget exhausted — "
                                   f"skipping {len(services) - i} services")
                    break
                batch = services[i:i+4]

                async def _one(svc: str):
                    try:
                        return svc, await asyncio.wait_for(
                            search_service_cves_all(*_split_service_version(svc), max_results=5),
                            timeout=75)
                    except asyncio.TimeoutError:
                        return svc, {"error": "timed out after 75s", "type": "TimeoutError"}

                results = await asyncio.gather(*[_one(s) for s in batch],
                                               return_exceptions=True)
                # FIX: return_exceptions=True can yield exception objects —
                # unpacking one as (svc, res) raised TypeError and discarded
                # all partial results from earlier batches
                for item in results:
                    if not isinstance(item, tuple):
                        continue
                    svc, res = item
                    if isinstance(res, dict) and (res.get("vulners") or res.get("nvd") or res.get("exploit_db")):
                        all_results["services"][svc] = res
                        print_service_results(res)

            if inline_cves:
                # FIX: the inline phase previously ran OUTSIDE the 240s wall
                # cap — worst case 240s (services) + 140s (inline) = 380s,
                # still over the MCP 300s ceiling. Bound it too: give the
                # inline phase whatever budget remains, and skip it entirely
                # if the services phase already consumed the wall.
                remaining = 240 - (loop.time() - wall_start)
                if remaining <= 10:
                    logger.warning("enrich_scan_cves: wall budget exhausted — "
                                   f"skipping {len(inline_cves)} inline CVEs")
                else:
                    inline_cves = inline_cves[:10]
                    inline_budget = min(60.0 + len(inline_cves) * 8.0, remaining)
                    cve_details = await asyncio.gather(
                        *[lookup_cve_all(c, timeout=inline_budget)
                          for c in inline_cves],
                        return_exceptions=True)
                    for cve in cve_details:
                        if isinstance(cve, dict):
                            all_results["inline_cves"][cve.get("cve_id","")] = cve
                            print_cve_card(cve)

            all_cves_flat = []
            for sd in all_results["services"].values():
                for item in sd.get("vulners",[]) + sd.get("nvd",[]):
                    if not any(c.get("cve_id")==item.get("cve_id") for c in all_cves_flat):
                        all_cves_flat.append(item)
            all_cves_flat.extend(all_results["inline_cves"].values())
            all_cves_flat.sort(key=_cvss_sort_key)

            all_results["total_unique_cves"] = len(all_cves_flat)
            cve_summary_lines = [
                f"{c.get('cve_id','?')}: CVSS {c.get('cvss_score','N/A')} | KEV={'Yes' if c.get('cisa_kev') else 'No'} | {c.get('description','')[:80]}"
                for c in all_cves_flat[:20]
            ]
            return {
                "target": target,
                "total_unique_cves": len(all_cves_flat),
                "services_analyzed": list(all_results["services"].keys()),
                "services_count": len(all_results["services"]),
                "inline_cves_count": len(all_results["inline_cves"]),
                "cve_summary": "\n".join(cve_summary_lines),
                "top_cves_detail": "\n\n".join([
                    f"--- {c.get('cve_id','?')} ---\n"
                    f"CVSS: {c.get('cvss_score','N/A')} ({c.get('cvss_severity','')}) | "
                    f"EPSS: {_epss_pct(c.get('epss_score'))}\n"
                    f"CISA KEV: {'Yes' if c.get('cisa_kev') else 'No'} | "
                    f"Published: {c.get('published','')[:10]}\n"
                    f"Description: {c.get('description','')[:150]}\n"
                    f"Exploits: {len(c.get('exploits',[]))} | "
                    f"MSF: {c.get('msf_module','None')} | "
                    f"EDB: {', '.join(c.get('edb_ids',[]))}"
                    for c in all_cves_flat[:20]
                ]),
                "highest_cvss": all_cves_flat[0].get("cvss_score") if all_cves_flat else None,
                "highest_cve": all_cves_flat[0].get("cve_id") if all_cves_flat else None,
            }
        except Exception as e:
            return {"error": str(e), "type": type(e).__name__}

    @mcp.tool(name="download_poc")
    async def download_poc(url: str, cve_id: str = "", target_dir: str = "/opt/pocs") -> Dict:
        """
        Download a PoC/exploit onto the Adara server and inspect it.
        Clones GitHub/GitLab repos (shallow) or fetches raw exploit files.
        Returns the local path, main language, file inventory, README and
        exploit scripts — ready to run against a target.

        Args:
            url:        https://github.com/... or raw file URL (exploit-db raws work)
            cve_id:     optional CVE to organize under /opt/pocs/<cve>/
            target_dir: base directory (default /opt/pocs)
        """
        try:
            console.print(f"[cyan]Downloading PoC:[/] {_markup_escape(url)}")
            result = await download_poc_repo(url, cve_id, target_dir)
            if result.get("ok"):
                _safe_print(f"  Saved to: {result['local_path']}")
                _safe_print(f"  Language: {result.get('main_language','?')} | "
                            f"files: {result.get('file_count',0)}")
                for s in result.get("exploit_scripts", [])[:8]:
                    _safe_print(f"    {s}")
            else:
                _safe_print(f"  Failed: {result.get('error','?')}")
            return result
        except Exception as e:
            return {"ok": False, "error": str(e), "type": type(e).__name__}

    return mcp


# ─────────────────────────────────────────────
# Standalone CLI
# ─────────────────────────────────────────────
async def _cli_main():
    import argparse
    p = argparse.ArgumentParser(description="CVE Enrichment — Vulners + NVD + Exploit-DB + PoC repos")
    p.add_argument("--cve",      help="Look up one CVE, e.g. CVE-2021-44228")
    p.add_argument("--cves",     nargs="+", help="Look up multiple CVEs")
    p.add_argument("--software", help="Software name, e.g. 'vsftpd'")
    p.add_argument("--version",  default="", help="Software version, e.g. '2.3.4'")
    p.add_argument("--scan",     help="Path to nmap/nikto output file to enrich")
    p.add_argument("--poc",      help="Search PoC repos for a CVE, e.g. CVE-2021-44228")
    p.add_argument("--download", help="Download a PoC repo/file (GitHub/GitLab URL)")
    p.add_argument("--dl-dir",   default="/opt/pocs", help="Download base dir (default /opt/pocs)")
    args = p.parse_args()

    if not any([args.cve, args.cves, args.software, args.scan, args.poc, args.download]):
        p.print_help()
        return

    if args.cve:
        print_cve_card(await lookup_cve_all(args.cve))

    if args.cves:
        # FIX: N concurrent lookups at the default 60s wall → NVD rate limiter
        # makes everything past ~#8 time out; scale like the MCP bulk path
        bulk_timeout = 60.0 + len(args.cves) * 8.0
        results = await asyncio.gather(*[lookup_cve_all(c, timeout=bulk_timeout)
                                         for c in args.cves],
                                       return_exceptions=True)
        for r in sorted(results, key=lambda x: _cvss_sort_key(x) if isinstance(x, dict) else 0.0):
            if isinstance(r, dict): print_cve_card(r)

    if args.software:
        res = await search_service_cves_all_deep(args.software, args.version)
        print_service_results(res)
        for cve in res.get("deep_cves") or []:
            print_cve_card(cve)

    if args.scan:
        try:
            with open(args.scan, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except (OSError, IOError) as e:
            console.print(f"[red]Error reading {_markup_escape(args.scan)}: {_markup_escape(str(e))}[/]")
            return
        svcs = _extract_scan_services(text)[:5]
        for svc in svcs:
            print_service_results(await search_service_cves_all(svc.strip()))
        inline = _extract_inline_cves(text)[:5]
        if inline:
            # FIX: same budget scaling as --cves (NVD no-key serialization)
            it = 60.0 + len(inline) * 8.0
            for cve in await asyncio.gather(*[lookup_cve_all(c, timeout=it)
                                              for c in inline],
                                            return_exceptions=True):
                if isinstance(cve, dict):
                    print_cve_card(cve)

    if args.poc:
        print_poc_results(await lookup_poc_all(args.poc))

    if args.download:
        print(json.dumps(await download_poc_repo(args.download, args.cve or "", args.dl_dir),
                         indent=2))

# ─────────────────────────────────────────────
# 4. GITHUB PoC REPO LOOKUP — nomi-sec/PoC-in-GitHub
# ─────────────────────────────────────────────
NOMI_SEC_RAW = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/CVE-{cve_num}.json"

async def lookup_nomisec_cve(cve_id: str) -> Optional[Dict]:
    """
    Fetch PoC repos from nomi-sec/PoC-in-GitHub for a CVE.
    Returns list of repos with html_url, full_name, stars, forks, description.
    """
    cve_id = cve_id.upper().strip()
    if not cve_id.startswith("CVE-"):
        return None
    parts = cve_id.split("-")
    if len(parts) < 3:
        return None
    year = parts[1]
    cve_num = "-".join(parts[1:])
    url = NOMI_SEC_RAW.format(year=year, cve_num=cve_num)
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(url, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 404:
                return {"cve_id": cve_id, "source": "nomi-sec", "repos": [], "count": 0}
            r.raise_for_status()
            data = r.json()
    except Exception as e:
        logger.debug(f"nomi-sec lookup failed for {cve_id}: {e}")
        return None

    repos = []
    for item in data if isinstance(data, list) else []:
        repos.append({
            "full_name": item.get("full_name", ""),
            "html_url": item.get("html_url", ""),
            "description": (item.get("description") or "")[:200],
            "stars": item.get("stargazers_count", 0),
            "forks": item.get("forks_count", 0),
            "owner": (item.get("owner") or {}).get("login", ""),
            "topics": item.get("topics", []),
            "updated_at": item.get("updated_at", ""),
        })
    return {
        "cve_id": cve_id,
        "source": "nomi-sec/PoC-in-GitHub",
        "repos": repos,
        "count": len(repos),
    }


# ─────────────────────────────────────────────
# 5. GITHUB PoC REPO LOOKUP — ycdxsb/PocOrExp_in_Github
# ─────────────────────────────────────────────
YCDXSB_RAW = "https://raw.githubusercontent.com/ycdxsb/PocOrExp_in_Github/main/{year}/README.md"

async def lookup_ycdxsb_cve(cve_id: str) -> Optional[Dict]:
    """
    Fetch PoC repos from ycdxsb/PocOrExp_in_Github for a CVE.
    Parses the markdown README for the year to find repo links.
    """
    cve_id = cve_id.upper().strip()
    if not cve_id.startswith("CVE-"):
        return None
    parts = cve_id.split("-")
    if len(parts) < 3:
        return None
    year = parts[1]
    url = YCDXSB_RAW.format(year=year)

    # whole-year READMEs are ~200-500KB; cache per year, not per CVE
    async def _fetch_readme() -> str:
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.get(url, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 404:
                return ""
            r.raise_for_status()
            return r.text

    try:
        text = await _cached_fetch(f"ycdxsb_readme:{year}", _fetch_readme)
    except Exception as e:
        logger.debug(f"ycdxsb lookup failed for {cve_id}: {e}")
        return None

    if not text:
        return {"cve_id": cve_id, "source": "ycdxsb", "repos": [], "count": 0}

    repos = []
    # Find the CVE section: '## CVE-YYYY-NNNNN' or '### CVE-YYYY-NNNNN'
    # (ycdxsb nests per-CVE headers one level under '## YYYY' year headers).
    # '## ' is a SUBSTRING of '### ', so matching only the two-space form
    # lands at offset 1 of the three-space header; we take the earliest hit
    # of both forms and cut at the next header of EITHER depth.
    idx = -1
    for header in (f"## {cve_id}", f"### {cve_id}"):
        i = text.find(header)
        if i != -1 and (idx == -1 or i < idx):
            idx = i
    if idx == -1:
        return {"cve_id": cve_id, "source": "ycdxsb/PocOrExp_in_Github", "repos": [], "count": 0}

    # Extract from header to the next '## ' or '### ' header — cutting at
    # '\n## ' alone ran the chunk to end-of-file (all later CVEs in the
    # year leaked in as false-positive PoCs).
    chunk = text[idx:]
    next_header = len(chunk)
    for sep in ("\n## ", "\n### "):
        n = chunk.find(sep)
        if n != -1:
            next_header = min(next_header, n)
    chunk = chunk[:next_header]

    # Parse repo links: - [https://github.com/...](https://github.com/...)
    for line in chunk.splitlines():
        line = line.strip()
        if line.startswith("- [") and "github.com" in line:
            # Extract URL from markdown link: - [url](url)
            m = re.search(r'\[(https?://[^\]]+)\]\(https?://[^\)]+\)', line)
            if m:
                url_str = m.group(1).rstrip("/")
                # Try to extract stars/forks from shields badges
                stars = 0
                forks = 0
                s_m = re.search(r'stars/([^/]+)-([\d.]+)', line)
                if s_m:
                    try:
                        stars = int(float(s_m.group(2)))
                    except ValueError:
                        pass
                f_m = re.search(r'forks/([^/]+)-([\d.]+)', line)
                if f_m:
                    try:
                        forks = int(float(f_m.group(2)))
                    except ValueError:
                        pass
                full_name = url_str.replace("https://github.com/", "")
                repos.append({
                    "full_name": full_name,
                    "html_url": url_str,
                    "description": "",
                    "stars": stars,
                    "forks": forks,
                    "owner": full_name.split("/")[0] if "/" in full_name else "",
                })

    return {
        "cve_id": cve_id,
        "source": "ycdxsb/PocOrExp_in_Github",
        "repos": repos,
        "count": len(repos),
    }


# ─────────────────────────────────────────────
# 5b. GITHUB SEARCH API — star-sorted global PoC search
# ─────────────────────────────────────────────
# Direct repo search catches PoCs that the curated lists (nomi-sec/ycdxsb)
# missed. Sort by stars so the most battle-tested PoC lands on top.
_GITHUB_API = "https://api.github.com/search/repositories"

# GitHub Search API: 10 req/min unauthenticated, 30 with token — bulk
# lookups fire 15 concurrent calls, so serialize them with a token bucket.
_gh_search_lock = asyncio.Lock()
_gh_search_last = 0.0
_gh_search_until = 0.0   # FIX: 403/429 cooldown — GitHub returns Retry-After
                         # or X-RateLimit-Reset; without honoring it, a burst
                         # got hard-banned for the rest of the session and
                         # EVERY later bulk lookup burned 15 doomed calls

async def _gh_search_throttle():
    global _gh_search_last, _gh_search_until
    interval = 2.0 if _GITHUB_TOKEN else 6.5
    async with _gh_search_lock:
        now = time.monotonic()
        if now < _gh_search_until:
            await asyncio.sleep(_gh_search_until - now)
            now = time.monotonic()
        wait = interval - (now - _gh_search_last)
        if wait > 0:
            await asyncio.sleep(wait)
        _gh_search_last = time.monotonic()

async def lookup_github_search_cve(cve_id: str, max_results: int = 8) -> Optional[Dict]:
    cve_id = cve_id.upper().strip()
    if not cve_id.startswith("CVE-"):
        return None
    headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": "cve-enrichment/1.0"}
    if _GITHUB_TOKEN:
        headers["Authorization"] = "Bearer " + _GITHUB_TOKEN
    try:
        await _gh_search_throttle()
        async with httpx.AsyncClient(timeout=15) as c:
            # name/description only — 'in:readme' matches 30k-star guide repos
            # that merely mention the CVE, drowning out the actual PoCs
            r = await c.get(_GITHUB_API, params={
                "q": f"{cve_id} in:name,description",
                "sort": "stars", "order": "desc", "per_page": max_results,
            }, headers=headers)
            if r.status_code in (403, 429):
                global _gh_search_until
                retry_after = r.headers.get("Retry-After")
                reset_hdr = r.headers.get("X-RateLimit-Reset")
                cooldown = 60.0
                if retry_after and retry_after.isdigit():
                    cooldown = float(retry_after)
                elif reset_hdr and reset_hdr.isdigit():
                    cooldown = max(1.0, float(reset_hdr) - time.time())
                _gh_search_until = time.monotonic() + cooldown
                logger.warning(f"github search rate-limited ({r.status_code}) — "
                               f"pausing {cooldown:g}s")
                return None
            if r.status_code != 200:
                return None
            items = r.json().get("items", [])
    except Exception as e:
        logger.debug(f"github search failed for {cve_id}: {e}")
        return None
    repos = [{
        "full_name": item.get("full_name", ""),
        "html_url": item.get("html_url", ""),
        "description": (item.get("description") or "")[:200],
        "stars": item.get("stargazers_count", 0),
        "forks": item.get("forks_count", 0),
        "owner": (item.get("owner") or {}).get("login", ""),
        "language": item.get("language") or "",
        "updated_at": item.get("updated_at", ""),
    } for item in items]
    return {
        "cve_id": cve_id,
        "source": "github_search (star-sorted)",
        "repos": repos,
        "count": len(repos),
    }


# ─────────────────────────────────────────────
# 5c. TRICKEST CVE DATABASE — curated per-CVE entries
# ─────────────────────────────────────────────
# trickest/cve stores one Markdown file per CVE: {year}/{cve_id}.md
TRICKEST_RAW = "https://raw.githubusercontent.com/trickest/cve/main/{year}/{cve_id}.md"

async def lookup_trickest_cve(cve_id: str) -> Optional[Dict]:
    cve_id = cve_id.upper().strip()
    if not cve_id.startswith("CVE-"):
        return None
    parts = cve_id.split("-")
    if len(parts) < 3:
        return None
    url = TRICKEST_RAW.format(year=parts[1], cve_id=cve_id)
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(url, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 404:
                return {"cve_id": cve_id, "source": "trickest/cve", "repos": [], "count": 0}
            r.raise_for_status()
            text = r.text
    except Exception as e:
        logger.debug(f"trickest lookup failed for {cve_id}: {e}")
        return None
    repos = []
    seen = set()
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r'-\s+https://github\.com/([^\s)]+)', line)
        if not m:
            continue
        path = m.group(1).rstrip("/")
        parts = path.split("/")
        if len(parts) >= 2 and parts[0] and parts[1] and parts[0] != "search":
            full_name = "/".join(parts[:2])
            if full_name in seen:
                continue
            seen.add(full_name)
            repos.append({
                "full_name": full_name,
                "html_url": "https://github.com/" + full_name,
                "description": "",
                "stars": 0,
                "forks": 0,
                "owner": parts[0],
                "updated_at": "",
            })
    return {
        "cve_id": cve_id,
        "source": "trickest/cve",
        # cap the payload — the full reference list can be thousands of links
        "repos": repos[:20],
        "count": len(repos),
    }


# ─────────────────────────────────────────────
# 6. SPLOITUS.COM exploit search
# ─────────────────────────────────────────────
SPLOITUS_RSS = "https://sploitus.com/rss"

async def lookup_sploitus_cve(cve_id: str) -> Optional[Dict]:
    """
    Search sploitus.com for exploits matching a CVE ID.
    Uses the RSS feed and filters entries by CVE in title.
    Note: only covers the latest ~30 entries.
    """
    cve_id = cve_id.upper().strip()
    if not cve_id.startswith("CVE-"):
        return None
    try:
        async def _fetch_feed() -> str:
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get(SPLOITUS_RSS, headers={"User-Agent": "Mozilla/5.0"})
                r.raise_for_status()
                return r.text
        # the feed is identical for every CVE — cache it 5 min so a bulk
        # lookup doesn't re-download it 15 times
        text = await _cached_fetch("sploitus_rss", _fetch_feed, ttl=300)
    except Exception as e:
        logger.debug(f"sploitus lookup failed: {e}")
        return None

    exploits = []
    try:
        root = ET.fromstring(text)
        # Try Atom format first
        ATOM_NS = "http://www.w3.org/2005/Atom"
        entries = root.findall(f".//{{{ATOM_NS}}}entry")
        is_atom = bool(entries)
        if not entries:
            # Try RSS 2.0 format
            entries = root.findall(".//item")
        for entry in entries:
            if is_atom:
                title_el = entry.find(f"{{{ATOM_NS}}}title")
                link_el = entry.find(f"{{{ATOM_NS}}}link")
                pub_el = entry.find(f"{{{ATOM_NS}}}published")
            else:
                title_el = entry.find("title")
                link_el = entry.find("link")
                pub_el = entry.find("pubDate")
            title = title_el.text if title_el is not None else ""
            link = ""
            if link_el is not None:
                link = link_el.get("href", "") or link_el.text or ""
            pub = pub_el.text[:10] if pub_el is not None and pub_el.text else ""
            if cve_id in title.upper():
                exploits.append({
                    "title": title,
                    "url": link,
                    "published": pub,
                    "source": "sploitus.com",
                })
    except Exception as e:
        logger.debug(f"sploitus parse error: {e}")

    return {
        "cve_id": cve_id,
        "source": "sploitus.com (RSS feed — latest entries only)",
        "exploits": exploits,
        "count": len(exploits),
    }


# ─────────────────────────────────────────────
# 7. PROGRAMMING LANGUAGE FOR PoC REPOS (GitHub API)
# ─────────────────────────────────────────────
_gh_core_rate_limited_until = 0.0  # epoch secs; 0 = not limited. Unauth core
                                  # limits reset hourly — the flag must expire
                                  # or enrichment is lost for the whole run.

def _gh_rate_limited() -> bool:
    global _gh_core_rate_limited_until
    if _gh_core_rate_limited_until and time.time() >= _gh_core_rate_limited_until:
        _gh_core_rate_limited_until = 0.0
    return bool(_gh_core_rate_limited_until)

async def get_repo_language(repo_full_name: str) -> str:
    """Fetch a GitHub repo's primary language via API."""
    global _gh_core_rate_limited_until
    if _gh_rate_limited():
        return ""
    if not repo_full_name or "/" not in repo_full_name:
        return ""
    try:
        headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": "cve-enrichment/1.0"}
        if _GITHUB_TOKEN:
            headers["Authorization"] = "Bearer " + _GITHUB_TOKEN
        async with httpx.AsyncClient(timeout=8) as c:
            r = await c.get("https://api.github.com/repos/" + repo_full_name, headers=headers)
            if r.status_code in (403, 429):
                _gh_core_rate_limited_until = time.time() + 3600
                return ""
            if r.status_code == 200:
                return str(r.json().get("language") or "")
    except Exception:
        pass
    return ""


async def enrich_repos_with_language(repos: list, max_repos: int = 10) -> list:
    """
    Fetch programming language for repos that lack one, in parallel.
    github_search results already carry language — skipping them keeps
    GitHub API calls low (unauthenticated core limit: 60 req/hr).
    """
    to_enrich = [
        r for r in repos[:max_repos]
        if r.get("full_name") and "/" in r["full_name"] and not r.get("language")
    ]
    if not to_enrich:
        return repos

    # probe once — if the core API is rate-limited (403), the remaining
    # calls would all fail; bail out before burning them
    probe_lang = await get_repo_language(to_enrich[0]["full_name"])
    if _gh_rate_limited():
        return repos
    for repo in repos:
        if repo.get("full_name") == to_enrich[0]["full_name"]:
            repo["language"] = probe_lang
            break
    rest = to_enrich[1:]

    if rest:
        langs = await asyncio.gather(*[get_repo_language(r["full_name"]) for r in rest],
                                     return_exceptions=True)
        for i, lang in enumerate(langs):
            if isinstance(lang, str) and i < len(rest):
                for repo in repos:
                    if repo.get("full_name") == rest[i]["full_name"]:
                        repo["language"] = lang
                        break
    return repos


# ─────────────────────────────────────────────
# 8. OTHER EXPLOIT SOURCES (Metasploit, Nuclei)
# ─────────────────────────────────────────────
MSF_DB_URL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/refs/heads/master/db/modules_metadata_base.json"
NUCLEI_DB_URL = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/refs/heads/main/cves.json"

# Inverted CVE -> (module, info) index over the ~7k-module MSF metadata
# dict — built once at download time so per-CVE lookups are O(1) instead
# of a linear scan of every module (the EDB CSV gets the same treatment).
_msf_cve_index: Dict[str, tuple] = {}

def _build_msf_index(msf_db: dict) -> None:
    global _msf_cve_index
    idx: Dict[str, tuple] = {}
    for mod, info in msf_db.items():
        for ref in info.get("references", []) or []:
            if isinstance(ref, str) and ref.upper().startswith("CVE-"):
                idx.setdefault(ref.upper(), (mod, info))
    _msf_cve_index = idx

async def lookup_other_exploit_sources(cve_id: str) -> Dict:
    """Search Metasploit and Nuclei for a CVE ID.

    Both DBs are large (MSF ~1.5MB, Nuclei ~35MB) and are fetched/parsed
    once per 12h via _cached_fetch — the Nuclei file is pre-parsed into a
    {ID: file_path} map so per-CVE lookups are O(1) instead of re-loading
    thousands of JSON lines every time.
    """
    cve_id = cve_id.upper().strip()
    result = {"cve_id": cve_id, "metasploit": "", "exploitdb": "", "nuclei": "", "nuclei_url": ""}

    async def _fetch_msf() -> dict:
        # FIX: 120s > lookup budget — the shielded fetch outlived every
        # awaiter (60s), so the FIRST caller after TTL/restart always
        # reported 'Lookup timed out'. 40s keeps the whole fetch inside
        # the caller's budget.
        async with httpx.AsyncClient(timeout=40) as c:
            r = await c.get(MSF_DB_URL, headers={"User-Agent": "Mozilla/5.0"})
            r.raise_for_status()
            msf_db = r.json()
            _build_msf_index(msf_db)
            return msf_db

    try:
        msf_db = await _cached_fetch("msf_db", _fetch_msf)
        hit = _msf_cve_index.get(cve_id)
        if hit:
            mod, info = hit
            rank_map = {600: "Excellent", 500: "Great", 400: "Good", 300: "Normal", 200: "Average", 100: "Low"}
            # keep the module path clean — "(Rank: X)" appended here would
            # break copy-paste commands like 'use <module> (Rank: Normal)'
            result["metasploit"]      = str(info.get("fullname", mod))
            result["metasploit_rank"] = str(rank_map.get(info.get("rank", 0), "Manual"))
    except Exception as e:
        logger.debug(f"Metasploit lookup failed: {e}")

    async def _fetch_nuclei() -> dict:
        nuclei_map = {}
        # FIX: 120s > lookup budget (see _fetch_msf) — 40s keeps it inside.
        async with httpx.AsyncClient(timeout=40) as c:
            r = await c.get(NUCLEI_DB_URL, headers={"User-Agent": "Mozilla/5.0"})
            r.raise_for_status()
            for line in r.text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if entry.get("ID") and entry.get("file_path"):
                    nuclei_map[entry["ID"].upper()] = entry["file_path"]
        return nuclei_map

    try:
        nuclei_map = await _cached_fetch("nuclei_map", _fetch_nuclei)
        fp = nuclei_map.get(cve_id)
        if fp:
            result["nuclei"] = str(fp)
            result["nuclei_url"] = "https://cloud.projectdiscovery.io/library/" + cve_id
    except Exception as e:
        logger.debug(f"Nuclei template lookup failed: {e}")
    return result


# ─────────────────────────────────────────────
# 9. DOCKER ENVIRONMENT (Vulhub)
# ─────────────────────────────────────────────
VULHUB_TOML_URL = "https://raw.githubusercontent.com/vulhub/vulhub/refs/heads/master/environments.toml"

async def lookup_vulhub_docker(cve_id: str) -> Dict:
    """Search Vulhub for a pre-built Docker environment for the CVE."""
    cve_id = cve_id.upper().strip()
    result = {"cve_id": cve_id, "found": False, "path": "", "setup_steps": ""}

    try:
        import tomllib
    except ImportError:
        # Python < 3.11 — tomllib is third-party there
        import tomli as tomllib

    async def _fetch_toml() -> dict:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get(VULHUB_TOML_URL, headers={"User-Agent": "Mozilla/5.0"})
            r.raise_for_status()
            return tomllib.loads(r.text)

    try:
        config = await _cached_fetch("vulhub_toml", _fetch_toml)
        for env in config.get("environment", []):
            cves = env.get("cve", [])
            if any(c.upper().strip() == cve_id for c in cves):
                path = env.get("path", "")
                result["found"] = True
                result["path"] = str(path)
                result["setup_steps"] = (
                    "1. git clone --depth 1 https://github.com/vulhub/vulhub.git\n"
                    "2. cd vulhub/" + str(path) + "\n"
                    "3. docker compose up -d\n"
                    "4. https://github.com/vulhub/vulhub/tree/master/" + str(path) + "\n"
                    "5. docker compose down"
                )
                break
    except Exception as e:
        logger.debug(f"Vulhub lookup failed: {e}")
    return result


# ─────────────────────────────────────────────
# 10. COMBINED PoC LOOKUP — runs all sources in parallel
# ─────────────────────────────────────────────
async def lookup_poc_all(cve_id: str) -> Dict:
    """
    Query all PoC/exploit sources simultaneously:
      • nomi-sec/PoC-in-GitHub     — curated PoC repos per CVE
      • ycdxsb/PocOrExp_in_Github  — aggregated PoC repos per year
      • trickest/cve               — curated per-CVE entries
      • GitHub Search API          — star-sorted global PoC search
      • sploitus.com               — exploit search results (RSS)
      • Metasploit + Nuclei        — other exploit sources
      • Vulhub Docker environments — pre-built vulnerable environments
    """
    cve_id = cve_id.upper().strip()
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"

    nomi, ycdx, trick, gh_search, sploit, others, docker, edb = await asyncio.gather(
        lookup_nomisec_cve(cve_id),
        lookup_ycdxsb_cve(cve_id),
        lookup_trickest_cve(cve_id),
        lookup_github_search_cve(cve_id),
        lookup_sploitus_cve(cve_id),
        lookup_other_exploit_sources(cve_id),
        lookup_vulhub_docker(cve_id),
        lookup_exploitdb_cve(cve_id),
        return_exceptions=True,
    )

    result = {"cve_id": cve_id}

    all_repos = []
    if isinstance(nomi, dict) and nomi.get("repos"):
        result["nomi_sec"] = nomi
        all_repos.extend(nomi["repos"])
    if isinstance(ycdx, dict) and ycdx.get("repos"):
        result["ycdxsb"] = ycdx
        all_repos.extend(ycdx["repos"])
    if isinstance(trick, dict) and trick.get("repos"):
        result["trickest"] = trick
        all_repos.extend(trick["repos"])
    if isinstance(gh_search, dict) and gh_search.get("repos"):
        result["github_search"] = gh_search
        all_repos.extend(gh_search["repos"])
    if isinstance(sploit, dict) and sploit.get("exploits"):
        result["sploitus"] = sploit

    seen_urls = set()
    unique_repos = []
    for repo in all_repos:
        url = repo.get("html_url", "")
        if url and url not in seen_urls:
            seen_urls.add(url)
            unique_repos.append(repo)

    # sort by stars (like CVE2PoC) — relevance breaks ties only; the
    # keyword search already filtered repos to the CVE, so a huge repo
    # whose name lacks the CVE string is still a top PoC (assetnote case)
    cve_l = cve_id.lower()

    def _relevance(r):
        name = (r.get("full_name") or "").lower()
        desc = (r.get("description") or "").lower()
        if cve_l in name:
            return 2
        if cve_l in desc:
            return 1
        return 0

    unique_repos.sort(key=lambda r: (r.get("stars", 0), _relevance(r), r.get("forks", 0)),
                      reverse=True)
    unique_repos = await enrich_repos_with_language(unique_repos, max_repos=15)

    # cap the returned list — the agent only needs the top matches; the full
    # dedup set can be enormous (trickest alone lists hundreds of links)
    result["all_repos"] = unique_repos[:20]
    result["total_repos"] = len(unique_repos)
    result["sources_queried"] = 8
    result["sources_responded"] = sum(
        1 for x in (nomi, ycdx, trick, gh_search, sploit, others, docker, edb)
        if isinstance(x, dict) and (
            x.get("repos") or x.get("exploits") or
            x.get("metasploit") or x.get("nuclei") or x.get("found")
        ) or isinstance(x, CVEResult) and x.edb_ids
    )

    # keep the agent's context lean — the per-source repo arrays duplicate
    # all_repos (nomi alone can carry 400+ entries); replace with counts
    for key in ("nomi_sec", "ycdxsb", "trickest", "github_search"):
        sub = result.get(key)
        if isinstance(sub, dict):
            repos = sub.get("repos") or []
            result[key] = {
                "source": sub.get("source", key),
                "count": len(repos),
                "top_repos": [
                    {"full_name": r.get("full_name", ""),
                     "stars": r.get("stars", 0),
                     "html_url": r.get("html_url", "")}
                    for r in repos[:10]
                ],
            }

    if isinstance(others, dict):
        result["other_sources"] = others
    if isinstance(docker, dict) and docker.get("found"):
        result["docker"] = docker

    # copy-paste run commands (CVE2PoC-style "PoCs From Other Sources"):
    # msfconsole, searchsploit, nuclei — each ready to execute as-is
    msf_mod, msf_rank, nuclei_tpl = "", "", ""
    if isinstance(others, dict):
        msf_mod    = str(others.get("metasploit") or "")
        msf_rank   = str(others.get("metasploit_rank") or "Normal")
        nuclei_tpl = str(others.get("nuclei") or "")
    edb_ids = []
    if isinstance(sploit, dict):
        for e in sploit.get("exploits") or []:
            m = re.search(r"exploit-db\.com/exploits/(\d+)", str(e.get("url") or e.get("link", "")))
            if m and m.group(1) not in edb_ids:
                edb_ids.append(m.group(1))
    edb_paths = []
    if isinstance(edb, CVEResult):
        for eid in edb.edb_ids:
            if eid not in edb_ids:
                edb_ids.append(eid)
        for ex in edb.exploits:
            if ex.get("path"):
                edb_paths.append(str(ex["path"]))
    run_commands = {}
    if msf_mod:
        # rank goes in a SEPARATE field — inside the -x string it becomes
        # part of the module path and breaks the copy-paste command
        run_commands["metasploit"] = f"msfconsole -q -x 'use {msf_mod}'"
        run_commands["metasploit_rank"] = msf_rank
    if edb_ids:
        # prefer the searchsploit DB path (exploits/multiple/webapps/NNNN.py)
        # exactly like CVE2PoC; plain EDB-IDs work too
        run_commands["exploitdb"] = "searchsploit -m " + \
            " ".join(edb_paths[:3] if edb_paths else edb_ids[:3])
    if nuclei_tpl:
        run_commands["nuclei"] = f"nuclei -t {nuclei_tpl} [-u <target>] [-l <hosts.txt>]"
    if run_commands:
        result["run_commands"] = run_commands

    return result


# ─────────────────────────────────────────────
# 12. PoC DOWNLOAD — clone/fetch a PoC onto the Adara server so the
#     agent can inspect and run it against a target immediately
# ─────────────────────────────────────────────
_DOWNLOAD_ALLOWED_HOSTS = ("github.com", "gitlab.com", "raw.githubusercontent.com",
                           "gist.github.com")
_DL_SCRIPT_EXTS = (".py", ".sh", ".go", ".rb", ".pl", ".php", ".js", ".java",
                   ".c", ".cs", ".ps1", ".exe", ".elf", ".jar", ".zip")
_DL_LANG_MAP = {"py": "Python", "sh": "Shell", "go": "Go", "rb": "Ruby",
                "pl": "Perl", "php": "PHP", "js": "JavaScript", "java": "Java",
                "c": "C", "cs": "C#", "ps1": "PowerShell", "exe": "Windows exe",
                "elf": "Linux binary", "jar": "Java jar", "zip": "Archive"}


def _repo_inventory(dest: str) -> Dict:
    """File inventory of a downloaded PoC: count by type, main language,
    README path, and any exploit scripts."""
    import pathlib
    files = [p for p in pathlib.Path(dest).rglob("*")
             if p.is_file() and ".git" not in str(p)]
    by_ext: Dict[str, int] = {}
    scripts = []
    for p in files:
        ext = p.suffix.lower() or "(none)"
        by_ext[ext] = by_ext.get(ext, 0) + 1
        if ext in _DL_SCRIPT_EXTS:
            scripts.append(str(p))
    main_lang = ""
    if by_ext:
        top = max(by_ext, key=lambda k: by_ext[k])
        main_lang = _DL_LANG_MAP.get(top.lstrip("."), top)
    readme = next((str(p) for p in files
                   if p.name.lower().startswith("readme")), "")
    return {
        "file_count": len(files),
        "main_language": main_lang,
        "extensions": dict(sorted(by_ext.items(), key=lambda kv: -kv[1])[:8]),
        "readme": readme,
        "exploit_scripts": scripts[:15],
    }


async def download_poc_repo(url: str, cve_id: str = "",
                            target_dir: str = "/opt/pocs") -> Dict:
    """Clone a PoC/exploit GitHub repo (or fetch a raw exploit file) onto
    the Adara server so the agent can inspect and run it against a target.
    Returns the local path, file inventory, README path, main language."""
    import subprocess
    import urllib.parse
    url = url.strip()
    try:
        parts = urllib.parse.urlparse(url)
    except ValueError:
        return {"ok": False, "error": "Invalid URL", "url": url}
    if parts.scheme not in ("https", "http") or \
       parts.netloc not in _DOWNLOAD_ALLOWED_HOSTS:
        return {"ok": False,
                "error": f"Only GitHub/GitLab https URLs allowed (got {parts.netloc})",
                "url": url}

    # Path-traversal guard: cve_id / URL-derived name / target_dir are all
    # caller-controlled. Strip path components, then containment-check the
    # realpath — otherwise cve_id='../../etc' or name='..' escapes the
    # sandbox and turns this into an arbitrary-write + chmod +x primitive.
    safe_cve = os.path.basename((cve_id or "").strip().replace("\\", "/"))
    if not safe_cve or safe_cve in (".", ".."):
        safe_cve = ""
    name = parts.path.rstrip("/").split("/")[-1] or safe_cve or "poc"
    name = os.path.basename(name.replace("\\", "/"))
    if name in (".", "..", ""):
        name = "poc"
    base = os.path.realpath(os.path.join(target_dir, safe_cve)) if safe_cve \
        else os.path.realpath(target_dir)
    dest = os.path.realpath(os.path.join(base, name))
    if dest != base and not dest.startswith(base + os.sep):
        return {"ok": False, "error": "Invalid path (traversal blocked)", "url": url}
    i = 1
    while os.path.exists(dest):
        dest = os.path.realpath(os.path.join(base, f"{name}-{i}"))
        i += 1
    os.makedirs(dest, exist_ok=True)

    is_raw_file = parts.netloc in ("raw.githubusercontent.com", "gist.github.com") \
        or parts.path.lower().endswith(_DL_SCRIPT_EXTS)
    try:
        if is_raw_file:
            res = await asyncio.to_thread(
                subprocess.run,
                ["curl", "-fsSL", "-o", os.path.join(dest, name), url],
                timeout=120, capture_output=True)
            if res.returncode != 0:
                shutil.rmtree(dest, ignore_errors=True)   # FIX: no empty-dir litter on failure
                return {"ok": False,
                        "error": (res.stderr or res.stdout or b"").decode(errors="replace")[:300],
                        "url": url}
        else:
            res = await asyncio.to_thread(
                subprocess.run,
                ["git", "clone", "--depth", "1", url, dest],
                timeout=180, capture_output=True)
            if res.returncode != 0:
                shutil.rmtree(dest, ignore_errors=True)   # FIX: no empty-dir litter on failure
                return {"ok": False,
                        "error": (res.stderr or res.stdout or b"").decode(errors="replace")[:300],
                        "url": url}
    except Exception as e:
        shutil.rmtree(dest, ignore_errors=True)
        return {"ok": False, "error": str(e), "url": url}

    inv = _repo_inventory(dest)
    inv["ok"] = True
    inv["local_path"] = dest
    inv["url"] = url
    inv["repo"] = f"{parts.netloc}{parts.path}"
    if inv.get("exploit_scripts") and os.name != "nt":
        for s in inv["exploit_scripts"]:
            if s.endswith((".sh", ".py", ".pl", ".rb")):
                try:
                    os.chmod(s, 0o755)
                except OSError:
                    pass
    return inv


# ─────────────────────────────────────────────
# 11. COMBINED CVE LOOKUP — runs ALL sources (NVD, Vulners, Exploit-DB,
#     PoC repos, Metasploit, Nuclei, Vulhub Docker) in parallel
# ─────────────────────────────────────────────
async def _epss_firstorg(cve_id: str) -> Optional[float]:
    """FIRST.org EPSS API — free, no key. Fallback when Vulners is
    unavailable, so EPSS still shows for every lookup."""
    key = f"epss:{cve_id}"
    cached = _cache_get(key)
    if cached is not _MISS:
        # FIX: a cached failure marker must not be returned as a score
        return None if cached is _FETCH_FAILED else cached
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get("https://api.first.org/data/v1/epss", params={"cve": cve_id})
            r.raise_for_status()
            data = r.json()
        score = None
        for item in data.get("data", []):
            if item.get("cve") == cve_id:
                try:
                    score = float(item.get("epss", 0) or 0)
                except (TypeError, ValueError):
                    score = None
                break
        _cache_put(key, score)
        return score
    except Exception as e:
        logger.debug(f"FIRST.org EPSS lookup failed: {e}")
        # FIX: transient failure cached short-term (was: None cached for 12h)
        _cache_put(key, _FETCH_FAILED, _FAIL_TTL)
        return None


async def lookup_cve_all(cve_id: str, timeout: float = 60.0) -> Dict:
    """Query ALL sources simultaneously: NVD, Vulners, Exploit-DB,
    PoC repos (GitHub), Metasploit, Nuclei, and Vulhub Docker environments.

    timeout: per-lookup budget. Bulk callers MUST scale this — the NVD rate
    limiter serializes requests 7s apart without an API key, so the Nth
    concurrent CVE starts ~N*7s late; a fixed 60s wall makes every lookup
    past ~#8 return "Lookup timed out" (a systematic false-negative)."""
    cve_id = cve_id.upper().strip()
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"
    # FIX: validate before touching any remote source — a bad id previously
    # fired sploitus + searchsploit + GitHub search for nothing
    if not _valid_cve_id(cve_id):
        return {"cve_id": cve_id, "error": f"Invalid CVE id format: {cve_id!r}",
                "type": "ValueError"}

    try:
        vulners_res, nvd_res, edb_res, other_res, poc_res, docker_res, epss_res = await asyncio.wait_for(
            asyncio.gather(
                lookup_vulners_cve(cve_id),
                lookup_nvd_cve(cve_id),
                lookup_exploitdb_cve(cve_id),
                lookup_other_exploit_sources(cve_id),
                lookup_poc_all(cve_id),
                lookup_vulhub_docker(cve_id),
                _epss_firstorg(cve_id),
                return_exceptions=True,
            ),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        logger.warning(f"CVE lookup timed out ({timeout:g}s) for {cve_id}")
        return {
            "cve_id": cve_id, "description": "Lookup timed out",
            "cvss_score": None, "cvss_severity": "", "epss_score": None,
            "published": "", "cisa_kev": False, "references": [],
            "exploits": [], "edb_ids": [], "msf_module": "",
            "sources": [], "risk_summary": "Lookup timed out",
        }

    merged: Dict[str, Any] = {"cve_id": cve_id}

    if isinstance(nvd_res, CVEResult) and nvd_res.description:
        merged.update({
            "description":   nvd_res.description,
            "cvss_score":    nvd_res.cvss_score,
            "cvss_severity": nvd_res.cvss_severity,
            "published":     nvd_res.published,
            "cisa_kev":      nvd_res.cisa_kev,
            "references":    nvd_res.references,
        })
    elif isinstance(vulners_res, CVEResult) and vulners_res.description:
        merged.update({
            "description":   vulners_res.description,
            "cvss_score":    vulners_res.cvss_score,
            "cvss_severity": vulners_res.cvss_severity,
            "published":     vulners_res.published,
            "cisa_kev":      False,
            "references":    vulners_res.references,
        })
    else:
        merged.update({"description":"","cvss_score":None,"cvss_severity":"",
                       "published":"","cisa_kev":False,"references":[]})

    merged["epss_score"]     = vulners_res.epss_score if isinstance(vulners_res, CVEResult) else None
    if merged["epss_score"] is None and isinstance(epss_res, (float, int)):
        merged["epss_score"] = float(epss_res)
    # FIX: wild_exploited derives ONLY from Vulners' exploitation data —
    # NVD's cisaExploitAdd (KEV) means "CISA tracks it", not "confirmed
    # exploited in the wild". KEV stays visible via its own cisa_kev flag.
    merged["wild_exploited"] = isinstance(vulners_res, CVEResult) and vulners_res.wild_exploited

    exploits = []
    if isinstance(vulners_res, CVEResult): exploits.extend(vulners_res.exploits)
    if isinstance(edb_res, CVEResult):     exploits.extend(edb_res.exploits)
    merged["exploits"]   = exploits[:8]
    merged["edb_ids"]    = edb_res.edb_ids    if isinstance(edb_res, CVEResult) else []
    merged["msf_module"] = edb_res.msf_module if isinstance(edb_res, CVEResult) else ""

    if isinstance(poc_res, dict) and poc_res.get("all_repos"):
        merged["poc_repos"] = poc_res["all_repos"][:15]
        merged["poc_total"] = poc_res["total_repos"]
    else:
        merged["poc_repos"] = []
        merged["poc_total"] = 0

    if isinstance(other_res, dict):
        if other_res.get("metasploit"):
            merged["msf_module"] = other_res["metasploit"]
            merged["msf_rank"]   = other_res.get("metasploit_rank", "")
        if other_res.get("nuclei"):
            merged["nuclei_template"] = other_res["nuclei"]
        if other_res.get("nuclei_url"):
            merged["nuclei_url"] = other_res["nuclei_url"]

    if isinstance(docker_res, dict) and docker_res.get("found"):
        merged["docker_env"] = docker_res
    else:
        merged["docker_env"] = {"found": False}

    sources = []
    if isinstance(nvd_res, CVEResult):     sources.append("nvd.nist.gov")
    if isinstance(vulners_res, CVEResult): sources.append("vulners.com")
    if isinstance(edb_res, CVEResult):     sources.append("exploit-db.com")
    if isinstance(poc_res, dict) and poc_res.get("all_repos"): sources.append("github-pocs")
    if isinstance(other_res, dict) and other_res.get("metasploit"): sources.append("metasploit")
    if isinstance(other_res, dict) and other_res.get("nuclei"): sources.append("nuclei")
    if isinstance(docker_res, dict) and docker_res.get("found"): sources.append("vulhub")
    merged["sources"]      = sources
    merged["risk_summary"] = _risk_summary(merged)
    return merged


# ─────────────────────────────────────────────
# Display helpers for PoC results
# ─────────────────────────────────────────────
def print_poc_results(data: Dict):
    """Display PoC repo results — safe ASCII-only output for Windows terminals."""
    cve_id = data.get("cve_id", "?")
    total = data.get("total_repos", 0)
    sources = []
    if data.get('nomi_sec'): sources.append('nomi-sec')
    if data.get('ycdxsb'): sources.append('ycdxsb')
    if data.get('sploitus'): sources.append('sploitus')
    if data.get('docker'): sources.append('vulhub')
    src_str = '+'.join(sources) if sources else 'none'
    _safe_print(f"[CVE] {cve_id}  |  Repos: {total}  |  Sources: {src_str}")
    _safe_print("=" * 70)

    repos = data.get("all_repos", [])
    if not repos:
        _safe_print("  No PoC repositories found for this CVE")
        return

    for i, repo in enumerate(repos[:15], 1):
        name = repo.get("full_name", repo.get("html_url", ""))
        desc = _ascii_safe((repo.get("description") or "")[:80])
        stars = repo.get("stars", 0)
        forks = repo.get("forks", 0)
        lang = repo.get("language", "")
        lang_str = f"  Lang: {lang}" if lang else ""
        _safe_print(f"")
        _safe_print(f"  +--- PoC #{i} {'-' * (50 - len(str(i)))}")
        _safe_print(f"  | Description: {desc}")
        _safe_print(f"  | Clone URL: https://github.com/{name}")
        _safe_print(f"  | Stars: {stars}  |  Forks: {forks}{lang_str}")
        _safe_print(f"  +{'=' * 60}")

    # Show sploitus exploits separately
    if data.get("sploitus") and data["sploitus"].get("exploits"):
        ex = data["sploitus"]["exploits"]
        _safe_print(f"\n  Sploitus.com - {len(ex)} exploit(s):")
        for e in ex:
            _safe_print(f"    {e.get('title','')[:80]}")

    # PoCs From Other Sources (Metasploit, ExploitDB, Nuclei) — copy-paste
    # run commands, same style as CVE2PoC
    other = data.get("other_sources")
    cmds = dict(data.get("run_commands") or {})
    if not cmds and other:
        if other.get("metasploit"):
            # FIX: rank was appended INSIDE the shell command string — a
            # copy-paste would run 'use <module> (Rank: Great)' and fail;
            # print it as a separate line (same fix as run_commands)
            cmds["metasploit"] = f"msfconsole -q -x 'use {other['metasploit']}'"
            if other.get("metasploit_rank"):
                cmds["_msf_rank_note"] = f"(Rank: {other.get('metasploit_rank')})"
        if other.get("nuclei"):
            cmds["nuclei"] = f"nuclei -t {other['nuclei']} [-u <target>] [-l <hosts.txt>]"
    if cmds:
        _safe_print(f"\n  --- PoCs From Other Sources ---")
        if cmds.get("metasploit"):
            _safe_print(f"  Metasploit: {cmds['metasploit']}")
            if cmds.get("_msf_rank_note"):
                _safe_print(f"  {cmds['_msf_rank_note']}")
        if cmds.get("exploitdb"):
            _safe_print(f"  ExploitDB: {cmds['exploitdb']}")
        if cmds.get("nuclei"):
            _safe_print(f"  Nuclei: {cmds['nuclei']}")

    # Docker environment
    docker = data.get("docker")
    if docker and docker.get("found"):
        _safe_print(f"\n  --- Pre-Built Vulnerable Docker Environment ---")
        for line in docker.get("setup_steps", "").split("\n"):
            _safe_print(f"  {line}")


# ─────────────────────────────────────────────
# Standalone CLI entry point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    asyncio.run(_cli_main())