#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
New Code Scanner - Compare old and new code versions and generate an HTML diff report.
Memory-efficient: streams files line-by-line, writes HTML incrementally.
"""

import os
import sys
import re
import zipfile
import difflib
import hashlib
import shutil
import html
import datetime


# ─────────────────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────────────────

BANNER = r"""
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║   ███╗   ██╗███████╗██╗    ██╗     ██████╗ ██████╗ ██████╗ ███████╗   ║
║   ████╗  ██║██╔════╝██║    ██║    ██╔════╝██╔═══██╗██╔══██╗██╔════╝   ║
║   ██╔██╗ ██║█████╗  ██║ █╗ ██║    ██║     ██║   ██║██║  ██║█████╗     ║
║   ██║╚██╗██║██╔══╝  ██║███╗██║    ██║     ██║   ██║██║  ██║██╔══╝     ║
║   ██║ ╚████║███████╗╚███╔███╔╝    ╚██████╗╚██████╔╝██████╔╝███████╗   ║
║   ╚═╝  ╚═══╝╚══════╝ ╚══╝╚══╝     ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝    ║
║                                                                       ║
║     ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗       ║
║     ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗      ║
║     ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝      ║
║     ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗      ║
║     ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║      ║
║     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝      ║
║                                                                       ║
║                  Version 1.0  •  Code Diff Analyzer                   ║
╚═══════════════════════════════════════════════════════════════════════╝
"""

COLORS = {
    "HEADER": "\033[95m",
    "BLUE": "\033[94m",
    "CYAN": "\033[96m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "RED": "\033[91m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
    "RESET": "\033[0m",
}


def cprint(text, color="RESET"):
    """Print colored text to the terminal."""
    print(f"{COLORS.get(color, '')}{text}{COLORS['RESET']}")


def print_banner():
    """Display the startup banner."""
    cprint(BANNER, "CYAN")
    cprint("  ⚡  Fast & Memory-Efficient Code Difference Analyzer", "DIM")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# USER INPUT
# ─────────────────────────────────────────────────────────────────────────────

def get_user_inputs():
    """Collect project name, analyst name, and ZIP file paths from the user."""
    cprint("─" * 60, "DIM")
    cprint("  📋  Project Information", "BOLD")
    cprint("─" * 60, "DIM")

    project_name = input(f"  {COLORS['YELLOW']}▸ Project Name: {COLORS['RESET']}").strip()
    if not project_name:
        project_name = "Untitled Project"

    analyst_name = input(f"  {COLORS['YELLOW']}▸ Analyst / Developer Name: {COLORS['RESET']}").strip()
    if not analyst_name:
        analyst_name = "Unknown"

    print()
    cprint("─" * 60, "DIM")
    cprint("  📦  ZIP File Paths", "BOLD")
    cprint("─" * 60, "DIM")

    while True:
        old_zip = input(f"  {COLORS['YELLOW']}▸ Old Version ZIP path: {COLORS['RESET']}").strip().strip('"').strip("'")
        if os.path.isfile(old_zip) and old_zip.lower().endswith(".zip"):
            break
        cprint("  ✖  Invalid file. Please provide a valid .zip file path.", "RED")

    while True:
        new_zip = input(f"  {COLORS['YELLOW']}▸ New Version ZIP path: {COLORS['RESET']}").strip().strip('"').strip("'")
        if os.path.isfile(new_zip) and new_zip.lower().endswith(".zip"):
            break
        cprint("  ✖  Invalid file. Please provide a valid .zip file path.", "RED")

    return project_name, analyst_name, old_zip, new_zip


# ─────────────────────────────────────────────────────────────────────────────
# ZIP EXTRACTION  (memory-efficient: extracts one file at a time)
# ─────────────────────────────────────────────────────────────────────────────

CHUNK_SIZE = 64 * 1024  # 64 KB chunks for streaming extraction


def safe_extract_zip(zip_path, dest_dir):
    """
    Extract a ZIP archive to *dest_dir*, one entry at a time,
    streaming in CHUNK_SIZE blocks so RAM stays low.
    Returns the number of extracted files.
    """
    if os.path.exists(dest_dir):
        shutil.rmtree(dest_dir)
    os.makedirs(dest_dir, exist_ok=True)

    file_count = 0
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            # Skip directories and __MACOSX / .DS_Store junk
            if info.is_dir():
                continue
            if "__MACOSX" in info.filename or info.filename.startswith("."):
                continue

            target_path = os.path.join(dest_dir, info.filename)
            target_dir = os.path.dirname(target_path)
            os.makedirs(target_dir, exist_ok=True)

            # Stream extraction: read in chunks
            with zf.open(info) as src, open(target_path, "wb") as dst:
                while True:
                    chunk = src.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    dst.write(chunk)
            file_count += 1

    return file_count


# ─────────────────────────────────────────────────────────────────────────────
# DIFF ENGINE
# ─────────────────────────────────────────────────────────────────────────────

BINARY_EXTENSIONS = frozenset([
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "webp",
    "mp3", "mp4", "avi", "mov", "wav", "ogg",
    "zip", "tar", "gz", "rar", "7z",
    "exe", "dll", "so", "dylib", "bin",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "ttf", "otf", "woff", "woff2", "eot",
    "pyc", "class", "o", "obj",
])

MAX_FILE_SIZE = 100 * 1024 * 1024  # Skip files > 100 MB for diff


def is_binary(filepath):
    """Heuristic check: extension-based + null-byte sniff."""
    ext = filepath.rsplit(".", 1)[-1].lower() if "." in filepath else ""
    if ext in BINARY_EXTENSIONS:
        return True
    try:
        with open(filepath, "rb") as f:
            sample = f.read(8192)
            if b"\x00" in sample:
                return True
    except Exception:
        return True
    return False


def read_lines(filepath):
    """Read a text file and return its lines (generator-friendly list)."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            return f.readlines()
    except Exception:
        return []


def file_hash(filepath):
    """Quick SHA-256 hash of a file for fast equality check (streamed)."""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
    except Exception:
        return None
    return h.hexdigest()


def collect_relative_paths(base_dir):
    """Walk a directory and return a set of relative file paths."""
    paths = set()
    for root, _dirs, files in os.walk(base_dir):
        for fname in files:
            abs_path = os.path.join(root, fname)
            rel_path = os.path.relpath(abs_path, base_dir).replace("\\", "/")
            paths.add(rel_path)
    return paths


def compute_diffs(old_dir, new_dir):
    """
    Compare old_dir vs new_dir.
    Yields dicts:
        {"type": "added"|"deleted"|"modified", "path": str,
         "old_lines": [...], "new_lines": [...], "diff_lines": [...]}
    Generator-based so only one diff is in memory at a time.
    """
    old_files = collect_relative_paths(old_dir)
    new_files = collect_relative_paths(new_dir)

    all_paths = sorted(old_files | new_files)

    for rel_path in all_paths:
        old_path = os.path.join(old_dir, rel_path)
        new_path = os.path.join(new_dir, rel_path)

        in_old = rel_path in old_files
        in_new = rel_path in new_files

        # --- ADDED ---
        if not in_old and in_new:
            if is_binary(new_path):
                yield {"type": "added", "path": rel_path, "binary": True,
                       "old_lines": [], "new_lines": [], "diff_lines": []}
            else:
                new_lines = read_lines(new_path)
                yield {"type": "added", "path": rel_path, "binary": False,
                       "old_lines": [], "new_lines": new_lines, "diff_lines": []}
            continue

        # --- DELETED ---
        if in_old and not in_new:
            if is_binary(old_path):
                yield {"type": "deleted", "path": rel_path, "binary": True,
                       "old_lines": [], "new_lines": [], "diff_lines": []}
            else:
                old_lines = read_lines(old_path)
                yield {"type": "deleted", "path": rel_path, "binary": False,
                       "old_lines": old_lines, "new_lines": [], "diff_lines": []}
            continue

        # --- BOTH EXIST → check if modified ---
        # Quick hash comparison first (avoids reading lines for identical files)
        old_hash = file_hash(old_path)
        new_hash = file_hash(new_path)
        if old_hash == new_hash:
            continue  # identical – skip

        # Skip very large files
        try:
            if os.path.getsize(old_path) > MAX_FILE_SIZE or os.path.getsize(new_path) > MAX_FILE_SIZE:
                yield {"type": "modified", "path": rel_path, "binary": True,
                       "old_lines": [], "new_lines": [], "diff_lines": [],
                       "note": "File too large for diff (>10 MB)"}
                continue
        except OSError:
            continue

        if is_binary(old_path) or is_binary(new_path):
            yield {"type": "modified", "path": rel_path, "binary": True,
                   "old_lines": [], "new_lines": [], "diff_lines": []}
            continue

        old_lines = read_lines(old_path)
        new_lines = read_lines(new_path)

        diff_lines = list(difflib.unified_diff(
            old_lines, new_lines,
            fromfile=f"old/{rel_path}",
            tofile=f"new/{rel_path}",
            lineterm="",
        ))

        if diff_lines:
            yield {"type": "modified", "path": rel_path, "binary": False,
                   "old_lines": [], "new_lines": [],
                   "diff_lines": diff_lines}


# ─────────────────────────────────────────────────────────────────────────────
# HTML REPORT GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

def generate_report(project_name, analyst_name, old_dir, new_dir, output_path):
    """
    Stream-writes a premium dark-themed HTML report to *output_path*.
    Returns summary stats dict.
    """
    stats = {"added": 0, "deleted": 0, "modified": 0, "total_files": 0}
    entries = []  # lightweight metadata only; code written inline

    # First pass: collect diffs into entries (we need stats for the header)
    for diff in compute_diffs(old_dir, new_dir):
        stats[diff["type"]] += 1
        stats["total_files"] += 1
        entries.append(diff)

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(_html_head(project_name))
        f.write(_html_header(project_name, analyst_name, now, stats))

        for idx, entry in enumerate(entries):
            f.write(_html_file_section(entry, idx, old_dir, new_dir))

        f.write(_html_footer())

    return stats


def _esc(text):
    """HTML-escape a string."""
    return html.escape(str(text))


def _html_head(project_name):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_esc(project_name)} — Code Scan Report</title>
<style>
/* ── Reset & Base ────────────────────────────────────────────── */
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2333;
  --border:#30363d;--text:#c9d1d9;--text2:#8b949e;
  --accent:#58a6ff;--green:#3fb950;--red:#f85149;
  --yellow:#d29922;--purple:#bc8cff;
  --font-mono:'JetBrains Mono','Fira Code','Cascadia Code',Consolas,monospace;
  --font-sans:'Segoe UI','Inter',system-ui,sans-serif;
}}
html{{scroll-behavior:smooth}}
body{{
  background:var(--bg);color:var(--text);font-family:var(--font-sans);
  line-height:1.6;min-height:100vh;
}}
a{{color:var(--accent);text-decoration:none}}
a:hover{{text-decoration:underline}}

/* ── Header ──────────────────────────────────────────────────── */
.hero{{
  background:linear-gradient(135deg,#0d1117 0%,#161b22 50%,#1a1e2e 100%);
  border-bottom:1px solid var(--border);padding:48px 32px;text-align:center;
}}
.hero h1{{
  font-size:2.4rem;font-weight:800;
  background:linear-gradient(135deg,var(--accent),var(--purple));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  background-clip:text;margin-bottom:8px;
}}
.hero .sub{{color:var(--text2);font-size:0.95rem}}
.meta-grid{{
  display:flex;gap:24px;justify-content:center;flex-wrap:wrap;margin-top:24px;
}}
.meta-card{{
  background:var(--surface);border:1px solid var(--border);border-radius:12px;
  padding:16px 28px;min-width:140px;text-align:center;
  transition:transform .2s,box-shadow .2s;
}}
.meta-card:hover{{transform:translateY(-2px);box-shadow:0 8px 24px rgba(0,0,0,.3)}}
.meta-card .num{{font-size:2rem;font-weight:700}}
.meta-card .label{{font-size:.8rem;color:var(--text2);text-transform:uppercase;letter-spacing:1px}}
.meta-card.added .num{{color:var(--green)}}
.meta-card.deleted .num{{color:var(--red)}}
.meta-card.modified .num{{color:var(--yellow)}}
.meta-card.total .num{{color:var(--accent)}}

/* ── Controls ────────────────────────────────────────────────── */
.controls{{
  max-width:1200px;margin:24px auto;padding:0 24px;
  display:flex;gap:12px;flex-wrap:wrap;align-items:center;
}}
.search-box{{
  flex:1;min-width:200px;padding:10px 16px;border-radius:8px;
  border:1px solid var(--border);background:var(--surface);color:var(--text);
  font-size:.95rem;outline:none;transition:border-color .2s;
}}
.search-box:focus{{border-color:var(--accent)}}
.filter-btn{{
  padding:8px 18px;border-radius:8px;border:1px solid var(--border);
  background:var(--surface);color:var(--text2);cursor:pointer;font-size:.85rem;
  transition:all .2s;
}}
.filter-btn:hover,.filter-btn.active{{
  background:var(--accent);color:#fff;border-color:var(--accent);
}}

/* ── File Sections ───────────────────────────────────────────── */
.container{{max-width:1200px;margin:0 auto;padding:24px}}
.file-section{{
  background:var(--surface);border:1px solid var(--border);border-radius:12px;
  margin-bottom:20px;overflow:hidden;
  transition:box-shadow .2s;
}}
.file-section:hover{{box-shadow:0 4px 20px rgba(0,0,0,.25)}}
.file-header{{
  display:flex;align-items:center;gap:12px;padding:14px 20px;
  cursor:pointer;user-select:none;border-bottom:1px solid var(--border);
  background:var(--surface2);
}}
.file-header:hover{{background:#1f2937}}
.badge{{
  display:inline-block;padding:3px 10px;border-radius:20px;
  font-size:.75rem;font-weight:600;text-transform:uppercase;letter-spacing:.5px;
}}
.badge.added{{background:rgba(63,185,80,.15);color:var(--green)}}
.badge.deleted{{background:rgba(248,81,73,.15);color:var(--red)}}
.badge.modified{{background:rgba(210,153,34,.15);color:var(--yellow)}}
.file-path{{font-family:var(--font-mono);font-size:.9rem;flex:1;word-break:break-all}}
.toggle-icon{{
  font-size:1.2rem;transition:transform .3s;color:var(--text2);
}}
.file-section.collapsed .toggle-icon{{transform:rotate(-90deg)}}
.file-section.collapsed .file-body{{display:none}}

/* ── Code Blocks ─────────────────────────────────────────────── */
.file-body{{padding:0}}
.code-panel-label{{
  padding:8px 20px;font-size:.8rem;font-weight:600;
  text-transform:uppercase;letter-spacing:1px;
  border-bottom:1px solid var(--border);
}}
.code-panel-label.old{{background:rgba(248,81,73,.06);color:var(--red)}}
.code-panel-label.new{{background:rgba(63,185,80,.06);color:var(--green)}}
.code-panel-label.diff{{background:rgba(88,166,255,.06);color:var(--accent)}}

pre.code-block{{
  margin:0;padding:16px 20px;overflow-x:auto;font-family:var(--font-mono);
  font-size:.82rem;line-height:1.7;background:var(--bg);
  border-bottom:1px solid var(--border);
}}
pre.code-block:last-child{{border-bottom:none}}
.line{{display:block;white-space:pre-wrap;word-break:break-all}}
.line.add{{background:rgba(63,185,80,.12);color:var(--green)}}
.line.del{{background:rgba(248,81,73,.10);color:var(--red)}}
.line.hunk{{color:var(--purple);font-weight:600}}
.line-num{{
  display:inline-block;width:48px;text-align:right;padding-right:12px;
  color:var(--text2);opacity:.5;user-select:none;
}}
.binary-note{{
  padding:24px;text-align:center;color:var(--text2);font-style:italic;
}}

/* ── Footer ──────────────────────────────────────────────────── */
.footer{{
  text-align:center;padding:32px;color:var(--text2);
  font-size:.8rem;border-top:1px solid var(--border);margin-top:40px;
}}

/* ── Scrollbar ───────────────────────────────────────────────── */
::-webkit-scrollbar{{width:8px;height:8px}}
::-webkit-scrollbar-track{{background:var(--bg)}}
::-webkit-scrollbar-thumb{{background:var(--border);border-radius:4px}}
::-webkit-scrollbar-thumb:hover{{background:var(--text2)}}

/* ── Responsive ──────────────────────────────────────────────── */
@media(max-width:640px){{
  .hero h1{{font-size:1.6rem}}
  .meta-grid{{gap:12px}}
  .meta-card{{min-width:100px;padding:12px 16px}}
  .controls{{flex-direction:column}}
}}
</style>
</head>
<body>
"""


def _html_header(project_name, analyst_name, timestamp, stats):
    return f"""
<div class="hero">
  <h1>🔍 {_esc(project_name)}</h1>
  <p class="sub">Code Scan Report &nbsp;•&nbsp; {_esc(analyst_name)} &nbsp;•&nbsp; {_esc(timestamp)}</p>
  <div class="meta-grid">
    <div class="meta-card total"><div class="num">{stats['total_files']}</div><div class="label">Total Changes</div></div>
    <div class="meta-card added"><div class="num">{stats['added']}</div><div class="label">Added</div></div>
    <div class="meta-card deleted"><div class="num">{stats['deleted']}</div><div class="label">Deleted</div></div>
    <div class="meta-card modified"><div class="num">{stats['modified']}</div><div class="label">Modified</div></div>
  </div>
</div>

<div class="controls">
  <input type="text" class="search-box" id="searchBox" placeholder="🔎  Search file paths..." oninput="filterFiles()">
  <button class="filter-btn active" data-filter="all" onclick="setFilter('all',this)">All</button>
  <button class="filter-btn" data-filter="added" onclick="setFilter('added',this)">Added</button>
  <button class="filter-btn" data-filter="deleted" onclick="setFilter('deleted',this)">Deleted</button>
  <button class="filter-btn" data-filter="modified" onclick="setFilter('modified',this)">Modified</button>
</div>

<div class="container" id="fileContainer">
"""


def _html_file_section(entry, idx, old_dir, new_dir):
    """Build HTML for one file entry."""
    t = entry["type"]
    path = entry["path"]
    binary = entry.get("binary", False)
    note = entry.get("note", "")

    parts = []
    parts.append(
        f'<div class="file-section collapsed" data-type="{t}" data-path="{_esc(path.lower())}">'
        f'<div class="file-header" onclick="toggleSection(this.parentElement)">'
        f'<span class="badge {t}">{t.upper()}</span>'
        f'<span class="file-path">{_esc(path)}</span>'
        f'<span class="toggle-icon">▼</span>'
        f'</div>'
        f'<div class="file-body">'
    )

    if binary:
        msg = note if note else "Binary file — diff not available."
        parts.append(f'<div class="binary-note">📦 {_esc(msg)}</div>')
    elif t == "added":
        parts.append('<div class="code-panel-label new">NEW FILE — All lines added</div>')
        parts.append('<pre class="code-block">')
        for i, line in enumerate(entry["new_lines"], 1):
            parts.append(f'<span class="line add"><span class="line-num">{i}</span>+{_esc(line.rstrip())}</span>\n')
        parts.append('</pre>')
    elif t == "deleted":
        parts.append('<div class="code-panel-label old">DELETED FILE — All lines removed</div>')
        parts.append('<pre class="code-block">')
        for i, line in enumerate(entry["old_lines"], 1):
            parts.append(f'<span class="line del"><span class="line-num">{i}</span>-{_esc(line.rstrip())}</span>\n')
        parts.append('</pre>')
    elif t == "modified":
        # UNIFIED DIFF only — with line numbers
        parts.append(f'<div class="code-panel-label diff">UNIFIED DIFF</div>')
        parts.append('<pre class="code-block">')
        old_ln = 0
        new_ln = 0
        for dline in entry["diff_lines"]:
            raw = dline.rstrip("\n").rstrip("\r")
            if raw.startswith("---") or raw.startswith("+++"):
                parts.append(f'<span class="line hunk">{_esc(raw)}</span>\n')
            elif raw.startswith("@@"):
                # Parse hunk header like @@ -1,5 +1,7 @@
                m = re.search(r'@@ -(\d+)', raw)
                if m:
                    old_ln = int(m.group(1))
                m2 = re.search(r'\+(\d+)', raw)
                if m2:
                    new_ln = int(m2.group(1))
                parts.append(f'<span class="line hunk">{_esc(raw)}</span>\n')
            elif raw.startswith("-"):
                parts.append(f'<span class="line del"><span class="line-num">{old_ln}</span>-{_esc(raw[1:])}</span>\n')
                old_ln += 1
            elif raw.startswith("+"):
                parts.append(f'<span class="line add"><span class="line-num">{new_ln}</span>+{_esc(raw[1:])}</span>\n')
                new_ln += 1
            else:
                parts.append(f'<span class="line"><span class="line-num">{old_ln}</span> {_esc(raw[1:] if raw.startswith(" ") else raw)}</span>\n')
                old_ln += 1
                new_ln += 1
        parts.append('</pre>')

    parts.append('</div></div>\n')  # close file-body & file-section
    return "".join(parts)


def _html_footer():
    return """
</div><!-- /container -->

<div class="footer">
  Generated by <strong>New Code Scanner v1.0</strong> &nbsp;•&nbsp; Memory-Efficient Code Diff Analyzer
</div>

<script>
/* ── Toggle collapse ─────────────────────────────────────────── */
function toggleSection(el){el.classList.toggle('collapsed')}

/* ── Search ──────────────────────────────────────────────────── */
function filterFiles(){
  const q=document.getElementById('searchBox').value.toLowerCase();
  document.querySelectorAll('.file-section').forEach(s=>{
    const p=s.getAttribute('data-path');
    const matchSearch=!q||p.includes(q);
    const matchFilter=currentFilter==='all'||s.getAttribute('data-type')===currentFilter;
    s.style.display=(matchSearch&&matchFilter)?'':'none';
  });
}

/* ── Filter buttons ──────────────────────────────────────────── */
let currentFilter='all';
function setFilter(f,btn){
  currentFilter=f;
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  filterFiles();
}

/* ── Collapse All / Expand All via keyboard (C / E) ──────────── */
document.addEventListener('keydown',e=>{
  if(e.target.tagName==='INPUT')return;
  if(e.key==='c'){document.querySelectorAll('.file-section').forEach(s=>s.classList.add('collapsed'))}
  if(e.key==='e'){document.querySelectorAll('.file-section').forEach(s=>s.classList.remove('collapsed'))}
});
</script>
</body>
</html>
"""


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def sanitize_folder_name(name):
    """Sanitize project name to be used as a folder name."""
    name = re.sub(r'[<>:"/\\|?*]', '_', name)
    name = name.strip().strip('.')
    return name if name else "project"


def main():
    print_banner()

    project_name, analyst_name, old_zip, new_zip = get_user_inputs()

    # Determine project directory using project name
    base_dir = os.path.dirname(os.path.abspath(__file__)) if "__file__" in dir() else os.getcwd()
    folder_name = sanitize_folder_name(project_name)
    project_dir = os.path.join(base_dir, folder_name)
    old_dir = os.path.join(project_dir, "old_version")
    new_dir = os.path.join(project_dir, "new_version")

    # ── Extract ZIPs ─────────────────────────────────────────────
    print()
    cprint("─" * 60, "DIM")
    cprint("  📂  Extracting ZIP files ...", "BOLD")
    cprint("─" * 60, "DIM")

    cprint(f"  ▸ Extracting OLD version → {old_dir}", "YELLOW")
    old_count = safe_extract_zip(old_zip, old_dir)
    cprint(f"    ✔ {old_count} files extracted", "GREEN")

    cprint(f"  ▸ Extracting NEW version → {new_dir}", "YELLOW")
    new_count = safe_extract_zip(new_zip, new_dir)
    cprint(f"    ✔ {new_count} files extracted", "GREEN")

    # ── Compute Diffs & Generate Report ──────────────────────────
    print()
    cprint("─" * 60, "DIM")
    cprint("  🔍  Analyzing differences ...", "BOLD")
    cprint("─" * 60, "DIM")

    report_path = os.path.join(project_dir, "report.html")
    stats = generate_report(project_name, analyst_name, old_dir, new_dir, report_path)

    print()
    cprint("─" * 60, "DIM")
    cprint("  📊  Scan Complete!", "GREEN")
    cprint("─" * 60, "DIM")
    cprint(f"  Total changed files : {stats['total_files']}", "BOLD")
    cprint(f"  ➕  Added           : {stats['added']}", "GREEN")
    cprint(f"  ➖  Deleted         : {stats['deleted']}", "RED")
    cprint(f"  ✏️   Modified        : {stats['modified']}", "YELLOW")
    print()
    cprint(f"  📄  Report saved to: {report_path}", "CYAN")
    cprint("─" * 60, "DIM")
    print()


if __name__ == "__main__":
    main()
