#!/usr/bin/env python3
"""
SNMP Walk Player — simulate a customer's exact device from their snmpwalk.
Run: python3 snmp-walkplayer.py
Then open: http://localhost:7374
"""

import http.server
import json
import os
import queue
import re
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from urllib.parse import urlparse

try:
    import yaml
except ImportError:
    sys.exit("ERROR: PyYAML not installed. Run: pip3 install pyyaml")

# ── Config ─────────────────────────────────────────────────────────────────────

AGENT_CONF       = "/opt/datadog-agent/etc/conf.d/snmp.d/conf.yaml"
AGENT_BIN        = "/opt/datadog-agent/bin/agent/agent"
DEFAULT_PROFILES = "/opt/datadog-agent/etc/conf.d/snmp.d/default_profiles"
USER_PROFILES    = "/opt/datadog-agent/etc/conf.d/snmp.d/profiles"
WALK_DIR         = os.path.expanduser("~/snmpsim-walkdata")
WALK_FILE        = os.path.join(WALK_DIR, "public.snmprec")
SNMP_PORT        = 1162   # native snmpsim — no Docker UDP forwarding issues
SNMPSIM_BIN      = "snmpsim-command-responder"  # installed via pip3 install snmpsim-lextudio
PORT             = 7374

# ── snmpwalk parser ────────────────────────────────────────────────────────────

TYPE_MAP = {
    "INTEGER": 2, "Integer32": 2,
    "STRING": 4, "OctetString": 4, "Hex-STRING": 4, "BITS": 4, "Bits": 4,
    "OID": 6, "OBJECT IDENTIFIER": 6,
    "IpAddress": 64, "Network Address": 64,
    "Counter32": 65,
    "Gauge32": 66, "Unsigned32": 66,
    "Timeticks": 67, "TimeTicks": 67,
    "Opaque": 68,
    "Counter64": 70,
}

def _parse_value(type_str, val_str):
    if type_str == "Hex-STRING":
        hex_clean = val_str.replace(" ", "").replace(":", "")
        return f"0x{hex_clean}" if hex_clean else "0x00"
    if type_str in ("Timeticks", "TimeTicks"):
        m = re.match(r'\((\d+)\)', val_str)
        return m.group(1) if m else "0"
    if type_str in ("OID", "OBJECT IDENTIFIER"):
        return val_str.lstrip(".")
    if type_str == "STRING":
        if val_str.startswith('"') and val_str.endswith('"'):
            val_str = val_str[1:-1]
        return val_str
    if type_str in ("BITS", "Bits"):
        hex_clean = val_str.replace(" ", "")
        return f"0x{hex_clean}" if hex_clean else "0x00"
    # INTEGER, Counter32, Gauge32, etc — handle enum(N) format
    m = re.match(r'.*\((\d+)\)\s*$', val_str)
    if m:
        return m.group(1)
    return val_str.strip()

def parse_walk(text):
    """Parse snmpwalk text into list of (oid, type_code, value) tuples."""
    entries = []
    current_oid = current_tc = current_val = None

    def flush():
        if current_oid and current_tc is not None and current_val is not None:
            entries.append((current_oid, current_tc, current_val))

    for raw in text.splitlines():
        line = raw.rstrip()
        # Numeric OID line: .1.3.6... = TYPE: value
        m = re.match(r'^(\.[0-9.]+)\s*=\s*(.+)$', line)
        if m:
            flush()
            oid = m.group(1).lstrip(".")
            rest = m.group(2)
            tm = re.match(r'([A-Za-z0-9 _-]+):\s*(.*)', rest)
            if not tm:
                current_oid = current_tc = current_val = None
                continue
            type_str = tm.group(1).strip()
            val_str  = tm.group(2).strip()
            tc = TYPE_MAP.get(type_str)
            if tc is None:
                current_oid = current_tc = current_val = None
                continue
            current_oid = oid
            current_tc  = tc
            current_val = _parse_value(type_str, val_str)
            continue

        # MIB-name format line (e.g. SNMPv2-MIB::sysDescr.0 = ...) — skip
        if re.match(r'^[A-Za-z].*::.*=', line):
            flush()
            current_oid = current_tc = current_val = None
            continue

        # Continuation of multi-line string value — collapse to single line for snmprec
        if current_oid and current_tc == 4 and line:
            current_val = (current_val or "") + " " + line.strip()

    flush()
    return entries

def _oid_key(oid):
    try:
        return tuple(int(x) for x in oid.split("."))
    except ValueError:
        return (999999,)

def walk_to_snmprec(text):
    entries = parse_walk(text)
    oid_map = {}
    for oid, tc, val in entries:
        if oid and val is not None:
            oid_map[oid] = (tc, str(val))
    return [f"{oid}|{tc}|{val}"
            for oid, (tc, val) in sorted(oid_map.items(), key=lambda kv: _oid_key(kv[0]))]

def extract_device_info(text):
    info = {"descr": "—", "objectid": "—", "name": "—", "oid_count": 0}
    entries = parse_walk(text)
    info["oid_count"] = len(entries)
    for oid, tc, val in entries:
        if oid == "1.3.6.1.2.1.1.1.0":
            info["descr"] = val[:120] + ("…" if len(val) > 120 else "")
        elif oid == "1.3.6.1.2.1.1.2.0":
            info["objectid"] = val
        elif oid == "1.3.6.1.2.1.1.5.0":
            info["name"] = val
    return info

def find_matching_profile(sys_object_id):
    if not sys_object_id or sys_object_id == "—":
        return None
    oid = sys_object_id.lstrip(".")
    for d in [USER_PROFILES, DEFAULT_PROFILES]:
        if not os.path.isdir(d):
            continue
        for fname in sorted(os.listdir(d)):
            if not fname.endswith(".yaml") or fname.startswith("_"):
                continue
            try:
                with open(os.path.join(d, fname)) as f:
                    data = yaml.safe_load(f) or {}
                for syso in data.get("sysobjectid", []):
                    pattern = str(syso).lstrip(".")
                    if "*" in pattern:
                        regex = re.escape(pattern).replace(r"\*", r"[0-9.]*")
                        if re.fullmatch(regex, oid):
                            return fname[:-5]
                    elif pattern == oid:
                        return fname[:-5]
            except Exception:
                continue
    return None

# ── Agent helpers ──────────────────────────────────────────────────────────────

def write_agent_conf(profile_name):
    conf = f"""instances:
  - ip_address: "127.0.0.1"
    port: {SNMP_PORT}
    community_string: "public"
    snmp_version: 2
    profile: {profile_name}
    tags:
      - "snmp_walkplayer:true"
"""
    try:
        with open(AGENT_CONF, "w") as f:
            f.write(conf)
        return True
    except PermissionError:
        r = subprocess.run(["sudo", "tee", AGENT_CONF],
                           input=conf, capture_output=True, text=True)
        return r.returncode == 0

def restart_agent():
    uid = subprocess.run(["id", "-u"], capture_output=True, text=True).stdout.strip()
    r = subprocess.run(
        ["launchctl", "kickstart", "-k", f"gui/{uid}/com.datadoghq.agent"],
        capture_output=True)
    time.sleep(2)
    return r.returncode == 0

_snmpsim_proc = None  # native snmpsim subprocess handle

def get_status():
    global _snmpsim_proc
    running = _snmpsim_proc is not None and _snmpsim_proc.poll() is None
    profile = None
    try:
        with open(AGENT_CONF) as f:
            for line in f:
                m = re.search(r"profile:\s*(\S+)", line)
                if m:
                    profile = m.group(1)
                    break
    except Exception:
        pass
    return {
        "container": "running" if running else "stopped",
        "running": running,
        "profile": profile or "—",
        "endpoint": f"127.0.0.1:{SNMP_PORT}/udp" if running else "—",
    }

# ── SSE broadcast ──────────────────────────────────────────────────────────────

_log_clients = []
_log_lock    = threading.Lock()
_state       = {"walk_text": None, "device_info": None, "profile": None}

def broadcast(data):
    msg = f"data: {json.dumps(data)}\n\n"
    with _log_lock:
        dead = []
        for q in _log_clients:
            try:
                q.put_nowait(msg)
            except Exception:
                dead.append(q)
        for q in dead:
            _log_clients.remove(q)

def log(line, tag=""):
    broadcast({"type": "log", "line": line, "tag": tag})

def run_simulation():
    def _worker():
        broadcast({"type": "start"})
        walk_text = _state.get("walk_text")
        profile   = _state.get("profile")

        if not walk_text:
            log("No walk file loaded.", "err")
            broadcast({"type": "done"})
            return
        try:
            log("Parsing walk file…")
            lines = walk_to_snmprec(walk_text)
            log(f"  ✓ {len(lines)} OIDs parsed", "ok")

            os.makedirs(WALK_DIR, exist_ok=True)
            with open(WALK_FILE, "w") as f:
                f.write("\n".join(lines) + "\n")
            log(f"  ✓ Walk written to {WALK_FILE}", "ok")

            log("Starting SNMP simulator…")
            global _snmpsim_proc
            # Kill any running instance
            if _snmpsim_proc and _snmpsim_proc.poll() is None:
                _snmpsim_proc.terminate()
                _snmpsim_proc.wait()
            # Also kill any stale process on the port
            subprocess.run(
                ["bash", "-c", f"lsof -ti udp:{SNMP_PORT} | xargs kill -9 2>/dev/null || true"],
                capture_output=True)
            cache_dir = os.path.expanduser("~/snmpsim-cache")
            os.makedirs(cache_dir, exist_ok=True)
            cmd = [
                SNMPSIM_BIN,
                f"--data-dir={WALK_DIR}",
                f"--agent-udpv4-endpoint=127.0.0.1:{SNMP_PORT}",
                f"--cache-dir={cache_dir}",
            ]
            _snmpsim_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(3)
            if _snmpsim_proc.poll() is not None:
                log("  ✗ snmpsim failed to start", "err")
                broadcast({"type": "done"})
                return
            log(f"  ✓ snmpsim on 127.0.0.1:{SNMP_PORT}/udp  (community: public)", "ok")

            log("Updating Datadog Agent config…")
            if profile:
                if write_agent_conf(profile):
                    log(f"  ✓ Profile: {profile}", "ok")
                else:
                    log("  ! Could not write conf.yaml — check sudo permissions", "warn")
            else:
                log("  ! No matching profile found — update conf.yaml manually", "warn")

            log("Restarting Datadog Agent…")
            if restart_agent():
                log("  ✓ Agent restarted", "ok")
            else:
                log("  ! Agent restart failed — restart manually", "warn")

            log("\n━━━ Simulation active ━━━", "done")
            if profile:
                log(f"  Profile  : {profile}", "dim")
            else:
                log("  Profile  : none matched — set manually in conf.yaml", "dim")
            log(f"  Endpoint : 127.0.0.1:{SNMP_PORT}  community=public", "dim")
            log("  Metrics appear in Datadog NDM in ~1-2 min.", "dim")

        except Exception as ex:
            log(f"Error: {ex}", "err")
        broadcast({"type": "done"})

    threading.Thread(target=_worker, daemon=True).start()

# ── HTML ───────────────────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SNMP Walk Player</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    font-size: 14px;
    background: #f6f8fa;
    color: #1f2328;
    height: 100vh;
    display: flex;
    flex-direction: column;
  }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 20px;
    background: #fff;
    border-bottom: 1px solid #d0d7de;
    flex-shrink: 0;
  }
  header h1 { font-size: 16px; font-weight: 600; }
  #badge {
    font-size: 13px; padding: 3px 10px;
    border-radius: 20px; background: #eaeef2; color: #57606a;
  }
  #badge.running { background: #dafbe1; color: #1a7f37; }

  main { display: flex; flex: 1; overflow: hidden; }

  aside {
    width: 280px; flex-shrink: 0;
    border-right: 1px solid #d0d7de;
    background: #fff;
    display: flex; flex-direction: column;
    padding: 12px; gap: 10px;
  }
  aside h2 {
    font-size: 12px; font-weight: 600; color: #57606a;
    text-transform: uppercase; letter-spacing: .05em;
  }

  /* Drop zone */
  #dropzone {
    border: 2px dashed #d0d7de;
    border-radius: 8px;
    padding: 24px 12px;
    text-align: center;
    cursor: pointer;
    transition: border-color .15s, background .15s;
    flex-shrink: 0;
  }
  #dropzone:hover, #dropzone.dragover {
    border-color: #0969da;
    background: #f0f6ff;
  }
  #dropzone.loaded {
    border-color: #1a7f37;
    border-style: solid;
    background: #f0fdf4;
  }
  #dropzone .dz-icon { font-size: 28px; margin-bottom: 6px; }
  #dropzone .dz-label { font-size: 13px; color: #57606a; }
  #dropzone .dz-sub   { font-size: 11px; color: #8c959f; margin-top: 4px; }
  #file-input { display: none; }

  /* Device info */
  .info-table { width: 100%; border-collapse: collapse; }
  .info-table td { font-size: 12px; padding: 3px 0; vertical-align: top; }
  .info-table td:first-child { color: #57606a; width: 72px; flex-shrink: 0; }
  .info-table td:last-child  { font-family: "SF Mono","Menlo",monospace; word-break: break-all; }
  .match-badge {
    display: inline-block;
    font-size: 11px; padding: 2px 8px;
    border-radius: 20px; margin-top: 2px;
  }
  .match-badge.found   { background: #dafbe1; color: #1a7f37; }
  .match-badge.missing { background: #fff8c5; color: #9a6700; }

  section {
    flex: 1; display: flex; flex-direction: column;
    padding: 16px; gap: 12px; overflow: hidden;
  }
  .card {
    background: #fff; border: 1px solid #d0d7de;
    border-radius: 8px; padding: 14px 16px;
  }
  .card h2 {
    font-size: 12px; font-weight: 600; color: #57606a;
    text-transform: uppercase; letter-spacing: .05em; margin-bottom: 10px;
  }
  .stat-grid { display: grid; grid-template-columns: 90px 1fr; gap: 4px 8px; }
  .stat-label { font-size: 12px; color: #57606a; }
  .stat-value { font-size: 12px; font-family: "SF Mono","Menlo",monospace; }
  .stat-value.running { color: #1a7f37; }
  .stat-value.stopped { color: #57606a; }

  .card.log-card { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
  #log {
    flex: 1; overflow-y: auto;
    font-family: "SF Mono","Menlo",monospace;
    font-size: 12px; line-height: 1.6;
    white-space: pre-wrap; word-break: break-all;
  }
  .log-ok   { color: #1a7f37; }
  .log-err  { color: #cf222e; }
  .log-warn { color: #9a6700; }
  .log-dim  { color: #656d76; }
  .log-head { font-weight: 700; }
  .log-done { color: #6f42c1; font-weight: 700; }

  .btn-row { display: flex; gap: 8px; flex-shrink: 0; }
  button {
    padding: 6px 14px; border: 1px solid #d0d7de;
    border-radius: 6px; background: #f6f8fa;
    font-size: 13px; cursor: pointer; font-family: inherit;
  }
  button:hover  { background: #eaeef2; }
  button.primary { background: #0969da; color: #fff; border-color: #0969da; }
  button.primary:hover { background: #0860ca; }
  button:disabled { opacity: .5; cursor: not-allowed; }
</style>
</head>
<body>
<header>
  <h1>SNMP Walk Player</h1>
  <span id="badge">● stopped</span>
</header>
<main>
  <aside>
    <h2>Customer Walk File</h2>

    <div id="dropzone" onclick="document.getElementById('file-input').click()">
      <div class="dz-icon" id="dz-icon">📂</div>
      <div class="dz-label" id="dz-label">Drop walk file here</div>
      <div class="dz-sub">or click to browse</div>
    </div>
    <input type="file" id="file-input" accept=".txt,.snmpwalk,.walk">

    <h2>Device Info</h2>
    <table class="info-table" id="device-info">
      <tr><td>Name</td>     <td id="d-name">—</td></tr>
      <tr><td>OID</td>      <td id="d-oid">—</td></tr>
      <tr><td>OIDs</td>     <td id="d-count">—</td></tr>
      <tr><td>Profile</td>  <td id="d-profile">—</td></tr>
      <tr><td>Descr</td>    <td id="d-descr" style="color:#57606a;font-family:inherit">—</td></tr>
    </table>
  </aside>

  <section>
    <div class="card">
      <h2>Status</h2>
      <div class="stat-grid">
        <span class="stat-label">Container</span> <span class="stat-value" id="s-container">—</span>
        <span class="stat-label">Profile</span>   <span class="stat-value" id="s-profile">—</span>
        <span class="stat-label">Endpoint</span>  <span class="stat-value" id="s-endpoint">—</span>
      </div>
    </div>
    <div class="card log-card">
      <h2>Log</h2>
      <div id="log"></div>
    </div>
    <div class="btn-row">
      <button class="primary" id="btn-simulate" onclick="startSimulation()" disabled>▶  Simulate Device</button>
      <button onclick="refreshStatus()">↻  Refresh</button>
      <button onclick="stopSimulation()">■  Stop</button>
    </div>
  </section>
</main>

<script>
let walkLoaded = false;
let busy = false;

// ── File handling ─────────────────────────────────────────────────────────────
const dropzone  = document.getElementById('dropzone');
const fileInput = document.getElementById('file-input');

dropzone.addEventListener('dragover',  e => { e.preventDefault(); dropzone.classList.add('dragover'); });
dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
dropzone.addEventListener('drop', e => {
  e.preventDefault();
  dropzone.classList.remove('dragover');
  const file = e.dataTransfer.files[0];
  if (file) loadFile(file);
});
fileInput.addEventListener('change', e => {
  if (e.target.files[0]) loadFile(e.target.files[0]);
});

function loadFile(file) {
  // Show parsing indicator immediately
  document.getElementById('dz-icon').textContent = '⏳';
  document.getElementById('dz-label').textContent = `Parsing ${file.name}…`;

  const run = async () => {
    // Stream file directly via FormData — no size limit, no JS memory spike
    const form = new FormData();
    form.append('file', file);
    const res = await fetch('/api/upload', { method: 'POST', body: form });
    const info = await res.json();

    // Update drop zone
    dropzone.classList.add('loaded');
    document.getElementById('dz-icon').textContent = '✅';
    document.getElementById('dz-label').textContent = file.name;

    // Update device info
    document.getElementById('d-name').textContent  = info.name;
    document.getElementById('d-oid').textContent   = info.objectid;
    document.getElementById('d-count').textContent = info.oid_count + ' OIDs';
    document.getElementById('d-descr').textContent = info.descr;

    const profileEl = document.getElementById('d-profile');
    if (info.profile) {
      profileEl.innerHTML = `<span class="match-badge found">✓ ${info.profile}</span>`;
    } else {
      profileEl.innerHTML = `<span class="match-badge missing">⚠ no match found</span>`;
    }

    walkLoaded = true;
    document.getElementById('btn-simulate').disabled = false;
  };
  run().catch(err => console.error('Upload failed:', err));
}

// ── Status ────────────────────────────────────────────────────────────────────
async function refreshStatus() {
  const s = await fetch('/api/status').then(r => r.json());
  const badge = document.getElementById('badge');
  badge.textContent = s.running ? `● ${s.profile}` : '● stopped';
  badge.className   = s.running ? 'running' : '';
  set('s-container', s.container, s.running ? 'running' : 'stopped');
  set('s-profile',   s.profile,   '');
  set('s-endpoint',  s.endpoint,  '');
}

function set(id, text, cls) {
  const el = document.getElementById(id);
  el.textContent = text;
  el.className = 'stat-value ' + cls;
}

// ── Log (SSE) ─────────────────────────────────────────────────────────────────
const logEl = document.getElementById('log');

function appendLog(line, tag) {
  const span = document.createElement('span');
  span.className = tag ? `log-${tag}` : '';
  span.textContent = line + '\n';
  logEl.appendChild(span);
  logEl.scrollTop = logEl.scrollHeight;
}

const es = new EventSource('/api/log-stream');
es.onmessage = e => {
  const msg = JSON.parse(e.data);
  if      (msg.type === 'log')   appendLog(msg.line, msg.tag);
  else if (msg.type === 'start') { appendLog('\n── Simulation starting ──', 'head'); setBusy(true); }
  else if (msg.type === 'done')  { setBusy(false); refreshStatus(); }
};

// ── Actions ───────────────────────────────────────────────────────────────────
async function startSimulation() {
  if (!walkLoaded || busy) return;
  await fetch('/api/simulate', { method: 'POST' });
}

async function stopSimulation() {
  await fetch('/api/stop', { method: 'POST' });
  appendLog('■ Stopped.', 'warn');
  refreshStatus();
}

function setBusy(b) {
  busy = b;
  const btn = document.getElementById('btn-simulate');
  btn.disabled = b || !walkLoaded;
  btn.textContent = b ? '  Working…' : '▶  Simulate Device';
}

// ── Init ──────────────────────────────────────────────────────────────────────
refreshStatus();
setInterval(refreshStatus, 10000);
</script>
</body>
</html>
"""

# ── HTTP handler ───────────────────────────────────────────────────────────────

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._send(200, "text/html", HTML.encode())
        elif path == "/api/status":
            self._send(200, "application/json", json.dumps(get_status()).encode())
        elif path == "/api/log-stream":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            q = queue.Queue()
            with _log_lock:
                _log_clients.append(q)
            try:
                while True:
                    try:
                        msg = q.get(timeout=15)
                        self.wfile.write(msg.encode())
                        self.wfile.flush()
                    except queue.Empty:
                        self.wfile.write(b": keep-alive\n\n")
                        self.wfile.flush()
            except Exception:
                pass
            finally:
                with _log_lock:
                    if q in _log_clients:
                        _log_clients.remove(q)
        else:
            self._send(404, "text/plain", b"Not found")

    def do_POST(self):
        path   = urlparse(self.path).path
        ctype  = self.headers.get("Content-Type", "")
        length = int(self.headers.get("Content-Length", 0))

        if path == "/api/upload":
            # Accept both multipart/form-data (large files) and application/json (legacy)
            if "multipart/form-data" in ctype:
                info = self._handle_multipart_upload(ctype, length)
            else:
                body = json.loads(self.rfile.read(length)) if length else {}
                text = body.get("text", "")
                info = self._process_walk_text(text)
            self._send(200, "application/json", json.dumps(info).encode())
            return

        elif path == "/api/simulate":
            run_simulation()
            self._send(200, "application/json", b'{"ok":true}')

        elif path == "/api/stop":
            global _snmpsim_proc
            if _snmpsim_proc and _snmpsim_proc.poll() is None:
                _snmpsim_proc.terminate()
                _snmpsim_proc.wait()
                _snmpsim_proc = None
            self._send(200, "application/json", b'{"ok":true}')

        else:
            self._send(404, "text/plain", b"Not found")

    def _process_walk_text(self, text):
        """Parse walk text, write snmprec, store state. Returns device info dict."""
        info = extract_device_info(text)
        info["profile"] = find_matching_profile(info.get("objectid", ""))
        _state["walk_text"] = text
        _state["device_info"] = info
        _state["profile"] = info["profile"]
        return info

    def _handle_multipart_upload(self, ctype, total_length):
        """Stream multipart upload directly to snmprec file, avoiding memory limits."""
        # Extract boundary from Content-Type header
        boundary_match = re.search(r'boundary=([^\s;]+)', ctype)
        if not boundary_match:
            return {"error": "no boundary"}
        boundary = boundary_match.group(1).strip('"').encode()

        # Read entire body (streaming to a temp file to avoid RAM for very large files)
        tmp = tempfile.NamedTemporaryFile(mode='wb', suffix='.walkdata', delete=False)
        tmp_path = tmp.name
        try:
            remaining = total_length
            CHUNK = 65536
            while remaining > 0:
                chunk = self.rfile.read(min(CHUNK, remaining))
                if not chunk:
                    break
                tmp.write(chunk)
                remaining -= len(chunk)
            tmp.close()

            # Parse multipart: find file content between boundary markers
            with open(tmp_path, 'rb') as f:
                raw = f.read()
        finally:
            os.unlink(tmp_path)

        # Find the file part's body (after the double CRLF header)
        delim = b'--' + boundary
        parts = raw.split(delim)
        file_text = None
        for part in parts:
            if b'filename=' in part and b'\r\n\r\n' in part:
                _, body_bytes = part.split(b'\r\n\r\n', 1)
                body_bytes = body_bytes.rstrip(b'\r\n--')
                file_text = body_bytes.decode('utf-8', errors='replace')
                break

        if file_text is None:
            return {"error": "no file found in upload"}

        return self._process_walk_text(file_text)

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)


def main():
    http.server.ThreadingHTTPServer.allow_reuse_address = True
    server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    server.daemon_threads = True
    url = f"http://localhost:{PORT}"
    print(f"SNMP Walk Player running at {url}  (Ctrl+C to quit)")
    threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
