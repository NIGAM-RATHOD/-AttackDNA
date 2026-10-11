"""
AttackDNA Backend - Flask API Server
Fetches CVE data from NVD, analyzes attack chains via Claude AI,
and serves interactive visualization data.
"""

import os
import json
import re
import time
import logging
import threading
from collections import OrderedDict
from datetime import datetime, timezone

import requests
try:
    import anthropic
except Exception as _anthropic_err:
    anthropic = None
from flask import Flask, jsonify, request, send_from_directory
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
APP_VERSION = "1.1.0"

app = Flask(__name__, static_folder="../frontend", static_url_path="")
app.json.sort_keys = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TIMEOUT = 15  # seconds

CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-opus-5-5")
CLAUDE_EFFORT = os.getenv("CLAUDE_EFFORT", "medium")
CLAUDE_TIMEOUT = 120  # seconds — reasoning models can take a while
# Server-side refusal fallback: re-runs a declined request on Anthropic's
# recommended fallback model instead of returning the refusal.
FALLBACK_BETA = "server-side-fallback-2026-07-01"
FALLBACK_MODEL_PREFIXES = ("claude-opus-5", "claude-fable-5", "claude-sonnet-5-5")

CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", 6 * 60 * 60))
CACHE_MAX_ENTRIES = 128

PHASE_NAMES = [
    "Recon",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# JSON schema enforced on Claude's response via structured outputs.
ATTACK_CHAIN_SCHEMA = {
    "type": "object",
    "properties": {
        "attack_phases": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "phase": {"type": "string", "enum": PHASE_NAMES},
                    "mitre_id": {"type": "string"},
                    "mitre_name": {"type": "string"},
                    "description": {"type": "string"},
                    "tools": {"type": "array", "items": {"type": "string"}},
                    "detection_point": {"type": "string"},
                    "connects_to": {"type": "array", "items": {"type": "string"}},
                },
                "required": [
                    "id", "phase", "mitre_id", "mitre_name", "description",
                    "tools", "detection_point", "connects_to",
                ],
                "additionalProperties": False,
            },
        },
        "one_liner": {"type": "string"},
        "severity_story": {"type": "string"},
        "patch_action": {"type": "string"},
        "affected_industries": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["attack_phases", "one_liner", "severity_story", "patch_action", "affected_industries"],
    "additionalProperties": False,
}

SYSTEM_PROMPT = (
    "You are a senior threat-intelligence analyst helping defenders understand how a "
    "published vulnerability could be chained into a realistic intrusion. Describe "
    "attacker behaviour at the level of MITRE ATT&CK techniques and well-known tooling "
    "so security teams can prioritise patching and detection. Do not include working "
    "exploit code, payloads, or step-by-step weaponisation instructions."
)


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

class TTLCache:
    """Tiny thread-safe LRU cache with per-entry expiry."""

    def __init__(self, max_entries: int, ttl_seconds: int):
        self.max_entries = max_entries
        self.ttl = ttl_seconds
        self._data = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            expires_at, value = item
            if expires_at < time.monotonic():
                del self._data[key]
                return None
            self._data.move_to_end(key)
            return value

    def set(self, key, value):
        if self.ttl <= 0:
            return
        with self._lock:
            self._data[key] = (time.monotonic() + self.ttl, value)
            self._data.move_to_end(key)
            while len(self._data) > self.max_entries:
                self._data.popitem(last=False)

    def clear(self):
        with self._lock:
            self._data.clear()


analysis_cache = TTLCache(CACHE_MAX_ENTRIES, CACHE_TTL_SECONDS)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_anthropic_client():
    """Return an Anthropic client or None if key is missing or SDK unavailable."""
    if anthropic is None:
        return None
    api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        return None
    return anthropic.Anthropic(api_key=api_key, timeout=CLAUDE_TIMEOUT)


def _nvd_headers() -> dict:
    headers = {"Accept": "application/json", "User-Agent": f"AttackDNA/{APP_VERSION}"}
    nvd_key = os.getenv("NVD_API_KEY", "").strip()
    if nvd_key:
        headers["apiKey"] = nvd_key
    return headers


def _validate_cve_id(cve_id: str) -> bool:
    """Validate CVE ID format: CVE-YYYY-NNNNN+"""
    return bool(re.match(r"^CVE-\d{4}-\d{4,}$", cve_id.upper()))


def _error(message: str, status: int):
    return jsonify({"error": True, "message": message}), status


def _extract_cve_data(nvd_item: dict) -> dict:
    """Extract relevant fields from a single NVD CVE item."""
    cve = nvd_item.get("cve", {})

    # Description (English preferred)
    description = ""
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break
    if not description:
        descriptions = cve.get("descriptions", [])
        description = descriptions[0].get("value", "") if descriptions else "No description available."

    # CVSS metrics – try 4.0, 3.1, 3.0, then 2.0
    cvss_score = None
    cvss_vector = None
    cvss_severity = None
    cvss_version = None
    metrics = cve.get("metrics", {})

    for version_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(version_key, [])
        if entries:
            # Prefer the NVD "Primary" score when several sources exist
            entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
            cvss_data = entry.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            cvss_severity = cvss_data.get("baseSeverity") or entry.get("baseSeverity")
            cvss_version = cvss_data.get("version")
            break

    # CWE IDs
    cwe_ids = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-") and val not in cwe_ids:
                cwe_ids.append(val)

    # Affected products (CPE)
    affected_products = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", True):
                    continue
                # Parse CPE 2.3 format: cpe:2.3:a:vendor:product:version:...
                parts = match.get("criteria", "").split(":")
                if len(parts) >= 6:
                    vendor = parts[3].replace("_", " ").title()
                    product = parts[4].replace("_", " ").title()
                    version = parts[5] if parts[5] not in ("*", "-") else "All versions"
                    label = f"{vendor} {product} {version}".strip()
                    if label not in affected_products:
                        affected_products.append(label)

    if not affected_products:
        affected_products = ["Not specified in NVD data"]

    # References
    references = []
    for ref in cve.get("references", [])[:8]:
        references.append({
            "url": ref.get("url", ""),
            "source": ref.get("source", ""),
            "tags": ref.get("tags", []),
        })

    return {
        "cve_id": cve.get("id", ""),
        "description": description,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cvss_version": cvss_version,
        "cvss_severity": cvss_severity or "UNKNOWN",
        "cwe_ids": cwe_ids if cwe_ids else ["Not specified"],
        "published_date": cve.get("published", ""),
        "last_modified": cve.get("lastModified", ""),
        "vuln_status": cve.get("vulnStatus", ""),
        "known_exploited": bool(cve.get("cisaExploitAdd")),
        "cisa_action_due": cve.get("cisaActionDue"),
        "affected_products": affected_products[:25],
        "references": references,
    }


def _build_claude_prompt(cve_data: dict) -> str:
    """Build the user prompt for Claude attack chain analysis."""
    kev_note = "Yes — listed in CISA KEV" if cve_data.get("known_exploited") else "Not listed in CISA KEV"
    return f"""Analyze {cve_data['cve_id']} and model a realistic attack chain.

<cve>
Description: {cve_data['description']}
CVSS: {cve_data['cvss_score']} ({cve_data['cvss_severity']}), vector {cve_data['cvss_vector']}
CWE: {', '.join(cve_data['cwe_ids'])}
Affected products: {', '.join(cve_data['affected_products'][:10])}
Known exploited: {kev_note}
</cve>

Guidance:
- Produce 4-8 phases that chain together plausibly for THIS vulnerability (not a generic template).
- Use real MITRE ATT&CK Enterprise technique IDs (e.g. T1190, T1059.001, T1078).
- Phase ids are "phase_1", "phase_2", ... in kill-chain order; connects_to lists the ids of the
  phases that directly follow, forming a directed graph. The final phase(s) connect to nothing.
- Each description is two sentences. Tools are real, publicly known tools.
- detection_point is a concrete, actionable detection (log source + signal).
- one_liner explains the risk to a non-technical executive in one sentence.
- severity_story is a two-paragraph narrative separated by a blank line.
- patch_action names the specific fix or vendor advisory plus interim mitigations."""


def _supports_fallback(model: str) -> bool:
    return model.startswith(FALLBACK_MODEL_PREFIXES)


def _call_claude(client, cve_data: dict):
    """Ask Claude for an attack chain. Returns (attack_chain | None, warning | None)."""
    params = dict(
        model=CLAUDE_MODEL,
        max_tokens=16000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": _build_claude_prompt(cve_data)}],
        output_config={
            "effort": CLAUDE_EFFORT,
            "format": {"type": "json_schema", "schema": ATTACK_CHAIN_SCHEMA},
        },
    )
    if _supports_fallback(CLAUDE_MODEL):
        message = client.beta.messages.create(betas=[FALLBACK_BETA], fallbacks="default", **params)
    else:
        message = client.messages.create(**params)

    if message.stop_reason == "refusal":
        log.warning("Claude declined analysis for %s", cve_data["cve_id"])
        return None, "AI declined to analyze this CVE. Showing basic attack chain."
    if message.stop_reason == "max_tokens":
        log.warning("Claude response truncated for %s", cve_data["cve_id"])
        return None, "AI response was truncated. Showing basic attack chain."

    raw_text = next((b.text for b in message.content if b.type == "text"), "")
    parsed = _parse_claude_json(raw_text)
    if parsed is None:
        return None, "AI returned malformed data. Showing basic attack chain."
    if not _validate_attack_chain(parsed):
        return None, "AI response missing required fields. Showing basic attack chain."

    _sanitize_links(parsed)
    log.info("Analyzed %s with %s — %d phases", cve_data["cve_id"], message.model, len(parsed["attack_phases"]))
    return parsed, None


def _parse_claude_json(text: str):
    """Parse Claude's response as JSON, with fallback cleanup for stray fences."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    cleaned = re.sub(r"```(?:json)?\s*", "", text).strip().rstrip("`")
    match = re.search(r"\{[\s\S]*\}", cleaned)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass
    return None


def _validate_attack_chain(data) -> bool:
    """Validate the structure of Claude's attack chain response."""
    if not isinstance(data, dict):
        return False
    for key in ATTACK_CHAIN_SCHEMA["required"]:
        if key not in data:
            return False

    phases = data["attack_phases"]
    if not isinstance(phases, list) or len(phases) == 0:
        return False

    required_phase_keys = ATTACK_CHAIN_SCHEMA["properties"]["attack_phases"]["items"]["required"]
    for phase in phases:
        if not isinstance(phase, dict):
            return False
        for key in required_phase_keys:
            if key not in phase:
                return False
    return True


def _sanitize_links(chain: dict) -> None:
    """Drop self-links and links to phases that don't exist."""
    ids = {p["id"] for p in chain["attack_phases"]}
    for phase in chain["attack_phases"]:
        phase["connects_to"] = [t for t in phase.get("connects_to", []) if t in ids and t != phase["id"]]


def _generate_fallback_chain(cve_data: dict) -> dict:
    """Generate a basic attack chain when Claude is unavailable."""
    return {
        "attack_phases": [
            {
                "id": "phase_1",
                "phase": "Recon",
                "mitre_id": "T1595",
                "mitre_name": "Active Scanning",
                "description": f"Attacker identifies systems vulnerable to {cve_data['cve_id']}. Scanning tools probe for the specific weakness described in the CVE.",
                "tools": ["Nmap", "Shodan", "Masscan"],
                "detection_point": "Network scan detection via IDS/IPS alerts",
                "connects_to": ["phase_2"],
            },
            {
                "id": "phase_2",
                "phase": "Initial Access",
                "mitre_id": "T1190",
                "mitre_name": "Exploit Public-Facing Application",
                "description": f"Exploitation of {cve_data['cve_id']} to gain initial foothold. The vulnerability is leveraged against the target system.",
                "tools": ["Metasploit", "Custom exploit"],
                "detection_point": "WAF alerts, anomalous application behavior in logs",
                "connects_to": ["phase_3"],
            },
            {
                "id": "phase_3",
                "phase": "Execution",
                "mitre_id": "T1059",
                "mitre_name": "Command and Scripting Interpreter",
                "description": "Attacker executes commands on the compromised system. Malicious payloads are deployed to establish control.",
                "tools": ["PowerShell", "Cobalt Strike"],
                "detection_point": "EDR alerts on suspicious process execution",
                "connects_to": ["phase_4"],
            },
            {
                "id": "phase_4",
                "phase": "Impact",
                "mitre_id": "T1486",
                "mitre_name": "Data Encrypted for Impact",
                "description": "Final impact phase where the attacker achieves their objective. Data may be exfiltrated, encrypted, or systems disrupted.",
                "tools": ["Custom malware"],
                "detection_point": "Data loss prevention alerts, unusual outbound traffic",
                "connects_to": [],
            },
        ],
        "one_liner": f"{cve_data['cve_id']} is a security vulnerability that could allow attackers to compromise affected systems.",
        "severity_story": (
            f"An attacker begins by scanning the internet for systems affected by {cve_data['cve_id']}. "
            f"Using automated tools, they identify vulnerable targets and craft an exploit leveraging the weakness "
            f"described in the CVE (CVSS: {cve_data['cvss_score']}).\n\n"
            f"Once inside, the attacker escalates privileges, moves laterally across the network, and ultimately "
            f"achieves their objective — whether that's data theft, ransomware deployment, or persistent access "
            f"for future operations."
        ),
        "patch_action": "Apply vendor patches immediately. Implement network segmentation and monitor for indicators of compromise.",
        "affected_industries": ["Technology", "Finance", "Healthcare", "Government"],
        "_fallback": True,
    }


def _fetch_nvd(params: dict):
    """Call the NVD API. Returns (json | None, (message, status) | None)."""
    try:
        resp = requests.get(NVD_BASE_URL, params=params, timeout=NVD_TIMEOUT, headers=_nvd_headers())
    except requests.exceptions.Timeout:
        return None, ("NVD API timed out. The National Vulnerability Database may be under heavy load — please try again shortly.", 504)
    except requests.exceptions.ConnectionError:
        return None, ("Cannot connect to the NVD API. Please check your internet connection and try again.", 503)
    except requests.exceptions.RequestException as e:
        log.error("NVD request error: %s", e)
        return None, ("An unexpected error occurred while contacting NVD. Please try again.", 502)

    if resp.status_code in (403, 429):
        return None, ("NVD rate limit reached. Wait ~30 seconds, or add an NVD_API_KEY to raise the limit.", 429)
    if resp.status_code == 404:
        return {"vulnerabilities": [], "totalResults": 0}, None
    if not resp.ok:
        log.error("NVD HTTP %s for %s", resp.status_code, params)
        return None, (f"NVD API returned an error (HTTP {resp.status_code}). Please try again later.", 502)

    try:
        return resp.json(), None
    except ValueError:
        return None, ("Received invalid data from NVD API. Please try again later.", 502)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
    )
    return resp


@app.route("/")
def index():
    """Serve the frontend."""
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/cve/<cve_id>")
def get_cve(cve_id):
    """
    Full CVE analysis pipeline:
    1. Validate CVE ID format
    2. Fetch from NVD API
    3. Analyze with Claude AI
    4. Return combined data
    """
    cve_id = cve_id.upper().strip()

    if not _validate_cve_id(cve_id):
        return _error("Invalid CVE ID format. Expected format: CVE-YYYY-NNNNN", 400)

    refresh = request.args.get("refresh") == "1"
    cached = None if refresh else analysis_cache.get(cve_id)
    if cached:
        log.info("Cache hit for %s", cve_id)
        return jsonify({**cached, "cached": True})

    # Step 1: Fetch from NVD API
    log.info("Fetching CVE data from NVD: %s", cve_id)
    nvd_data, err = _fetch_nvd({"cveId": cve_id})
    if err:
        return _error(*err)

    vulnerabilities = nvd_data.get("vulnerabilities", [])
    if not vulnerabilities:
        return _error(f"{cve_id} was not found in the National Vulnerability Database.", 404)

    cve_data = _extract_cve_data(vulnerabilities[0])

    # Step 2: Send to Claude for attack chain analysis
    client = _get_anthropic_client()
    if client is None:
        log.warning("No ANTHROPIC_API_KEY set — using fallback attack chain")
        attack_chain = _generate_fallback_chain(cve_data)
        ai_warning = "Claude API key not configured. Showing a generic template chain."
    else:
        try:
            attack_chain, ai_warning = _call_claude(client, cve_data)
        except Exception as e:
            if anthropic and isinstance(e, anthropic.APITimeoutError):
                log.error("Claude API timeout for %s", cve_id)
                attack_chain, ai_warning = None, "AI analysis timed out. Showing basic attack chain."
            elif anthropic and isinstance(e, anthropic.AuthenticationError):
                log.error("Claude API rejected the API key")
                attack_chain, ai_warning = None, "Claude API key is invalid. Showing basic attack chain."
            elif anthropic and isinstance(e, anthropic.RateLimitError):
                log.error("Claude API rate limited for %s", cve_id)
                attack_chain, ai_warning = None, "AI service is rate limited. Showing basic attack chain."
            elif anthropic and isinstance(e, anthropic.APIConnectionError):
                log.error("Claude API connection error for %s", cve_id)
                attack_chain, ai_warning = None, "Cannot connect to AI service. Showing basic attack chain."
            elif anthropic and isinstance(e, anthropic.APIStatusError):
                log.error("Claude API status error for %s: %s", cve_id, e)
                attack_chain, ai_warning = None, f"AI service error (HTTP {e.status_code}). Showing basic attack chain."
            else:
                log.exception("Unexpected Claude error for %s", cve_id)
                attack_chain, ai_warning = None, "Unexpected AI error. Showing basic attack chain."

        if attack_chain is None:
            attack_chain = _generate_fallback_chain(cve_data)

    response = {
        "error": False,
        "cve": cve_data,
        "attack_chain": attack_chain,
        "analyzed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    if ai_warning:
        response["ai_warning"] = ai_warning
    else:
        # Only cache real AI analyses so transient failures are retried next time
        analysis_cache.set(cve_id, response)

    return jsonify({**response, "cached": False})


@app.route("/api/search")
def search_cves():
    """Search NVD for CVEs matching a keyword. Returns top 5."""
    query = request.args.get("q", "").strip()
    if not query:
        return _error("Search query parameter 'q' is required.", 400)
    if len(query) > 100:
        return _error("Search query is too long (max 100 characters).", 400)

    if _validate_cve_id(query.upper()):
        return jsonify({
            "error": False,
            "redirect_cve": query.upper(),
            "message": "Direct CVE ID detected. Use the /api/cve/ endpoint.",
            "results": [],
        })

    data, err = _fetch_nvd({"keywordSearch": query, "resultsPerPage": 5})
    if err:
        return _error(*err)

    results = []
    for vuln in data.get("vulnerabilities", []):
        extracted = _extract_cve_data(vuln)
        desc = extracted["description"]
        results.append({
            "cve_id": extracted["cve_id"],
            "description": desc[:200] + ("..." if len(desc) > 200 else ""),
            "cvss_score": extracted["cvss_score"],
            "cvss_severity": extracted["cvss_severity"],
            "published_date": extracted["published_date"],
        })

    return jsonify({
        "error": False,
        "query": query,
        "total_results": data.get("totalResults", 0),
        "results": results,
    })


@app.route("/api/health")
def health():
    """Health check endpoint."""
    return jsonify({
        "status": "ok",
        "service": "AttackDNA",
        "version": APP_VERSION,
        "claude_configured": bool(os.getenv("ANTHROPIC_API_KEY", "").strip()),
        "model": CLAUDE_MODEL,
        "nvd_key_configured": bool(os.getenv("NVD_API_KEY", "").strip()),
    })


@app.errorhandler(404)
def not_found(_e):
    if request.path.startswith("/api/"):
        return _error("Endpoint not found.", 404)
    return send_from_directory(app.static_folder, "index.html")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    # The debugger allows arbitrary code execution, so only bind publicly when it's off.
    host = "127.0.0.1" if debug else os.getenv("HOST", "127.0.0.1")
    log.info("Starting AttackDNA on http://%s:%d (debug=%s, model=%s)", host, port, debug, CLAUDE_MODEL)
    app.run(host=host, port=port, debug=debug)
