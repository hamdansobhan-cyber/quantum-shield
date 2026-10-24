from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from dotenv import load_dotenv
from urllib.parse import urlparse
from datetime import datetime, date, timedelta
import os
import re
import json
import sqlite3
import subprocess
import sys
import shutil
import tempfile
import secrets
import smtplib
from email.message import EmailMessage
import xml.etree.ElementTree as ET
import pyotp
import qrcode
import io
import base64

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "QuantumShield2026")

DB_FILE = "scans.db"
USER_DB = "users.db"

# SQLMap installation path
SQLMAP_PATH = os.getenv("SQLMAP_PATH", r"C:\Users\hamdan\OneDrive\Desktop\vanurbility scanner\sqlmap-master\sqlmap.py")


# ---------- Google Login ----------
oauth = OAuth(app)

google = oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID", ""),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET", ""),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"}
)


# ---------- Database ----------
def init_databases():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS security_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            threat_score INTEGER NOT NULL,
            threat_level TEXT NOT NULL,
            low_count INTEGER NOT NULL,
            medium_count INTEGER NOT NULL,
            high_count INTEGER NOT NULL,
            raw_output TEXT NOT NULL,
            results_json TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS authorized_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL UNIQUE,
            notes TEXT DEFAULT '',
            added_by TEXT DEFAULT 'user',
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS remediation_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            target TEXT NOT NULL,
            finding_key TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'Unknown',
            evidence TEXT DEFAULT '',
            recommendation TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'Open',
            priority TEXT NOT NULL DEFAULT 'Medium',
            due_date TEXT DEFAULT '',
            verification_result TEXT DEFAULT '',
            updated_at TEXT NOT NULL,
            UNIQUE(scan_id, finding_key)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT DEFAULT '',
            details TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

    # Create the users table if it does not exist.
    conn = sqlite3.connect(USER_DB)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                totp_secret TEXT,
                is_2fa_enabled BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Migrate older users.db files. CREATE TABLE IF NOT EXISTS does not
        # add new columns to a table that already exists.
        columns = {
            row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()
        }

        if "totp_secret" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")

        if "is_2fa_enabled" not in columns:
            conn.execute(
                "ALTER TABLE users ADD COLUMN is_2fa_enabled BOOLEAN DEFAULT 0"
            )

        conn.commit()
    finally:
        conn.close()


init_databases()


# ---------- Input Validation ----------
def is_valid_target(target):
    """Validate an IPv4 address or domain name."""
    ip = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    domain = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"

    if target.lower() in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}:
        return False

    return bool(re.match(ip, target) or re.match(domain, target))


def is_valid_web_target(target):
    """Validate an HTTP or HTTPS URL for SQLMap."""
    try:
        parsed = urlparse(target)
        return parsed.scheme in {"http", "https"} and bool(parsed.hostname)
    except Exception:
        return False


def logged_in():
    return "manual_user" in session or "user" in session


# ---------- Nmap ----------
def run_nmap(target, scan_type, extra=None):
    """Run Nmap and parse its XML output for reliable scan results."""
    extra = extra or {}

    nmap = shutil.which("nmap")
    if not nmap:
        for path in [r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"]:
            if os.path.exists(path):
                nmap = path
                break
    if not nmap:
        return parse_nmap("Nmap is not installed or could not be found in PATH.", scan_type)

    scan_settings = {
        "quick": (["-F"], 60),
        "stealth": (["-sS", "--top-ports", "100"], 90),
        "tcp_connect": (["-sT", "--top-ports", "100"], 90),
        "tcp_ack": (["-sA", "--top-ports", "100"], 90),
        "tcp_window": (["-sW", "--top-ports", "100"], 90),
        "tcp_maimon": (["-sM", "--top-ports", "100"], 90),
        "tcp_fin": (["-sF", "--top-ports", "100"], 90),
        "tcp_null": (["-sN", "--top-ports", "100"], 90),
        "tcp_xmas": (["-sX", "--top-ports", "100"], 90),
        "udp": (["-sU", "--top-ports", "20"], 180),
        "ip_protocol": (["-sO"], 120),
        "idle": (["-sI"], 180),
        "ftp_bounce": (["-b"], 180),
        "sctp_init": (["-sY"], 120),
        "sctp_cookie": (["-sZ"], 120),
        "version": (["-sV", "--top-ports", "50"], 120),
        "os": (["-O", "--top-ports", "20"], 120),
        "intense": (["-T4", "-A", "--top-ports", "100"], 180),
        "all_ports": (["-p-", "--open"], 300),
        "ping": (["-sn"], 60),
        "vuln": (["-sV", "--script=vulners", "--top-ports", "20"], 180),
        "default_web_script": (["-sV", "-sC", "--top-ports", "100"], 180),
        "vuln_detection": (["-sV", "--script=vuln", "--top-ports", "100"], 240),
        "web_enum": (["-sV", "--script=http-enum", "--top-ports", "100"], 180),
        "ssl_audit": (["-sV", "--script=ssl-enum-ciphers,ssl-cert", "--top-ports", "100"], 240),
        "comprehensive_web": (["-sV", "--script=http-title,http-headers,http-methods,http-enum,http-security-headers,ssl-enum-ciphers,ssl-cert", "--top-ports", "100"], 300),
        "custom_flags": ([], 120)
    }
    args, timeout = scan_settings.get(scan_type, scan_settings["quick"])
    args = args.copy()

    if scan_type == "custom_flags":
        allowed = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"}
        flags = [flag.strip().upper() for flag in str(extra.get("scanflags", "")).split(",") if flag.strip()]
        if not flags or any(flag not in allowed for flag in flags):
            return parse_nmap("Invalid custom TCP flags. Use SYN,ACK or FIN,PSH,URG.", scan_type)
        args = ["--scanflags", ",".join(flags), "--top-ports", "100"]

    if scan_type in ("idle", "ftp_bounce"):
        key = "zombie" if scan_type == "idle" else "ftp_bounce"
        host = str(extra.get(key, "")).strip()
        if not is_valid_target(host):
            name = "zombie host" if scan_type == "idle" else "FTP relay host"
            return parse_nmap(f"{scan_type.replace('_', ' ').title()} requires a valid {name}.", scan_type)
        args.append(host)

    xml_path = None
    try:
        fd, xml_path = tempfile.mkstemp(prefix="quantumshield_nmap_", suffix=".xml")
        os.close(fd)
        cmd = [nmap] + args + ["-oX", xml_path, target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        human_output = ((result.stdout or "") + ("\n" + result.stderr if result.stderr else "")).strip()

        xml_text = ""
        if os.path.exists(xml_path):
            with open(xml_path, "r", encoding="utf-8", errors="replace") as f:
                xml_text = f.read()

        if xml_text.strip().startswith("<?xml") or "<nmaprun" in xml_text:
            parsed = parse_nmap_xml(xml_text, human_output, scan_type)
            return parsed

        return parse_nmap(human_output or "Nmap completed without output.", scan_type)
    except subprocess.TimeoutExpired:
        return nmap_error_result(f"Nmap scan timed out after {timeout} seconds.", scan_type)
    except Exception as e:
        return nmap_error_result(f"Nmap error: {e}", scan_type)
    finally:
        if xml_path:
            try:
                os.remove(xml_path)
            except OSError:
                pass


def parse_nmap_xml(xml_text, human_output, scan_type):
    """Parse Nmap XML and preserve the states Nmap actually reported."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return parse_nmap(human_output or "Invalid Nmap XML output.", scan_type)

    results = []
    cves = []
    high = medium = low = 0
    protocol_count = 0
    vuln_findings = 0
    host_status = "UNKNOWN"
    host_status_detail = "Nmap did not report host status."
    os_name = "Not detected"
    os_details = "No operating-system information was reported."
    os_confidence = "N/A"
    device_type = "Unknown"
    state_counts = {"open": 0, "closed": 0, "filtered": 0,
                    "unfiltered": 0, "open|filtered": 0,
                    "closed|filtered": 0, "unknown": 0}

    hosts = root.findall("host")
    if not hosts:
        message = human_output.strip() or "Nmap returned no host records."
        return nmap_error_result(message, scan_type)

    for host in hosts:
        status = host.find("status")
        if status is not None:
            state = (status.get("state") or "unknown").upper()
            if state == "UP":
                host_status = "UP"
            elif host_status != "UP":
                host_status = "DOWN" if state == "DOWN" else state
            host_status_detail = status.get("reason") or state

        for osmatch in host.findall("./os/osmatch"):
            if osmatch.get("name"):
                os_name = osmatch.get("name")
                os_details = os_name
                if osmatch.get("accuracy"):
                    os_confidence = osmatch.get("accuracy") + "%"
                break

        dev = host.find("./os/osclass")
        if dev is not None:
            device_type = dev.get("type") or device_type

        ports = host.find("ports")
        if ports is None:
            continue

        for port in ports.findall("port"):
            protocol = (port.get("protocol") or "unknown").lower()
            portid = port.get("portid", "?")
            state_el = port.find("state")
            if state_el is None:
                continue

            state = (state_el.get("state") or "unknown").lower()
            state_counts[state] = state_counts.get(state, 0) + 1

            service_el = port.find("service")
            service = ((service_el.get("name") if service_el is not None else None)
                       or "unknown")
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""
            extrainfo = service_el.get("extrainfo", "") if service_el is not None else ""
            detail = " ".join(x for x in [product, version, extrainfo] if x).strip()
            if not detail:
                detail = "Not detected"

            scripts_text = []
            for script in port.findall("script"):
                out = script.get("output", "")
                scripts_text.append(out)
                for cve in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", out, re.I):
                    cve = cve.upper()
                    if cve not in cves:
                        cves.append(cve)

            if state == "closed":
                continue

            combined = (detail + " " + " ".join(scripts_text)).upper()
            if scan_type in {"vuln", "vuln_detection"}:
                if "STATE: VULNERABLE" in combined or "VULNERABLE:" in combined or "IS VULNERABLE" in combined:
                    risk = "HIGH"
                    high += 1
                    vuln_findings += 1
                else:
                    risk = "INFO"
            else:
                risk = "INFO"

            if scan_type in {"vuln", "vuln_detection", "default_web_script", "web_enum", "ssl_audit", "comprehensive_web"} and scripts_text:
                detail = (detail + " | " + " | ".join(scripts_text)).strip(" |")

            results.append({
                "port": f"{portid}/{protocol}",
                "state": state,
                "service": service.upper(),
                "version": detail,
                "risk": risk
            })

            if protocol == "ip":
                protocol_count += 1

        for script in host.findall("./hostscript/script"):
            out = script.get("output", "")
            for cve in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", out, re.I):
                cve = cve.upper()
                if cve not in cves:
                    cves.append(cve)

    if scan_type in {"vuln", "vuln_detection"}:
        if vuln_findings == 0:
            high = medium = low = 0

    if scan_type == "ping":
        high = medium = low = 0

    score, level = make_score(high, medium, low)

    if scan_type == "ping":
        result_label = "HOST STATUS"
        result_value = host_status if host_status != "UNKNOWN" else "NOT REPORTED"
    elif scan_type == "os":
        result_label = "OS DETECTION"
        result_value = os_name if os_name != "Not detected" else "NOT DETECTED"
    elif scan_type == "version":
        result_label = "SERVICES DETECTED"
        result_value = str(len(results))
    elif scan_type in {"vuln", "vuln_detection"}:
        result_label = "VULNERABILITY FINDINGS"
        result_value = str(vuln_findings)
    elif scan_type == "ip_protocol":
        result_label = "PROTOCOLS DETECTED"
        result_value = str(protocol_count)
    else:
        result_label = "SCAN RESULTS"
        result_value = str(len(results))

    meta = {
        "open_ports": state_counts.get("open", 0) + state_counts.get("open|filtered", 0),
        "closed_ports": state_counts.get("closed", 0),
        "filtered_ports": state_counts.get("filtered", 0),
        "unfiltered_ports": state_counts.get("unfiltered", 0),
        "open_filtered_ports": state_counts.get("open|filtered", 0),
        "services": len({x["service"] for x in results}),
        "os_name": os_name,
        "os_details": os_details,
        "os_confidence": os_confidence,
        "device_type": device_type,
        "cves": cves,
        "host_status": host_status,
        "host_status_detail": host_status_detail,
        "protocol_count": protocol_count,
        "vuln_findings": vuln_findings,
        "result_label": result_label,
        "result_value": result_value,
        "result_count": len(results),
        "state_counts": state_counts,
        "host_count": len(hosts),
        "scan_status": "COMPLETED",
        "scan_message": "Nmap returned structured scan data."
    }

    if host_status == "DOWN" and not results:
        meta["scan_status"] = "INCONCLUSIVE"
        meta["scan_message"] = "Nmap could not confirm the host was reachable. No findings were recorded."
        return human_output or meta["scan_message"], [], 0, "UNKNOWN", 0, 0, 0, meta

    if scan_type == "os" and os_name == "Not detected":
        meta["scan_status"] = "INCONCLUSIVE"
        meta["scan_message"] = "Nmap did not obtain a usable operating-system fingerprint."

    return human_output or "Nmap completed.", results, score, level, low, medium, high, meta


def nmap_error_result(message, scan_type):
    meta = {
        "open_ports": 0,
        "closed_ports": 0,
        "filtered_ports": 0,
        "unfiltered_ports": 0,
        "open_filtered_ports": 0,
        "services": 0,
        "os_name": "Not available",
        "os_details": message,
        "os_confidence": "N/A",
        "device_type": "Unknown",
        "cves": [],
        "host_status": "ERROR",
        "host_status_detail": message,
        "protocol_count": 0,
        "vuln_findings": 0,
        "result_label": "SCAN ERROR",
        "result_value": "ERROR",
        "result_count": 0,
        "state_counts": {},
        "host_count": 0,
        "scan_status": "FAILED",
        "scan_message": message
    }
    return message, [], 0, "UNKNOWN", 0, 0, 0, meta


# ---------- Threat Score ----------
def make_score(high, medium, low):
    high = max(0, int(high or 0))
    medium = max(0, int(medium or 0))
    low = max(0, int(low or 0))

    score = min(100, high * 45 + medium * 25 + low * 10)

    if high + medium + low == 0:
        return 0, "UNRATED"
    if score >= 66:
        level = "CRITICAL"
    elif score >= 36:
        level = "HIGH"
    elif score >= 16:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level


def parse_nmap(output, scan_type):
    results = []
    high = medium = low = 0
    os_name = "Not detected"
    os_details = "No operating-system information was reported."
    os_confidence = "N/A"
    device_type = "Unknown"
    cves = []
    host_status = "UNKNOWN"
    host_status_detail = "Nmap did not report host status."
    protocol_count = 0
    vuln_findings = 0

    lines = output.splitlines()
    for line in lines:
        text = line.strip()
        lower = text.lower()

        if re.search(r"host is up", lower):
            host_status = "UP"
            host_status_detail = text
        elif re.search(r"host seems down|0 hosts up|host is down", lower):
            host_status = "DOWN"
            host_status_detail = text
        elif text.startswith("Nmap scan report for") and host_status == "UNKNOWN":
            host_status_detail = text

        if text.startswith("OS details:"):
            os_details = text.split(":", 1)[1].strip()
            os_name = os_details
        elif text.startswith("Running:"):
            os_name = text.split(":", 1)[1].strip()
            os_details = os_name
        elif text.startswith("Aggressive OS guesses:"):
            guess = text.split(":", 1)[1].strip()
            os_details = guess
            match = re.search(r"(\d+)%", guess)
            if match:
                os_confidence = match.group(1) + "%"
            os_name = guess.split(",", 1)[0].strip()
        elif text.startswith("Device type:"):
            device_type = text.split(":", 1)[1].strip()

        for cve in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, re.I):
            cve = cve.upper()
            if cve not in cves:
                cves.append(cve)

        proto_match = re.match(r"^(\d+)/(ip)\s+(open|closed|filtered|open\|filtered)\s+(\S+)", text, re.I)
        if proto_match:
            port, state, service = proto_match.groups()
            if state.lower() in {"open", "open|filtered"}:
                results.append({"port": f"{port}/ip", "state": state.lower(), "service": service.upper(), "version": "Not detected", "risk": "INFO"})
                protocol_count += 1
            continue

        if not re.search(r"/(tcp|udp|sctp)\s+", line, re.I):
            if scan_type == "vuln" and ("VULNERABLE" in text.upper() or "STATE: VULNERABLE" in text.upper()):
                vuln_findings += 1
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        port, state, service = parts[:3]
        version = " ".join(parts[3:]) or "Not detected"
        state_lower = state.lower()

        if state_lower == "closed":
            continue

        risk = "INFO"
        if scan_type == "vuln":
            if "state: vulnerable" in version.lower() or "is vulnerable" in version.lower():
                risk = "HIGH"
                high += 1
                vuln_findings += 1

        results.append({
            "port": port,
            "state": state,
            "service": service.upper(),
            "version": version,
            "risk": risk
        })

    if scan_type == "ping":
        if host_status == "UP":
            low = 0
            medium = 0
            high = 0
        elif host_status == "DOWN":
            low = medium = high = 0

    score, level = make_score(high, medium, low)

    if scan_type == "ping":
        result_label = "HOST STATUS"
        result_value = host_status if host_status != "UNKNOWN" else "NOT REPORTED"
    elif scan_type == "os":
        result_label = "OS DETECTION"
        result_value = os_name if os_name != "Not detected" else "NOT DETECTED"
    elif scan_type == "version":
        result_label = "SERVICES DETECTED"
        result_value = str(len(results))
    elif scan_type == "vuln":
        result_label = "VULNERABILITY FINDINGS"
        result_value = str(vuln_findings)
    elif scan_type == "ip_protocol":
        result_label = "PROTOCOLS DETECTED"
        result_value = str(protocol_count)
    elif scan_type.startswith("nikto"):
        result_label = "WEB FINDINGS"
        result_value = str(len(results))
    elif scan_type == "sqlmap":
        result_label = "INJECTION STATUS"
        result_value = "DETECTED" if high else "NOT CONFIRMED"
    else:
        result_label = "SCAN RESULTS"
        result_value = str(len(results))

    scan_status = "COMPLETED"
    scan_message = "Nmap returned output."
    if host_status == "DOWN" and not results:
        scan_status = "INCONCLUSIVE"
        scan_message = "Nmap could not confirm the host was reachable. No findings were recorded."
        high = medium = low = 0
    elif scan_type == "os" and os_name == "Not detected":
        scan_status = "INCONCLUSIVE"
        scan_message = "Nmap did not obtain a usable operating-system fingerprint."
    elif re.search(r"failed to resolve|could not resolve|not installed|invalid scanflags|execution failed", output, re.I):
        scan_status = "FAILED"
        scan_message = "Nmap reported an execution or target-resolution error."
        results = []
        high = medium = low = 0

    score, level = make_score(high, medium, low)

    meta = {
        "scan_status": scan_status,
        "scan_message": scan_message,
        "open_ports": len([x for x in results if x["state"].lower() in {"open", "open|filtered"}]),
        "services": len({x["service"] for x in results}),
        "os_name": os_name,
        "os_details": os_details,
        "os_confidence": os_confidence,
        "device_type": device_type,
        "cves": cves,
        "host_status": host_status,
        "host_status_detail": host_status_detail,
        "protocol_count": protocol_count,
        "vuln_findings": vuln_findings,
        "result_label": result_label,
        "result_value": result_value,
        "result_count": len(results)
    }

    return output, results, score, level, low, medium, high, meta


# ---------- Nikto ----------
def run_nikto(target, scan_type="nikto"):
    plugin_map = {
        "nikto": None,
        "nikto_ssl": "ssl",
        "nikto_headers": "headers",
        "nikto_outdated": "outdated",
        "nikto_robots": "robots",
        "nikto_httpoptions": "httpoptions",
    }

    args = ["nikto", "-h", target, "-nointeractive"]
    plugin = plugin_map.get(scan_type)
    if plugin:
        args.extend(["-Plugins", plugin])

    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=90
        )

        if result.stdout and ("Nikto" in result.stdout or "+" in result.stdout):
            return parse_nikto(result.stdout)
    except Exception:
        pass

    return nikto_fallback(target)


def parse_nikto(output):
    results = []
    high = medium = low = 0
    cves = []

    for line in output.splitlines():
        text = line.strip()

        if not text.startswith("+"):
            continue

        finding = text[1:].strip()
        risk = "UNRATED"

        for cve in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, re.I):
            cve = cve.upper()
            if cve not in cves:
                cves.append(cve)

        results.append({
            "port": "80/443 (HTTP/S)",
            "state": "open",
            "service": "WEB-SERVER",
            "version": finding[:50] + "..." if len(finding) > 50 else finding,
            "risk": risk
        })

    score, level = make_score(high, medium, low)

    meta = {
        "open_ports": len(results),
        "services": 1,
        "os_name": "Web Server Target",
        "os_details": "Nikto Web Vulnerability Assessment Scanner",
        "os_confidence": "N/A",
        "device_type": "Web Application / Server",
        "cves": cves
    }

    meta["scan_status"] = "COMPLETED"
    meta["scan_message"] = "Nikto output was parsed. Finding severity is not assigned unless the scanner reports it."
    return output, results, score, level, low, medium, high, meta


def nikto_fallback(target):
    output = (
        "[ERROR] Nikto execution was unavailable or timed out.\n"
        f"[INFO] Target: {target}\n"
        "[INFO] Make sure Nikto is installed and available in PATH.\n"
    )

    meta = {
        "open_ports": 0,
        "services": 0,
        "os_name": "Not available",
        "os_details": "Nikto was unavailable; no web scan was performed.",
        "os_confidence": "N/A",
        "device_type": "Unknown",
        "cves": [],
        "scan_status": "FAILED",
        "scan_message": "Nikto could not be run or did not return parseable output."
    }

    return output, [], 0, "UNKNOWN", 0, 0, 0, meta


# ---------- SQLMap ----------
def run_sqlmap(target, scan_type="sqlmap"):
    mode_map = {
        "sqlmap": {
            "label": "SQL INJECTION DETECTION",
            "description": "Standard SQLMap parameter injection assessment.",
            "extra": ["--level=1", "--risk=1"],
            "timeout": 120,
        },
        "sqlmap_deep": {
            "label": "DEEP SQL INJECTION ANALYSIS",
            "description": "Broader SQLMap detection using level 3 and risk 2.",
            "extra": ["--level=3", "--risk=2"],
            "timeout": 180,
        },
        "sqlmap_forms": {
            "label": "FORM ANALYSIS",
            "description": "SQLMap form discovery and parameter testing.",
            "extra": ["--forms", "--level=1", "--risk=1"],
            "timeout": 180,
        },
        "sqlmap_crawl": {
            "label": "WEB CRAWL ANALYSIS",
            "description": "SQLMap crawls links to discover additional testable parameters.",
            "extra": ["--crawl=2", "--level=1", "--risk=1"],
            "timeout": 240,
        },
        "sqlmap_fingerprint": {
            "label": "DBMS FINGERPRINT",
            "description": "SQLMap attempts to fingerprint the backend DBMS.",
            "extra": ["--fingerprint", "--level=1", "--risk=1"],
            "timeout": 150,
        },
        "sqlmap_dbs": {
            "label": "DATABASE ENUMERATION",
            "description": "SQLMap enumerates database names when injection is confirmed.",
            "extra": ["--dbs", "--level=1", "--risk=1"],
            "timeout": 180,
        },
    }
    mode = mode_map.get(scan_type, mode_map["sqlmap"])
    args = [
        sys.executable, SQLMAP_PATH, "-u", target, "--batch", "--threads=1"
    ] + mode["extra"]

    base_meta = {
        "open_ports": 0,
        "services": 1,
        "os_name": "Web Application",
        "os_details": mode["description"],
        "os_confidence": "N/A",
        "device_type": "Web Application / Server",
        "cves": [],
        "sqlmap_mode": scan_type,
        "sqlmap_label": mode["label"],
        "sqlmap_description": mode["description"],
        "sqlmap_dbms": "Not detected",
        "sqlmap_databases": [],
        "sqlmap_items": 0,
        "result_label": mode["label"],
        "result_value": "NOT CONFIRMED",
        "scan_status": "READY",
        "scan_message": "Waiting for SQLMap output."
    }

    if not os.path.exists(SQLMAP_PATH):
        message = (
            "[ERROR] SQLMap was not found at the configured path.\n"
            f"[INFO] Expected file: {SQLMAP_PATH}"
        )
        base_meta["scan_status"] = "FAILED"
        base_meta["scan_message"] = "SQLMap was not found at the configured path."
        return message, [], 0, "UNKNOWN", 0, 0, 0, base_meta

    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=mode["timeout"]
        )
        output = (result.stdout or "") + "\n" + (result.stderr or "")
        lower = output.lower()

        connection_failed = any(term in lower for term in (
            "unable to connect to the target", "connection timed out",
            "could not connect to the server", "failed to connect",
            "target url is not reachable", "no connection could be made"
        ))
        if connection_failed:
            base_meta["scan_status"] = "FAILED"
            base_meta["scan_message"] = "SQLMap could not connect to the target; no security conclusion was made."
            return output.strip(), [], 0, "UNKNOWN", 0, 0, 0, base_meta

        injection_evidence = (
            "is vulnerable" in lower or "is injectable" in lower or
            "parameter '" in lower and "is vulnerable" in lower
        )
        dbms_match = re.search(r"back-end DBMS:\s*(.+)", output, re.I)
        dbms = dbms_match.group(1).strip() if dbms_match else "Not detected"

        databases=[]
        in_db_block=False
        for line in output.splitlines():
            t=line.strip()
            if re.search(r"available databases", t, re.I):
                in_db_block=True
                continue
            if in_db_block:
                m=re.match(r"\[\*\]\s+(.+)", t)
                if m:
                    name=m.group(1).strip()
                    if name and name not in databases:
                        databases.append(name)
                elif t and not t.startswith("[") and not t.startswith("Database:"):
                    if any(k in t.lower() for k in ("available tables", "web server", "fetching", "database management")):
                        in_db_block=False

        vulnerable_lines=[]
        for line in output.splitlines():
            t=line.strip()
            if not t: continue
            l=t.lower()
            if any(k in l for k in ("is vulnerable", "is injectable", "type:", "title:", "payload:")):
                vulnerable_lines.append(t)

        if scan_type == "sqlmap_dbs":
            value = str(len(databases)) if databases else ("AVAILABLE" if injection_evidence else "NOT CONFIRMED")
            label = "DATABASES FOUND"
            item_count = len(databases)
        elif scan_type == "sqlmap_fingerprint":
            value = dbms if dbms != "Not detected" else ("DETECTED" if injection_evidence else "NOT DETECTED")
            label = "DBMS FINGERPRINT"
            item_count = 1 if dbms != "Not detected" else 0
        elif scan_type == "sqlmap_forms":
            forms = len(re.findall(r"(?im)^\s*form(?:\s+number)?\s*[:#]?\s*\d+", output))
            value = str(forms) if forms else ("TESTED" if "form" in lower else "0")
            label = "FORMS ANALYZED"
            item_count = forms
        elif scan_type == "sqlmap_crawl":
            urls = len(re.findall(r"(?im)^\s*\[\+\].*(?:http|https)://", output))
            value = str(urls) if urls else ("COMPLETED" if "crawl" in lower else "0")
            label = "TARGETS DISCOVERED"
            item_count = urls
        else:
            value = "DETECTED" if injection_evidence else "NOT CONFIRMED"
            label = "INJECTION STATUS"
            item_count = len(vulnerable_lines)

        if injection_evidence:
            finding_text = "SQL injection evidence detected by SQLMap."
            if vulnerable_lines:
                finding_text = " | ".join(vulnerable_lines[:5])
            results = [{"port": "WEB", "state": "confirmed finding", "service": "SQLMAP", "version": finding_text, "risk": "HIGH"}]
            score, level = make_score(1, 0, 0)
            low, medium, high = 0, 0, 1
        else:
            results = []
            score, level, low, medium, high = 0, "LOW", 0, 0, 0

        meta=dict(base_meta)
        meta.update({
            "scan_status": "COMPLETED",
            "scan_message": "SQLMap completed; only explicitly reported injection evidence is counted as a finding.",
            "result_label": label,
            "result_value": value,
            "sqlmap_dbms": dbms,
            "sqlmap_databases": databases,
            "sqlmap_items": item_count,
        })
        return output, results, score, level, low, medium, high, meta

    except FileNotFoundError:
        message = f"[ERROR] Python could not start SQLMap.\n[INFO] SQLMap path: {SQLMAP_PATH}"
    except subprocess.TimeoutExpired:
        message = f"[ERROR] SQLMap {scan_type} timed out after {mode['timeout']} seconds."
    except Exception as error:
        message = f"[ERROR] SQLMap execution failed: {error}"

    base_meta["scan_status"] = "FAILED"
    base_meta["scan_message"] = message
    return message, [], 0, "UNKNOWN", 0, 0, 0, base_meta


# ---------- Scanner Selection ----------
def run_scan(target, scan_type, extra=None):
    if scan_type.startswith("sqlmap"):
        if not is_valid_web_target(target):
            return None, "SQLMap requires a valid HTTP or HTTPS URL."
        return run_sqlmap(target, scan_type), None

    if not is_valid_target(target):
        return None, (
            "CRITICAL ERR: Provide a valid IPv4 address or domain name. "
            "Local host addresses are not allowed."
        )

    if scan_type in {
        "nikto", "nikto_ssl", "nikto_headers", "nikto_outdated",
        "nikto_robots", "nikto_httpoptions"
    }:
        return run_nikto(target, scan_type), None

    return run_nmap(target, scan_type, extra=extra), None


# ---------- Simple email OTP verification ----------
def send_signup_otp(email, otp):
    smtp_email = os.getenv("SMTP_EMAIL", "")
    smtp_password = os.getenv("SMTP_PASSWORD", "")
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))

    if not smtp_email or not smtp_password:
        raise RuntimeError("Email is not configured. Set SMTP_EMAIL and SMTP_PASSWORD in .env.")

    message = EmailMessage()
    message["Subject"] = "Verify your Quantum Shield account"
    message["From"] = smtp_email
    message["To"] = email
    message.set_content(
        f"Your Quantum Shield verification code is: {otp}\n\n"
        "Enter this code on the verification page to finish creating your account. "
        "The code expires in 10 minutes. If you did not request this, ignore this email."
    )

    with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
        server.starttls()
        server.login(smtp_email, smtp_password)
        server.send_message(message)


# ---------- Authentication & 2FA (Updated to use login_3.html) ----------
@app.route("/")
def login():
    return render_template("login.html")


@app.route("/login", methods=["GET", "POST"])
def manual_login():
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    conn = sqlite3.connect(USER_DB)
    user = conn.execute(
        "SELECT id, username, email, password, totp_secret, is_2fa_enabled FROM users WHERE email=?",
        (email,)
    ).fetchone()
    conn.close()

    if not user:
        return render_template("login_3.html", error="❌ Account not found.")

    if not check_password_hash(user[3], password):
        return render_template("login_3.html", error="❌ Incorrect password.")

    # Check if Google Authenticator 2FA is enabled for user
    if user[5]:  # is_2fa_enabled
        session["pending_2fa_user"] = {
            "id": user[0],
            "username": user[1],
            "email": user[2],
            "totp_secret": user[4]
        }
        return redirect(url_for("verify_login_2fa"))

    session["manual_user"] = {
        "id": user[0],
        "username": user[1],
        "email": user[2]
    }

    # First-time users are sent to the Authenticator setup page.
    # Users who already enabled 2FA continue to the verification step above.
    return redirect(url_for("setup_2fa"))


@app.route("/login/verify-2fa", methods=["GET", "POST"])
def verify_login_2fa():
    pending_user = session.get("pending_2fa_user")
    if not pending_user:
        return redirect("/")

    if request.method == "POST":
        code = request.form.get("otp", "").strip()
        totp = pyotp.TOTP(pending_user["totp_secret"])

        if totp.verify(code):
            session.pop("pending_2fa_user", None)
            session["manual_user"] = {
                "id": pending_user["id"],
                "username": pending_user["username"],
                "email": pending_user["email"]
            }
            return redirect("/home")
        else:
            return render_template("verify_login_2fa.html", error="❌ Invalid Authenticator code. Try again.")

    return render_template("verify_login_2fa.html")


@app.route("/settings/2fa-setup", methods=["GET", "POST"])
def setup_2fa():
    if not logged_in():
        return redirect("/")

    user_info = session.get("manual_user") or session.get("user")
    email = user_info.get("email") if isinstance(user_info, dict) else user_info
    if not email:
        return redirect("/")

    conn = sqlite3.connect(USER_DB)

    if request.method == "POST":
        token = request.form.get("otp", "").strip()
        secret = session.get("temp_totp_secret")

        if not secret:
            conn.close()
            return redirect(url_for("setup_2fa"))

        if not re.fullmatch(r"\d{6}", token):
            conn.close()
            return render_template(
                "setup_2fa.html",
                error="Enter the 6-digit code shown in your Authenticator app.",
                qr_code=session.get("temp_qr", ""),
                secret=secret
            )

        if pyotp.TOTP(secret).verify(token, valid_window=1):
            conn.execute(
                "UPDATE users SET totp_secret=?, is_2fa_enabled=1 WHERE email=?",
                (secret, email)
            )
            conn.commit()
            conn.close()
            session.pop("temp_totp_secret", None)
            session.pop("temp_qr", None)
            return render_template(
                "settings.html",
                success_msg="Google Authenticator 2FA enabled successfully!"
            )

        conn.close()
        return render_template(
            "setup_2fa.html",
            error="Invalid code. Check your phone's time and try the current 6-digit code.",
            qr_code=session.get("temp_qr", ""),
            secret=secret
        )

    # Reuse the same QR and secret if the setup page is refreshed.
    secret = session.get("temp_totp_secret")
    qr_base64 = session.get("temp_qr")
    if not secret or not qr_base64:
        secret = pyotp.random_base32()
        session["temp_totp_secret"] = secret

        totp_uri = pyotp.TOTP(secret).provisioning_uri(
            name=email,
            issuer_name="Quantum Shield"
        )
        img = qrcode.make(totp_uri)
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        qr_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")
        session["temp_qr"] = qr_base64

    conn.close()
    return render_template("setup_2fa.html", qr_code=qr_base64, secret=secret)


@app.route("/signup")
def signup():
    return render_template("signup.html")


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")

    if not username or not email or not password:
        return render_template("signup.html", error="Please complete all fields.")
    if password != confirm:
        return render_template("signup.html", error="Passwords do not match.")
    if len(password) < 8:
        return render_template("signup.html", error="Password must be at least 8 characters.")

    conn = sqlite3.connect(USER_DB)
    exists = conn.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    if exists:
        return render_template("signup.html", error="Email already exists. Please log in.")

    otp = f"{secrets.randbelow(1000000):06d}"
    session["signup_pending"] = {
        "username": username,
        "email": email,
        "password": generate_password_hash(password),
        "otp": otp,
        "expires": (datetime.now() + timedelta(minutes=10)).timestamp(),
        "attempts": 0,
    }

    try:
        send_signup_otp(email, otp)
    except Exception as error:
        session.pop("signup_pending", None)
        app.logger.error("Signup OTP email failed: %s", error)
        return render_template("signup.html", error="Could not send verification email. Check your email settings and try again.")

    return redirect(url_for("verify_signup_otp"))


@app.route("/verify-signup", methods=["GET", "POST"])
def verify_signup_otp():
    pending = session.get("signup_pending")
    if not pending:
        return redirect(url_for("signup"))

    if request.method == "POST":
        code = request.form.get("otp", "").strip()
        pending["attempts"] = pending.get("attempts", 0) + 1
        session["signup_pending"] = pending

        if pending["attempts"] > 5:
            session.pop("signup_pending", None)
            return render_template("verify_otp.html", error="Too many attempts. Please create your account again.")
        if datetime.now().timestamp() > pending["expires"]:
            session.pop("signup_pending", None)
            return render_template("signup.html", error="Verification code expired. Please create your account again.")
        if not secrets.compare_digest(code, pending["otp"]):
            return render_template("verify_otp.html", error="Incorrect code. Please try again.", email=pending["email"])

        conn = sqlite3.connect(USER_DB)
        try:
            conn.execute(
                "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                (pending["username"], pending["email"], pending["password"])
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            session.pop("signup_pending", None)
            return render_template("signup.html", error="That email is already registered. Please log in.")
        conn.close()
        session.pop("signup_pending", None)
        return render_template("login_3.html", message="Email verified! Your account is ready. Please log in.")

    return render_template("verify_otp.html", email=pending["email"])


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgetpassword.html")

    email = request.form.get("email", "").strip().lower()
    new_password = request.form.get("new_password", "")
    confirm = request.form.get("confirm_password", "")

    if new_password != confirm:
        return render_template("forgetpassword.html", error="Passwords do not match.")

    conn = sqlite3.connect(USER_DB)
    user = conn.execute(
        "SELECT id FROM users WHERE email=?", (email,)
    ).fetchone()

    if not user:
        conn.close()
        return render_template("forgetpassword.html", error="Account not found.")

    conn.execute(
        "UPDATE users SET password=? WHERE email=?",
        (generate_password_hash(new_password), email)
    )
    conn.commit()
    conn.close()

    return redirect("/")


@app.route("/login/google")
def login_google():
    redirect_uri = url_for("authorize", _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route("/authorize")
def authorize():
    """Complete Google sign-in, then require Authenticator setup/verification."""
    token = google.authorize_access_token()
    google_user = token.get("userinfo")

    if not google_user:
        response = google.get("userinfo")
        response.raise_for_status()
        google_user = response.json()

    email = str(google_user.get("email", "")).strip().lower()
    username = str(
        google_user.get("name")
        or google_user.get("given_name")
        or (email.split("@", 1)[0] if email else "")
    ).strip()

    if not email:
        return redirect(url_for("login"))

    conn = sqlite3.connect(USER_DB)
    try:
        user = conn.execute(
            "SELECT id, username, email, totp_secret, is_2fa_enabled "
            "FROM users WHERE email=?",
            (email,)
        ).fetchone()

        # Google-only accounts also need a local record to store their
        # Authenticator secret. The random password cannot be used to sign in.
        if not user:
            random_password_hash = generate_password_hash(secrets.token_urlsafe(32))
            conn.execute(
                "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                (username or email.split("@", 1)[0], email, random_password_hash)
            )
            conn.commit()
            user = conn.execute(
                "SELECT id, username, email, totp_secret, is_2fa_enabled "
                "FROM users WHERE email=?",
                (email,)
            ).fetchone()
    finally:
        conn.close()

    if not user:
        return redirect(url_for("login"))

    # Do not create an authenticated session until 2FA succeeds.
    session.pop("user", None)
    session.pop("manual_user", None)
    session.pop("pending_2fa_user", None)

    if user[4] and user[3]:
        session["pending_2fa_user"] = {
            "id": user[0],
            "username": user[1],
            "email": user[2],
            "totp_secret": user[3]
        }
        return redirect(url_for("verify_login_2fa"))

    session["manual_user"] = {
        "id": user[0],
        "username": user[1],
        "email": user[2]
    }
    return redirect(url_for("setup_2fa"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ---------- Security feature helpers ----------
def current_username():
    user = session.get("manual_user") or session.get("user") or {}
    if isinstance(user, dict):
        return str(user.get("email") or user.get("name") or user.get("username") or "user")
    return str(user)


def write_audit(action, target="", details=""):
    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        "INSERT INTO audit_log (username, action, target, details, created_at) VALUES (?, ?, ?, ?, ?)",
        (current_username(), action, target, details, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()


def target_is_authorized(target):
    normalized = (target or "").strip().lower().rstrip(".")
    conn = sqlite3.connect(DB_FILE)
    rows = conn.execute("SELECT target FROM authorized_targets").fetchall()
    conn.close()
    return any(normalized == row[0].strip().lower().rstrip(".") for row in rows)


def ensure_remediation_items(scan_id, target, results):
    conn = sqlite3.connect(DB_FILE)
    for index, item in enumerate(results or []):
        if not isinstance(item, dict):
            continue
        title = str(item.get("finding") or item.get("title") or item.get("service") or item.get("port") or "Scan observation")
        evidence = str(item.get("evidence") or item.get("version") or item.get("description") or item.get("state") or "")
        severity = str(item.get("severity") or item.get("risk") or "Unknown").title()
        if severity not in {"Critical", "High", "Medium", "Low", "Unknown", "Info", "Informational"}:
            severity = "Unknown"
        key_source = json.dumps({"title": title, "evidence": evidence, "port": item.get("port"), "service": item.get("service")}, sort_keys=True)
        finding_key = str(abs(hash(key_source)))
        recommendation = str(item.get("recommendation") or item.get("remediation") or "Review this observation and confirm whether it represents a security issue before applying a fix.")
        priority = "High" if severity in {"Critical", "High"} else ("Low" if severity in {"Low", "Info", "Informational"} else "Medium")
        conn.execute("""INSERT OR IGNORE INTO remediation_items
            (scan_id, target, finding_key, title, severity, evidence, recommendation, status, priority, due_date, verification_result, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'Open', ?, '', '', ?)""",
            (scan_id, target, finding_key, title[:240], severity, evidence[:2000], recommendation[:2000], priority, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()


# ---------- Main Pages ----------
@app.route("/home")
def scan_home():
    if not logged_in():
        return redirect("/")
    return render_template("index.html")


@app.route("/settings")
def settings():
    return render_template("settings.html")


@app.route("/reconnaissance")
def reconnaissance():
    return render_template("reconnaissance.html")


@app.route("/scan-config")
def scan_config():
    return render_template("scanconfig.html")


@app.route("/vulnerability")
def vulnerability():
    return render_template("vulnerability.html")


@app.route("/monitoring")
def monitoring():
    return render_template("monitoring.html")


@app.route("/history")
def history():
    return render_template("scanhistory.html")


@app.route("/aiassistant")
def aiassistant():
    return render_template("aiassistant.html")


# ---------- Save Scan ----------
def save_scan(target, scan_type, raw, results, score, level, low, medium, high):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO security_scans
        (target, scan_type, timestamp, threat_score, threat_level,
         low_count, medium_count, high_count, raw_output, results_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        target, scan_type, datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        score, level, low, medium, high, raw, json.dumps(results)
    ))

    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


# ---------- Scanning ----------
@app.route("/scan", methods=["POST"])
def scan():
    if not logged_in():
        return redirect("/")

    target = request.form.get("target", "").strip()
    scan_type = request.form.get("scan_type", "quick")
    extra = {
        "scanflags": request.form.get("scanflags", ""),
        "zombie": request.form.get("zombie", ""),
        "ftp_bounce": request.form.get("ftp_bounce", ""),
    }

    # Targets no longer need to be pre-added to the Security Center allowlist.
    # The scanner's own target validation still applies.
    if not target:
        return render_template("index.html", error_msg="Enter a target IP address or domain before launching a scan.")

    write_audit("scan_started", target, "scan_type=" + str(scan_type))
    try:
        scan_result, error = run_scan(target, scan_type, extra=extra)
    except Exception as exc:
        error = "The scan could not be completed: " + str(exc)
        scan_result = None

    if error or scan_result is None:
        message = error or "The scanner did not return a result. Check that the selected scanning tool is installed and configured."
        write_audit("scan_failed", target, str(message)[:500])
        return render_template("index.html", error_msg=message)

    try:
        raw, results, score, level, low, medium, high, meta = scan_result
    except (TypeError, ValueError) as exc:
        message = "The scan ran, but Quantum Shield could not process its output: " + str(exc)
        write_audit("scan_failed", target, str(message)[:500])
        return render_template("index.html", error_msg=message)
    scan_id = save_scan(target, scan_type, raw, results, score, level, low, medium, high)
    ensure_remediation_items(scan_id, target, results)
    write_audit("scan_completed", target, "scan_id=" + str(scan_id) + "; findings=" + str(len(results or [])))

    return render_template(
        "dashboard.html",
        scan_id=scan_id,
        target=target,
        scan_type=scan_type,
        raw_output=raw,
        results=results,
        threat_score=score,
        threat_level=level,
        low_count=low,
        medium_count=medium,
        high_count=high,
        scan_meta=meta
    )


@app.route("/scan-config-run", methods=["POST"])
def scan_config_run():
    target = request.form.get("target", "").strip()
    scan_type = request.form.get("scan_type", "quick")
    extra = {
        "scanflags": request.form.get("scanflags", ""),
        "zombie": request.form.get("zombie", ""),
        "ftp_bounce": request.form.get("ftp_bounce", ""),
    }

    if request.form.get("scan_confirmed") != "yes":
        write_audit("scan_config_blocked", target, "Authorization confirmation missing.")
        return render_template("scanresult.html", error_msg="Please confirm that you are authorized to scan this target.")
    if not target:
        return render_template("scanresult.html", error_msg="Enter a target IP address or domain before launching a scan.")

    write_audit("scan_started", target, "scan_type=" + str(scan_type) + "; source=scan-config")
    scan_result, error = run_scan(target, scan_type, extra=extra)

    if error:
        write_audit("scan_failed", target, str(error)[:500])
        return render_template("scanresult.html", error_msg=error)

    raw, results, score, level, low, medium, high, meta = scan_result
    scan_id = save_scan(target, scan_type, raw, results, score, level, low, medium, high)
    ensure_remediation_items(scan_id, target, results)
    write_audit("scan_completed", target, "scan_id=" + str(scan_id) + "; source=scan-config")

    return render_template(
        "scanresult.html",
        scan_id=scan_id,
        target=target,
        scan_type=scan_type,
        results=results,
        threat_score=score,
        threat_level=level,
        low_count=low,
        medium_count=medium,
        high_count=high,
        scan_meta=meta
    )


# ---------- Scan History ----------
@app.route("/api/history")
def get_scan_history():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row

    rows = conn.execute("""
        SELECT id, target, scan_type, timestamp,
               threat_score, threat_level
        FROM security_scans
        ORDER BY id DESC
    """).fetchall()

    conn.close()
    return jsonify([dict(row) for row in rows])


# ---------- AI Assistant ----------
@app.route("/api/chat", methods=["POST"])
def chat_with_assistant():
    if not logged_in():
        return jsonify({"error": "Please log in first."}), 401
    data = request.get_json() or {}
    message = str(data.get("query", "")).strip()
    scan_id = data.get("scan_id")
    if not message:
        return jsonify({"error": "Message cannot be empty"}), 400

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    if scan_id:
        scan = conn.execute("SELECT * FROM security_scans WHERE id = ?", (scan_id,)).fetchone()
    else:
        scan = conn.execute("SELECT * FROM security_scans ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    if not scan:
        return jsonify({"reply": "There are no saved scan results to analyze yet. Run an authorized scan and ask again."})

    try:
        results = json.loads(scan["results_json"] or "[]")
    except (TypeError, json.JSONDecodeError):
        results = []
    lowered = message.lower()
    lines = [f"I am using saved scan #{scan['id']} for {scan['target']} ({scan['scan_type']}, {scan['timestamp']})."]
    if any(word in lowered for word in ("port", "service", "open")):
        ports = [item for item in results if isinstance(item, dict) and (item.get("port") or item.get("service"))]
        if ports:
            lines.append("Relevant observed port/service records:")
            for item in ports[:8]:
                lines.append("- Port: {0}; state: {1}; service: {2}; version/evidence: {3}".format(item.get("port", "N/A"), item.get("state", "N/A"), item.get("service", "N/A"), item.get("version") or item.get("evidence") or "not reported"))
        else:
            lines.append("The saved parser output contains no port/service records to quote.")
    elif any(word in lowered for word in ("fix", "remediat", "recommend", "resolve", "mitigat")):
        candidates = [item for item in results if isinstance(item, dict)]
        if candidates:
            lines.append("Prioritized review based only on records returned by the scan:")
            for item in candidates[:8]:
                severity = str(item.get("severity") or item.get("risk") or "Unknown")
                title = item.get("finding") or item.get("title") or item.get("service") or item.get("port") or "Scan observation"
                advice = item.get("recommendation") or item.get("remediation") or "Validate the evidence, identify the owning service, then apply the vendor-supported fix if confirmed."
                lines.append(f"- [{severity}] {title}: {advice}")
        else:
            lines.append("No parsed finding records were saved. This does not prove the target is secure; use a scan type that tests the security property you need.")
    elif any(word in lowered for word in ("risk", "vulnerabilit", "finding", "result", "scan")):
        lines.append(f"Saved parser records: {len(results)}. Recorded severity counts: High {scan['high_count']}, Medium {scan['medium_count']}, Low {scan['low_count']}.")
        lines.append("These counts reflect the scan parser's labels, not independent confirmation of exploitability. A CVE string or service banner alone is not proof of a vulnerable installation.")
        if results:
            for item in [x for x in results if isinstance(x, dict)][:6]:
                lines.append("- {0} | severity/risk: {1} | evidence: {2}".format(item.get("finding") or item.get("title") or item.get("service") or item.get("port") or "Observation", item.get("severity") or item.get("risk") or "Unknown", item.get("evidence") or item.get("version") or item.get("description") or item.get("state") or "No evidence field reported"))
        else:
            lines.append("No parsed findings were returned by this scan. Check the scan status/output and remember that a scan only covers its configured scope.")
    else:
        lines.append("Ask about this scan's ports, evidence, risk counts, or remediation. I will distinguish recorded output from assumptions and will not claim an issue is confirmed unless the saved evidence supports that conclusion.")
    return jsonify({"reply": "\n".join(lines), "scan_id": scan["id"], "target": scan["target"]})


# ---------- Security Center ----------
@app.route("/security-center")
def security_center():
    if not logged_in():
        return redirect("/")
    return render_template("security_center.html")


@app.route("/api/allowlist", methods=["GET", "POST", "DELETE"])
def api_allowlist():
    if not logged_in():
        return jsonify({"error": "Please log in first."}), 401
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    if request.method == "GET":
        rows = conn.execute("SELECT * FROM authorized_targets ORDER BY id DESC").fetchall()
        conn.close()
        return jsonify([dict(row) for row in rows])
    data = request.get_json(silent=True) or request.form
    target = str(data.get("target", "")).strip()
    if request.method == "POST":
        if not (is_valid_target(target) or is_valid_web_target(target)):
            conn.close()
            return jsonify({"error": "Enter a valid IP/domain or an http(s) URL for an explicitly authorized target."}), 400
        notes = str(data.get("notes", "")).strip()[:500]
        try:
            conn.execute("INSERT INTO authorized_targets (target, notes, added_by, created_at) VALUES (?, ?, ?, ?)", (target, notes, current_username(), datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({"error": "That exact target is already on the allowlist."}), 409
        conn.close()
        write_audit("allowlist_added", target, notes)
        return jsonify({"ok": True, "message": "Authorized target added."}), 201
    target_id = data.get("id")
    row = conn.execute("SELECT target FROM authorized_targets WHERE id = ?", (target_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Allowlist entry not found."}), 404
    conn.execute("DELETE FROM authorized_targets WHERE id = ?", (target_id,))
    conn.commit()
    conn.close()
    write_audit("allowlist_removed", row["target"], "Target removed from approved list.")
    return jsonify({"ok": True})


@app.route("/api/remediations", methods=["GET", "POST", "PATCH"])
def api_remediations():
    if not logged_in():
        return jsonify({"error": "Please log in first."}), 401
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    if request.method == "GET":
        rows = conn.execute("SELECT * FROM remediation_items ORDER BY CASE priority WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 ELSE 2 END, id DESC").fetchall()
        conn.close()
        return jsonify([dict(row) for row in rows])
    data = request.get_json(silent=True) or {}
    if request.method == "POST":
        scan = conn.execute("SELECT target FROM security_scans WHERE id = ?", (data.get("scan_id"),)).fetchone()
        if not scan:
            conn.close()
            return jsonify({"error": "Choose an existing scan before adding a remediation item."}), 400
        title = str(data.get("title", "")).strip()
        if not title:
            conn.close()
            return jsonify({"error": "A finding title is required."}), 400
        conn.execute("""INSERT INTO remediation_items
            (scan_id, target, finding_key, title, severity, evidence, recommendation, status, priority, due_date, verification_result, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'Open', ?, '', '', ?)""",
            (int(data["scan_id"]), scan["target"], "manual-" + str(datetime.now().timestamp()), title[:240], str(data.get("severity", "Unknown")), str(data.get("evidence", ""))[:2000], str(data.get("recommendation", ""))[:2000], "Open", str(data.get("priority", "Medium")), str(data.get("due_date", "")), datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        item_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.commit(); conn.close()
        write_audit("remediation_created", scan["target"], "remediation_id=" + str(item_id))
        return jsonify({"ok": True, "id": item_id}), 201
    item_id = data.get("id")
    status = str(data.get("status", "Open"))
    priority = str(data.get("priority", "Medium"))
    due_date = str(data.get("due_date", ""))
    verification = str(data.get("verification_result", ""))[:1000]
    if status not in {"Open", "In Progress", "Fixed", "Accepted Risk"}:
        conn.close(); return jsonify({"error": "Invalid remediation status."}), 400
    if priority not in {"Low", "Medium", "High", "Critical"}:
        conn.close(); return jsonify({"error": "Invalid priority."}), 400
    row = conn.execute("SELECT target FROM remediation_items WHERE id = ?", (item_id,)).fetchone()
    if not row:
        conn.close(); return jsonify({"error": "Remediation item not found."}), 404
    conn.execute("UPDATE remediation_items SET status=?, priority=?, due_date=?, verification_result=?, updated_at=? WHERE id=?", (status, priority, due_date, verification, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), item_id))
    conn.commit(); conn.close()
    write_audit("remediation_updated", row["target"], f"remediation_id={item_id}; status={status}; priority={priority}")
    return jsonify({"ok": True})


@app.route("/api/compare")
def api_compare():
    if not logged_in():
        return jsonify({"error": "Please log in first."}), 401
    try:
        old_id, new_id = int(request.args.get("old_id", "")), int(request.args.get("new_id", ""))
    except ValueError:
        return jsonify({"error": "Provide old_id and new_id."}), 400
    conn = sqlite3.connect(DB_FILE); conn.row_factory = sqlite3.Row
    old = conn.execute("SELECT * FROM security_scans WHERE id=?", (old_id,)).fetchone()
    new = conn.execute("SELECT * FROM security_scans WHERE id=?", (new_id,)).fetchone()
    conn.close()
    if not old or not new:
        return jsonify({"error": "Both scans must exist in history."}), 404
    if old["target"].lower().rstrip(".") != new["target"].lower().rstrip("."):
        return jsonify({"error": "Compare scans of the same target only."}), 400
    def parse_items(row):
        try: return json.loads(row["results_json"] or "[]")
        except (TypeError, json.JSONDecodeError): return []
    def signature(item):
        if not isinstance(item, dict): return str(item)
        return "|".join(str(item.get(k, "")).strip().lower() for k in ("port", "service", "finding", "title", "version", "state", "severity"))
    old_items, new_items = parse_items(old), parse_items(new)
    old_map = {signature(x): x for x in old_items}; new_map = {signature(x): x for x in new_items}
    return jsonify({"target": old["target"], "old_scan": {"id": old_id, "timestamp": old["timestamp"], "scan_type": old["scan_type"], "threat_score": old["threat_score"], "threat_level": old["threat_level"], "count": len(old_items)}, "new_scan": {"id": new_id, "timestamp": new["timestamp"], "scan_type": new["scan_type"], "threat_score": new["threat_score"], "threat_level": new["threat_level"], "count": len(new_items)}, "score_change": int(new["threat_score"] or 0)-int(old["threat_score"] or 0), "new_findings": list(new_map[k] for k in new_map.keys()-old_map.keys()), "no_longer_reported": list(old_map[k] for k in old_map.keys()-new_map.keys()), "note": "A finding absent from a later scan is 'no longer reported', not automatically verified fixed."})


@app.route("/api/audit")
def api_audit():
    if not logged_in():
        return jsonify({"error": "Please log in first."}), 401
    conn = sqlite3.connect(DB_FILE); conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 100").fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])


# ---------- PDF Report ----------
@app.route("/download_report")
def download_report():
    from xml.sax.saxutils import escape

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    scan = conn.execute(
        "SELECT * FROM security_scans ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()

    if not scan:
        return "No scan records found.", 404

    try:
        results = json.loads(scan["results_json"] or "[]")
    except (TypeError, json.JSONDecodeError):
        results = []

    score = int(scan["threat_score"] or 0)
    level = scan["threat_level"] or "UNKNOWN"
    low = int(scan["low_count"] or 0)
    medium = int(scan["medium_count"] or 0)
    high = int(scan["high_count"] or 0)

    services = sorted({
        str(item.get("service", "Unknown"))
        for item in results
    })

    source = scan["raw_output"] + " " + " ".join(
        str(item.get("version", "")) for item in results
    )

    cves = []
    for cve in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", source, re.I):
        cve = cve.upper()
        if cve not in cves:
            cves.append(cve)

    filename = f"Quantum_Shield_Report_{scan['id']}.pdf"

    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        rightMargin=42,
        leftMargin=42,
        topMargin=48,
        bottomMargin=48,
        title=f"Quantum Shield Report - {scan['target']}",
        author="Quantum Shield"
    )

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="QS_Title",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=27,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=8
    ))

    styles.add(ParagraphStyle(
        name="QS_H2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#0369a1"),
        spaceBefore=14,
        spaceAfter=9
    ))

    styles.add(ParagraphStyle(
        name="QS_Body",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor("#1e293b"),
        spaceAfter=7
    ))

    styles.add(ParagraphStyle(
        name="QS_Table",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor("#0f172a")
    ))

    styles.add(ParagraphStyle(
        name="QS_White",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.white
    ))

    elements = [
        Paragraph("QUANTUM SHIELD", styles["QS_Title"]),
        Paragraph(
            "Detailed Security Assessment & Threat Intelligence Report",
            styles["QS_Body"]
        ),
        HRFlowable(
            width="100%",
            thickness=2,
            color=colors.HexColor("#38bdf8"),
            spaceAfter=14
        )
    ]

    report_scan_type = str(scan["scan_type"] or "").lower()
    risk_scan = (report_scan_type in {
        "vuln", "vulnerability", "vuln_script", "vuln_detection_script",
        "vuln_detection", "nikto"
    } or report_scan_type.startswith("nikto")
      or report_scan_type.startswith("sqlmap"))
    summary = [
        ["Target Asset", scan["target"]],
        ["Scan Type", scan["scan_type"].upper()],
        ["Scan ID", str(scan["id"])],
        ["Timestamp", scan["timestamp"]],
        ["Risk Score", f"{score} / 100 — {level}" if risk_scan else "Not applicable to this scan type"],
        ["Structured Result Records", str(len(results))]
    ]

    table_data = [
        [
            Paragraph(f"<b>{escape(str(a))}</b>", styles["QS_Table"]),
            Paragraph(escape(str(b)), styles["QS_Table"])
        ]
        for a, b in summary
    ]

    table = Table(table_data, colWidths=[125, 365])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e0f2fe")),
        ("BACKGROUND", (1, 0), (1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.7, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7)
    ]))

    elements += [
        table,
        Paragraph("1. Executive Summary", styles["QS_H2"])
    ]

    if risk_scan:
        if level == "UNRATED":
            assessment = "No severity-rated findings were available."
        elif score >= 66:
            assessment = "CRITICAL calculated finding score. Validate findings and prioritize remediation."
        elif score >= 36:
            assessment = "HIGH calculated finding score. Validate high-priority findings."
        elif score >= 16:
            assessment = "MEDIUM calculated finding score. Review findings in context."
        else:
            assessment = "LOW calculated finding score based on findings rated by this application."
        elements.append(Paragraph(assessment, styles["QS_Body"]))
        elements.append(Paragraph(
            f"The scan recorded <b>{high} high</b>, <b>{medium} medium</b>, "
            f"and <b>{low} low</b> severity-rated findings.",
            styles["QS_Body"]
        ))
        elements.append(Paragraph("2. Risk Distribution", styles["QS_H2"]))
        risk_data = [
            [Paragraph("<b>Severity</b>", styles["QS_White"]), Paragraph("<b>Count</b>", styles["QS_White"]), Paragraph("<b>Interpretation</b>", styles["QS_White"])],
            ["HIGH", str(high), "Priority issues requiring prompt investigation."],
            ["MEDIUM", str(medium), "Review based on exposure and impact."],
            ["LOW", str(low), "Lower-risk observations or hardening opportunities."]
        ]
        risk_table = Table(risk_data, colWidths=[100, 70, 320], repeatRows=1)
        risk_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP")
        ]))
        elements.append(risk_table)
    else:
        elements.append(Paragraph(
            "This scan type does not produce a general vulnerability risk score.",
            styles["QS_Body"]
        ))

    elements.append(Paragraph("3. Scan Scope & Technical Overview", styles["QS_H2"]))
    elements.append(Paragraph(
        f"Quantum Shield executed a <b>{escape(scan['scan_type'].upper())}</b> "
        f"assessment against <b>{escape(scan['target'])}</b>.",
        styles["QS_Body"]
    ))

    if services:
        elements.append(Paragraph(
            "<b>Observed services:</b> " + escape(", ".join(services)),
            styles["QS_Body"]
        ))

    elements.append(Paragraph("4. Detailed Findings", styles["QS_H2"]))

    finding_data = [[
        Paragraph("<b>Port / Node</b>", styles["QS_White"]),
        Paragraph("<b>State</b>", styles["QS_White"]),
        Paragraph("<b>Service</b>", styles["QS_White"]),
        Paragraph("<b>Version / Finding</b>", styles["QS_White"]),
        Paragraph("<b>Risk</b>", styles["QS_White"])
    ]]

    for item in results:
        finding_data.append([
            Paragraph(escape(str(item.get("port", "N/A"))), styles["QS_Table"]),
            Paragraph(escape(str(item.get("state", "N/A"))), styles["QS_Table"]),
            Paragraph(escape(str(item.get("service", "N/A"))), styles["QS_Table"]),
            Paragraph(escape(str(item.get("version", "N/A"))), styles["QS_Table"]),
            Paragraph("<b>" + escape(str(item.get("risk", "UNKNOWN"))) + "</b>", styles["QS_Table"])
        ])

    if len(finding_data) == 1:
        finding_data.append([
            Paragraph("No findings were returned.", styles["QS_Table"]),
            "", "", "", ""
        ])

    finding_table = Table(finding_data, colWidths=[65, 55, 85, 225, 55], repeatRows=1)
    finding_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP")
    ]))

    elements.append(finding_table)

    elements.append(Paragraph("5. CVE References", styles["QS_H2"]))
    if cves:
        cve_data = [[
            Paragraph("<b>CVE Reference</b>", styles["QS_White"]),
            Paragraph("<b>Source</b>", styles["QS_White"])
        ]]
        for cve in cves:
            cve_data.append([
                Paragraph(escape(cve), styles["QS_Table"]),
                Paragraph("Reported or referenced in stored scan output.", styles["QS_Table"])
            ])
        cve_table = Table(cve_data, colWidths=[150, 340], repeatRows=1)
        cve_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")])
        ]))
        elements.append(cve_table)
    else:
        elements.append(Paragraph("No CVE references were present.", styles["QS_Body"]))

    elements.append(PageBreak())
    elements.append(Paragraph("6. Scanner Output Appendix", styles["QS_H2"]))
    raw_output = scan["raw_output"] or "No raw scanner output was stored."
    if len(raw_output) > 12000:
        raw_output = raw_output[:12000] + "\n\n[Output truncated.]"

    elements.append(Paragraph(escape(raw_output).replace("\n", "<br/>"), styles["QS_Body"]))

    def page_number(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(42, 25, "QUANTUM SHIELD — SECURITY INTELLIGENCE REPORT")
        canvas.drawRightString(570, 25, f"Page {document.page}")
        canvas.restoreState()

    doc.build(elements, onFirstPage=page_number, onLaterPages=page_number)

    return send_file(filename, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)