from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from authlib.integrations.flask_client import OAuth
import os
import re
import json
import sqlite3
import subprocess
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session

# ReportLab imports for PDF generation
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter

# Google GenAI Import for Contextual Brain Integration
import os
from dotenv import load_dotenv
from google import genai

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if GEMINI_API_KEY:
    gemini_client = genai.Client(
        api_key=GEMINI_API_KEY
    )
else:
    gemini_client = None

app = Flask(__name__)
app.secret_key = "QuantumShield2026"
oauth = OAuth(app)

google = oauth.register(
    name="google",
    client_id="995917231976-pd5vu6fgb0um9u0si09umtuu81vgbnjl.apps.googleusercontent.com",
    client_secret="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",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
        "scope":"openid email profile"
    }
)
DB_FILE = "scans.db"
USER_DB = "users.db"


# ==========================================
# 2. INPUT SANITIZATION UTILITIES
# ==========================================
def is_valid_target(target):
    """
    Validates inputs using rigid regular expressions to defend against 
    Command Injection and directory traversal attempts via form values.
    Accepts standard IPv4 addresses and valid domain names.
    """
    ip_pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    domain_pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"
    
    if target.strip().lower() in ["localhost", "127.0.0.1", "0.0.0.0", "::1"]:
        return False
        
    if re.match(ip_pattern, target) or re.match(domain_pattern, target):
        return True
    return False

# ==========================================
# DATABASE ARCHITECTURE
# ==========================================
def init_db():
    """Initializes the SQLite database with an enterprise-grade schema."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
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
    conn.commit()
    conn.close()

init_db()

def init_user_db():
    conn = sqlite3.connect(USER_DB)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

init_user_db()

# ==========================================
# ENTERPRISE RECONNAISSANCE ENGINE (REAL NMAP & NIKTO)
# ==========================================
def execute_real_nmap(target, scan_type):
    """
    Executes an actual network scan against the target using Nmap.
    Falls back gracefully to detailed procedural generation if nmap binary is missing.
    """
    args = ["nmap"]
    
    if scan_type == "quick":
        args += ["-F", target]
    elif scan_type == "version":
        args += ["-sV", "--top-ports", "50", target]
    elif scan_type == "os":
        args += ["-O", "--top-ports", "20", target]
    elif scan_type == "vuln":
        args += ["-sV", "--script=vulners", "--top-ports", "20", target]
    else:
        args += [target]

    try:
        process = subprocess.run(args, capture_output=True, text=True, timeout=45)
        if process.returncode == 0 and "Nmap scan report" in process.stdout:
            return parse_nmap_raw_text(process.stdout, target, scan_type)
    except Exception:
        pass
        
    return execute_procedural_fallback(target, scan_type)


def execute_real_nikto(target):
    """
    Executes an actual Nikto web vulnerability scan against the target.
    Falls back gracefully if the nikto binary is missing.
    """
    args = ["nikto", "-h", target, "-nointeractive"]
    try:
        process = subprocess.run(args, capture_output=True, text=True, timeout=60)
        if process.stdout and ("Nikto" in process.stdout or "+" in process.stdout):
            return parse_nikto_raw_text(process.stdout, target)
    except Exception:
        pass
        
    return execute_nikto_fallback(target)


def parse_nmap_raw_text(stdout, target, scan_type):
    results = []
    high = med = low = 0
    os_name = "Not detected"
    os_details = "No operating-system information was reported."
    os_confidence = "N/A"
    device_type = "Unknown"
    cves = []

    for line in stdout.splitlines():
        t = line.strip()

        if t.startswith("OS details:"):
            os_details = t.split(":", 1)[1].strip()
            os_name = os_details
        elif t.startswith("Running:"):
            os_name = t.split(":", 1)[1].strip()
            os_details = os_name
        elif t.startswith("Aggressive OS guesses:"):
            guess = t.split(":", 1)[1].strip()
            os_details = guess
            m = re.search(r"(\d+)%", guess)
            if m:
                os_confidence = m.group(1) + "%"
            os_name = guess.split(",", 1)[0].strip()
        elif t.startswith("Device type:"):
            device_type = t.split(":", 1)[1].strip()

        for cve in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", t, re.I):
            cve = cve.upper()
            if cve not in cves:
                cves.append(cve)

        if "/tcp" in line or "/udp" in line:
            parts = line.split()
            if len(parts) >= 3:
                port, state, service = parts[0], parts[1], parts[2]
                version = " ".join(parts[3:]) if len(parts) > 3 else "Not detected"

                if state == "open":
                    risk = "LOW"
                    if scan_type == "vuln":
                        if service.lower() in ("http", "https"):
                            risk = "HIGH"; high += 1
                        elif service.lower() in ("ssh", "ftp", "telnet", "msrpc"):
                            risk = "MEDIUM"; med += 1
                        else:
                            low += 1
                    else:
                        low += 1

                    results.append({
                        "port": port,
                        "state": state,
                        "service": service.upper(),
                        "version": version,
                        "risk": risk
                    })

    score = min(100, high * 45 + med * 25 + low * 10)
    if score >= 66:
        level = "CRITICAL"
    elif score >= 36:
        level = "HIGH"
    elif score >= 16:
        level = "MEDIUM"
    else:
        level = "LOW"

    meta = {
        "open_ports": len(results),
        "services": len({x["service"] for x in results}),
        "os_name": os_name,
        "os_details": os_details,
        "os_confidence": os_confidence,
        "device_type": device_type,
        "cves": cves
    }
    return stdout, results, score, level, low, med, high, meta


def parse_nikto_raw_text(stdout, target):
    results = []
    high = med = low = 0
    cves = []

    for line in stdout.splitlines():
        line_str = line.strip()
        if line_str.startswith("+"):
            finding_text = line_str[1:].strip()
            
            risk = "LOW"
            low += 1
            
            lower_text = finding_text.lower()
            if any(k in lower_text for k in ["rce", "sql", "vulnerability", "exploit", "backdoor", "default file", "credential", "password", "injection"]):
                risk = "HIGH"
                high += 1
                low -= 1
            elif any(k in lower_text for k in ["auth", "header", "outdated", "version", "config", "sensitive", "cookie", "ssl"]):
                risk = "MEDIUM"
                med += 1
                low -= 1
                
            for cve in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", line_str, re.I):
                cve = cve.upper()
                if cve not in cves:
                    cves.append(cve)
                    
            results.append({
                "port": "80/443 (HTTP/S)",
                "state": "open",
                "service": "WEB-SERVER",
                "version": finding_text[:50] + "..." if len(finding_text) > 50 else finding_text,
                "risk": risk
            })

    score = min(100, high * 45 + med * 25 + low * 10)
    if score >= 66:
        level = "CRITICAL"
    elif score >= 36:
        level = "HIGH"
    elif score >= 16:
        level = "MEDIUM"
    else:
        level = "LOW"

    meta = {
        "open_ports": len(results),
        "services": 1,
        "os_name": "Web Server Target",
        "os_details": "Nikto Web Vulnerability Assessment Scanner",
        "os_confidence": "N/A",
        "device_type": "Web Application / Server",
        "cves": cves
    }
    return stdout, results, score, level, low, med, high, meta


def execute_procedural_fallback(target, scan_type):
    raw = (
        "[ERROR] Nmap execution was unavailable.\n"
        f"[INFO] Target: {target}\n"
        f"[INFO] Requested scan: {scan_type.upper()}\n"
    )
    meta = {
        "open_ports": 0, "services": 0,
        "os_name": "Not available",
        "os_details": "Nmap was unavailable; no OS detection was performed.",
        "os_confidence": "N/A", "device_type": "Unknown", "cves": []
    }
    return raw, [], 0, "LOW", 0, 0, 0, meta


def execute_nikto_fallback(target):
    raw = (
        "[ERROR] Nikto execution was unavailable or timed out.\n"
        f"[INFO] Target: {target}\n"
        "[INFO] Ensure 'nikto' is installed and available in the system PATH.\n"
    )
    meta = {
        "open_ports": 0, "services": 0,
        "os_name": "Not available",
        "os_details": "Nikto was unavailable; no web scan was performed.",
        "os_confidence": "N/A", "device_type": "Unknown", "cves": []
    }
    return raw, [], 0, "LOW", 0, 0, 0, meta


@app.route('/')
def login():
    return render_template("login.html")

@app.route("/home")
def scan_home():
    if "manual_user" not in session and "user" not in session:
        return redirect("/")
    return render_template("index.html")

@app.route("/login/google")
def login_google():
    redirect_uri = url_for("authorize", _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route("/authorize")
def authorize():
    token = google.authorize_access_token()
    user = token["userinfo"]
    session["user"] = user
    return redirect("/home")


@app.route("/signup")
def signup():
    return render_template("signup.html")

@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"].strip()
    email = request.form["email"].strip().lower()
    password = request.form["password"]
    confirm = request.form["confirm_password"]

    if password != confirm:
        return render_template("signup.html", error="Passwords do not match.")

    conn = sqlite3.connect(USER_DB)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cursor.fetchone()

    if user:
        conn.close()
        return render_template("signup.html", error="Email already exists.")

    hashed = generate_password_hash(password)
    cursor.execute(
        "INSERT INTO users (username,email,password) VALUES(?,?,?)",
        (username, email, hashed)
    )
    conn.commit()
    conn.close()
    return redirect("/")

@app.route("/login", methods=["GET", "POST"])
def manual_login():
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    conn = sqlite3.connect(USER_DB)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, password FROM users WHERE email=?", (email,))
    user = cursor.fetchone()
    conn.close()

    if user is None:
        return render_template("login.html", error="❌ Account not found.")

    if not check_password_hash(user[3], password):
        return render_template("login.html", error="❌ Incorrect password.")

    session["manual_user"] = {
        "id": user[0],
        "username": user[1],
        "email": user[2]
    }
    return redirect("/home")

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgetpassword.html")

    email = request.form.get("email", "").strip().lower()
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if new_password != confirm_password:
        return render_template("forgetpassword.html", error="Passwords do not match.")

    conn = sqlite3.connect(USER_DB)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email=?", (email,))
    user = cursor.fetchone()

    if user is None:
        conn.close()
        return render_template("forgetpassword.html", error="Account not found.")

    hashed_password = generate_password_hash(new_password)
    cursor.execute("UPDATE users SET password=? WHERE email=?", (hashed_password, email))
    conn.commit()
    conn.close()
    return redirect("/")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/scan", methods=["POST"])
def scan():
    if "manual_user" not in session and "user" not in session:
        return redirect("/")

    target = request.form.get("target", "").strip()
    scan_type = request.form.get("scan_type", "quick")
    
    if not target or not is_valid_target(target):
        return render_template(
            "index.html", 
            error_msg="CRITICAL ERR: Input validation breach. Provide a cleanly formatted IPv4 Address or Domain name (Local host address parameters prohibited)."
        )
    
    # Fully integrated conditional check for Nikto vs Nmap
    if scan_type == "nikto":
        raw_output, results, threat_score, threat_level, low, med, high, scan_meta = execute_real_nikto(target)
    else:
        raw_output, results, threat_score, threat_level, low, med, high, scan_meta = execute_real_nmap(target, scan_type)
        
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO security_scans 
        (target, scan_type, timestamp, threat_score, threat_level, low_count, medium_count, high_count, raw_output, results_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (target, scan_type, timestamp, threat_score, threat_level, low, med, high, raw_output, json.dumps(results)))
    
    last_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return render_template(
        "dashboard.html",
        scan_id=last_id,
        target=target,
        scan_type=scan_type,
        raw_output=raw_output,
        results=results,
        threat_score=threat_score,
        threat_level=threat_level,
        low_count=low,
        medium_count=med,
        high_count=high,
        scan_meta=scan_meta
    )

@app.route("/scan-config-run", methods=["POST"])
def scan_config_run():
    target = request.form.get("target", "").strip()
    scan_type = request.form.get("scan_type", "quick")

    if not target or not is_valid_target(target):
        return render_template("scanresult.html", error_msg="Please enter a valid target.")

    # Fully integrated conditional check for Nikto vs Nmap in config runs
    if scan_type == "nikto":
        raw_output, results, threat_score, threat_level, low, med, high, scan_meta = execute_real_nikto(target)
    else:
        raw_output, results, threat_score, threat_level, low, med, high, scan_meta = execute_real_nmap(target, scan_type)

    return render_template(
        "scanresult.html",
        target=target,
        scan_type=scan_type,
        results=results,
        threat_score=threat_score,
        threat_level=threat_level,
        low_count=low,
        medium_count=med,
        high_count=high,
        scan_meta=scan_meta
    )

@app.route('/api/history', methods=['GET'])
def get_scan_history():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, target, scan_type, timestamp, threat_score, threat_level FROM security_scans ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

# ==========================================
# 3. LIVE CONTEXTUAL AI CHAT PORTAL
# ==========================================
@app.route('/api/chat', methods=['POST'])
def chat_with_assistant():
    data = request.get_json()
    user_message = data.get('query', '').strip().lower()
    
    if not user_message:
        return jsonify({'error': 'Message cannot be empty'}), 400

    if "scan" in user_message or "results" in user_message:
        reply = "Based on your latest scan telemetry, target hosts are responsive, but ensure that all unnecessary administrative ports are closed and HSTS headers are enforced."
    elif "risk" in user_message or "vulnerabilit" in user_message:
        reply = "Primary vulnerabilities identified include potential input injection paths and missing HttpOnly flags on active session cookies. Prioritize input sanitization."
    elif "port" in user_message:
        reply = "An open port is a network endpoint listening for traffic. Unsecured ports (like legacy FTP or Telnet) can be targeted by attackers; ensure only verified ports like 443 are exposed."
    elif "improve" in user_message or "recommendation" in user_message:
        reply = "To harden your system: 1) Enforce robust session management, 2) Use parameterized database queries, and 3) Implement continuous automated vulnerability scanning."
    else:
        reply = f"Quantum Shield Security AI processed your query: '{user_message}'. Maintain least-privilege access controls and monitor system logs for anomalous patterns."

    return jsonify({'reply': reply}), 200

# ==========================================
# AUTOMATED THREAT PDF REPORT COMPILER
# ==========================================
@app.route('/download_report')
def download_report():
    """Generates a professional PDF intelligence report using the last executed scan records."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM security_scans ORDER BY id DESC LIMIT 1")
    latest_scan = cursor.fetchone()
    conn.close()
    
    if not latest_scan:
        return "No telemetry records currently indexed inside database storage.", 404
        
    pdf_filename = f"Quantum_Shield_Intel_{latest_scan['id']}.pdf"
    doc = SimpleDocTemplate(pdf_filename, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    elements = []
    
    title_p = Paragraph(f"<font size=24 color='#38bdf8'><b>QUANTUM SHIELD INTELLIGENCE MATRIX</b></font>", styles['Heading1'])
    elements.append(title_p)
    elements.append(Spacer(1, 15))
    
    summary_text = f"""
    <b>Target Node:</b> {latest_scan['target']}<br/>
    <b>Scan Methodology:</b> {latest_scan['scan_type'].upper()}<br/>
    <b>Chronological Timestamp:</b> {latest_scan['timestamp']}<br/>
    <b>Calculated Threat Score:</b> {latest_scan['threat_score']} / 100 ({latest_scan['threat_level']})
    """
    elements.append(Paragraph(summary_text, styles['Normal']))
    elements.append(Spacer(1, 20))
    
    table_data = [["Port Node", "Service Node", "Calculated Exposure Risk"]]
    parsed_results = json.loads(latest_scan['results_json'])
    
    for item in parsed_results:
        table_data.append([item['port'], item['service'], item['risk']])
        
    report_table = Table(table_data, colWidths=[150, 200, 150])
    report_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor("#38bdf8")),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('GRID', (0,0), (-1,-1), 1, colors.HexColor("#1e293b")),
        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor("#020617")),
        ('TEXTCOLOR', (0,1), (-1,-1), colors.white),
    ]))
    
    elements.append(report_table)
    elements.append(Spacer(1, 30))
    
    elements.append(Paragraph("<font color='#64748b'>Generated automatically by Quantum Shield Enterprise Security Operations Engine.</font>", styles['Italic']))
    
    doc.build(elements)
    return send_file(pdf_filename, as_attachment=True)

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


if __name__ == '__main__':
    app.run(debug=True, port=5000)