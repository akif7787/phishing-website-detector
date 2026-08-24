"""
Phishing Website Detection System - Flask Application Server
Provides RESTful analysis endpoints, SSRF validation, security heuristic inspection,
and responsive dashboard web interface.
"""

import os
from datetime import datetime, timezone
from typing import Any, Dict

from flask import Flask, jsonify, render_template, request, send_from_directory
from flask_cors import CORS

from analyzer.database import AnalysisDatabase
from analyzer.dns_analyzer import DNSAnalyzer
from analyzer.domain_analyzer import DomainAnalyzer
from analyzer.risk_engine import RiskEngine
from analyzer.ssl_analyzer import SSLAnalyzer
from analyzer.ssrf_validator import SSRFValidator
from analyzer.url_analyzer import URLAnalyzer

# Initialize Flask application with public/templates support
app = Flask(__name__, template_folder="public" if os.path.exists("public/index.html") else "templates", static_folder="static")

# Configuration
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-educational-secret-key-2026")
app.config["JSON_SORT_KEYS"] = False
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16 KB request limit to prevent DoS

# Configure CORS for Netlify frontend and cross-origin clients
cors_origins_env = os.getenv("CORS_ORIGINS", "*")
allowed_origins = [o.strip() for o in cors_origins_env.split(",") if o.strip()] if cors_origins_env != "*" else "*"

CORS(
    app,
    resources={r"/api/*": {"origins": allowed_origins}},
    methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
    supports_credentials=True,
)

# Initialize SQLite database (supports /tmp path for ephemeral environments)
DB_PATH = os.getenv("DATABASE_PATH", "analysis_history.db")
AnalysisDatabase.init_db(DB_PATH)


@app.route("/", methods=["GET"])
def index():
    """
    Renders the primary cybersecurity dashboard user interface.
    """
    return render_template("index.html")


@app.route("/css/<path:filename>", methods=["GET"])
def serve_css(filename):
    folder = "public/css" if os.path.exists("public/css") else "static/css"
    return send_from_directory(folder, filename)


@app.route("/js/<path:filename>", methods=["GET"])
def serve_js(filename):
    folder = "public/js" if os.path.exists("public/js") else "static/js"
    return send_from_directory(folder, filename)


@app.route("/api/analyze", methods=["POST"])
def analyze_url():
    """
    Main URL security analysis endpoint.
    Accepts JSON: {"url": "https://example.com"}
    or form data: url=https://example.com
    """
    # Parse request data
    raw_url = None
    if request.is_json:
        data = request.get_json(silent=True) or {}
        raw_url = data.get("url")
    else:
        raw_url = request.form.get("url")

    if not raw_url or not isinstance(raw_url, str) or not raw_url.strip():
        return jsonify({
            "status": "error",
            "error_type": "VALIDATION_ERROR",
            "message": "Please enter a valid URL to analyze.",
        }), 400

    raw_url = raw_url.strip()

    # 1. SSRF and Syntax Validation
    ssrf_result = SSRFValidator.validate_and_sanitize(raw_url)
    if not ssrf_result.is_safe:
        return jsonify({
            "status": "error",
            "error_type": "SSRF_SECURITY_BLOCK",
            "message": ssrf_result.error_message or "URL rejected due to security policy.",
            "submitted_url": raw_url,
        }), 400

    sanitized_url = ssrf_result.sanitized_url
    hostname = ssrf_result.hostname
    port = ssrf_result.port
    scheme = ssrf_result.scheme
    resolved_ips = ssrf_result.resolved_ips
    is_ip_host = ssrf_result.is_ip_host

    # 2. Modular Analyzers
    # A. URL Lexical & Heuristic Analysis
    url_data = URLAnalyzer.analyze(sanitized_url)

    # B. DNS Record Inspection
    dns_data = DNSAnalyzer.analyze(
        hostname=hostname,
        is_ip_host=is_ip_host,
        pre_resolved_ips=resolved_ips,
    )

    # C. Domain / WHOIS Registration Inspection
    domain_data = DomainAnalyzer.analyze(
        registered_domain=url_data.get("registered_domain") or hostname,
        is_ip_host=is_ip_host,
    )

    # D. SSL / TLS Certificate Inspection
    ssl_data = SSLAnalyzer.analyze(
        hostname=hostname,
        port=port,
        scheme=scheme,
        is_ip_host=is_ip_host,
    )

    # 3. Transparent Phishing Risk Scoring Engine
    risk_assessment = RiskEngine.evaluate(
        url_data=url_data,
        dns_data=dns_data,
        domain_data=domain_data,
        ssl_data=ssl_data,
    )

    # Prepare response payload
    timestamp_iso = datetime.now(timezone.utc).isoformat()
    response_payload: Dict[str, Any] = {
        "status": "success",
        "submitted_url": raw_url,
        "sanitized_url": sanitized_url,
        "hostname": hostname,
        "domain": url_data.get("registered_domain") or hostname,
        "timestamp": timestamp_iso,
        "risk_score": risk_assessment["risk_score"],
        "risk_level": risk_assessment["risk_level"],
        "risk_tier": risk_assessment["risk_tier"],
        "badge_color": risk_assessment["badge_color"],
        "summary": risk_assessment["summary"],
        "indicator_count": risk_assessment["indicator_count"],
        "indicators": risk_assessment["indicators"],
        "positive_factors": risk_assessment["positive_factors"],
        "recommendations": risk_assessment["recommendations"],
        "disclaimer": risk_assessment["disclaimer"],
        "url_analysis": url_data,
        "dns_analysis": dns_data,
        "domain_analysis": domain_data,
        "ssl_analysis": ssl_data,
    }

    # Save to SQLite history
    top_ind = None
    if risk_assessment["indicators"]:
        top_ind = risk_assessment["indicators"][0]["name"]

    try:
        history_id = AnalysisDatabase.save_analysis(
            url=sanitized_url,
            domain=url_data.get("registered_domain") or hostname,
            risk_score=risk_assessment["risk_score"],
            risk_level=risk_assessment["risk_level"],
            risk_tier=risk_assessment["risk_tier"],
            top_indicator=top_ind,
            result_dict=response_payload,
            db_path=DB_PATH,
        )
        response_payload["history_id"] = history_id
    except Exception as e:
        # Non-fatal error; log or proceed
        response_payload["history_id"] = None

    return jsonify(response_payload), 200


@app.route("/api/history", methods=["GET"])
def get_history():
    """
    Returns recent URL analysis history records.
    """
    limit = request.args.get("limit", default=20, type=int)
    limit = max(1, min(100, limit))
    try:
        history = AnalysisDatabase.get_recent_analyses(limit=limit, db_path=DB_PATH)
        return jsonify({
            "status": "success",
            "count": len(history),
            "history": history,
        }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to retrieve history: {str(e)}",
        }), 500


@app.route("/api/history/<int:item_id>", methods=["GET"])
def get_history_item(item_id: int):
    """
    Retrieves full stored JSON analysis for a specific history ID.
    """
    try:
        item = AnalysisDatabase.get_analysis_by_id(item_id, db_path=DB_PATH)
        if not item:
            return jsonify({
                "status": "error",
                "message": "Analysis report not found.",
            }), 404
        return jsonify({
            "status": "success",
            "report": item,
        }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to retrieve report: {str(e)}",
        }), 500


@app.route("/api/history", methods=["DELETE"])
def clear_history():
    """
    Clears all saved history records.
    """
    try:
        AnalysisDatabase.clear_history(db_path=DB_PATH)
        return jsonify({
            "status": "success",
            "message": "Analysis history cleared successfully.",
        }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to clear history: {str(e)}",
        }), 500


@app.route("/api/health", methods=["GET"])
def health_check():
    """
    API Health check endpoint.
    """
    return jsonify({
        "status": "healthy",
        "service": "phishing-website-detection-system",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }), 200


@app.errorhandler(404)
def not_found_handler(e):
    if request.path.startswith("/api/"):
        return jsonify({"status": "error", "message": "API endpoint not found."}), 404
    return render_template("index.html"), 404


@app.errorhandler(405)
def method_not_allowed_handler(e):
    return jsonify({"status": "error", "message": "HTTP Method Not Allowed."}), 405


@app.errorhandler(500)
def server_error_handler(e):
    return jsonify({"status": "error", "message": "Internal server error occurred."}), 500


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5001))
    host = os.getenv("HOST", "127.0.0.1")
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    print(f"🚀 Phishing Website Detection System running at http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)
