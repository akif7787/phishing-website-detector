"""
Netlify Serverless Function Handler for PhishGuard Flask API.
Bridges AWS Lambda / Netlify Function events with standard Python WSGI Flask application.
"""

import base64
import io
import os
import sys
import urllib.parse

# Ensure root project directory is on sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(CURRENT_DIR))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Set database path to /tmp for serverless execution
os.environ.setdefault("DATABASE_PATH", "/tmp/analysis_history.db")

from app import app


def handler(event, context):
    """
    AWS Lambda / Netlify Functions proxy integration handler.
    """
    http_method = event.get("httpMethod", "GET")
    raw_path = event.get("path", "/")

    # Normalize path if routed via /.netlify/functions/api/...
    if raw_path.startswith("/.netlify/functions/api"):
        path = raw_path[len("/.netlify/functions/api"):] or "/"
    elif raw_path.startswith("/api"):
        path = raw_path
    else:
        path = raw_path

    # Parse query string
    query_params = event.get("queryStringParameters") or {}
    query_string = urllib.parse.urlencode(query_params) if query_params else ""

    # Parse headers
    headers = event.get("headers") or {}
    environ_headers = {}
    for key, value in headers.items():
        key_upper = key.upper().replace("-", "_")
        if key_upper in ("CONTENT_TYPE", "CONTENT_LENGTH"):
            environ_headers[key_upper] = value
        else:
            environ_headers[f"HTTP_{key_upper}"] = value

    # Parse body
    raw_body = event.get("body", "") or ""
    if event.get("isBase64Encoded", False) and raw_body:
        body_bytes = base64.b64decode(raw_body)
    else:
        body_bytes = raw_body.encode("utf-8") if isinstance(raw_body, str) else raw_body

    # Build WSGI environment
    environ = {
        "REQUEST_METHOD": http_method,
        "SCRIPT_NAME": "",
        "PATH_INFO": path,
        "QUERY_STRING": query_string,
        "SERVER_NAME": "netlify",
        "SERVER_PORT": "443",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "wsgi.version": (1, 0),
        "wsgi.url_scheme": "https",
        "wsgi.input": io.BytesIO(body_bytes),
        "wsgi.errors": sys.stderr,
        "wsgi.multithread": False,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False,
        "CONTENT_LENGTH": str(len(body_bytes)),
    }
    environ.update(environ_headers)

    response_headers = []
    status_code_container = [200]

    def start_response(status, response_headers_list, exc_info=None):
        status_code = int(status.split(" ")[0])
        status_code_container[0] = status_code
        response_headers.extend(response_headers_list)

    response_iter = app(environ, start_response)
    response_body = b"".join(response_iter)

    headers_dict = {}
    for k, v in response_headers:
        headers_dict[k] = v

    # Add CORS headers
    headers_dict["Access-Control-Allow-Origin"] = "*"
    headers_dict["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    headers_dict["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"

    return {
        "statusCode": status_code_container[0],
        "headers": headers_dict,
        "body": response_body.decode("utf-8", errors="replace"),
        "isBase64Encoded": False,
    }
