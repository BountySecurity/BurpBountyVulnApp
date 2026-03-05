"""SSRF vulnerability endpoints - triggers 6 SSRF profiles."""
import requests as req_lib
import subprocess
from flask import Blueprint, request, make_response

ssrf_bp = Blueprint('ssrf', __name__, url_prefix='/ssrf')


@ssrf_bp.route('/fetch')
def fetch_url():
    """SSRF - fetches arbitrary URLs. Triggers: SSRF-Collaborator, OpenRedirect_SSRF,
    OpenRedirect_SSRF_Collaborator, SSRF_Collaborator_HTTP0_9, SSRF_Collaborator_HTTP1_0"""
    url = request.args.get('url', '')
    if not url:
        return """<html><body>
<h1>URL Fetcher</h1>
<form><input name="url" placeholder="Enter URL" size="50"><button>Fetch</button></form>
</body></html>"""

    try:
        resp = req_lib.get(url, timeout=10, verify=False, allow_redirects=True)
        content = resp.text[:5000]
        return f"""<html><body>
<h1>Fetched Content</h1>
<p>Status: {resp.status_code}</p>
<pre>{content}</pre>
</body></html>"""
    except Exception as e:
        # Even on error, the DNS resolution already happened (Collaborator detects this)
        return f"""<html><body>
<h1>Fetch Error</h1>
<p>Could not fetch URL: {e}</p>
</body></html>"""


@ssrf_bp.route('/fetch', methods=['POST'])
def fetch_url_post():
    url = request.form.get('url', '')
    if not url:
        return "<html><body><p>No URL provided</p></body></html>"
    try:
        resp = req_lib.get(url, timeout=10, verify=False, allow_redirects=True)
        return f"<html><body><pre>{resp.text[:5000]}</pre></body></html>"
    except Exception as e:
        return f"<html><body><p>Error: {e}</p></body></html>"


@ssrf_bp.route('/proxy')
def proxy():
    """SSRF proxy endpoint. Triggers: SSRF-Collaborator"""
    target = request.args.get('target', '')
    if not target:
        return """<html><body>
<h1>Proxy Service</h1>
<form><input name="target" size="50"><button>Proxy</button></form>
</body></html>"""
    try:
        resp = req_lib.get(target, timeout=10, verify=False)
        proxy_resp = make_response(resp.content)
        proxy_resp.headers['Content-Type'] = resp.headers.get('Content-Type', 'text/html')
        return proxy_resp
    except Exception as e:
        return f"<html><body><p>Proxy error: {e}</p></body></html>"


@ssrf_bp.route('/scheme')
def scheme_ssrf():
    """SSRF with various URL schemes. Triggers: SSRF-URLScheme, SSRF-Collaborator
    Handles file://, dict://, gopher://, etc."""
    url = request.args.get('url', '')
    if not url:
        return """<html><body>
<h1>Resource Loader</h1>
<form><input name="url" size="50"><button>Load</button></form>
</body></html>"""

    # Handle file:// scheme directly
    if url.startswith('file://'):
        filepath = url[7:]  # Remove file://
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            return f"<html><body><pre>{content}</pre></body></html>"
        except Exception as e:
            return f"<html><body><p>Error: {e}</p></body></html>"

    # For other schemes, try curl (supports dict://, gopher://, etc.)
    try:
        result = subprocess.run(
            ['curl', '-s', '-m', '10', url],
            capture_output=True, text=True, timeout=15
        )
        return f"<html><body><pre>{result.stdout[:5000]}</pre></body></html>"
    except Exception as e:
        return f"<html><body><p>Error: {e}</p></body></html>"


@ssrf_bp.route('/img')
def img_proxy():
    """Image proxy SSRF. Triggers: OpenRedirect_SSRF_Collaborator"""
    src = request.args.get('src', '')
    if not src:
        return "<html><body><p>No image source</p></body></html>"
    try:
        resp = req_lib.get(src, timeout=10, verify=False)
        proxy_resp = make_response(resp.content)
        proxy_resp.headers['Content-Type'] = resp.headers.get('Content-Type', 'image/png')
        return proxy_resp
    except:
        return "<html><body><p>Image not found</p></body></html>", 404
