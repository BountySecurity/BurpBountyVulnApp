"""Collaborator-dependent endpoints.
These endpoints process values from headers/params that would trigger OOB callbacks
when Burp Collaborator is active."""
import subprocess
from flask import Blueprint, request, make_response

collab_bp = Blueprint('collab', __name__, url_prefix='/collab')


@collab_bp.route('/headers')
def header_injection():
    """X-Headers-Collaborator. Triggers: X-Headers-Collaborator
    Processes URLs/hostnames from X-* headers (DNS/HTTP lookups)."""
    # List of headers that the profile injects Collaborator payloads into
    interesting_headers = [
        'X-Forwarded-For', 'X-Host', 'X-Forwarded-Server',
        'X-Forwarded-Scheme', 'X-Original-URL', 'X-Rewrite-URL',
        'Forwarded', 'Origin', 'Referer', 'X-Forwarded-Host',
        'X-Forwarded-Proto', 'X-ProxyUser-Ip', 'X-Wap-Profile',
        'Client-IP', 'True-Client-IP', 'Cluster-Client-IP',
        'X-Custom-IP-Authorization'
    ]

    found = {}
    for header in interesting_headers:
        val = request.headers.get(header, '')
        if val:
            found[header] = val
            # Try to resolve/fetch the value (triggers Collaborator detection)
            try:
                if val.startswith('http'):
                    import requests as req_lib
                    req_lib.get(val, timeout=3, verify=False)
                else:
                    # DNS resolution
                    subprocess.run(
                        ['nslookup', val],
                        capture_output=True, timeout=3
                    )
            except:
                pass

    headers_html = ''.join(f'<li>{k}: {v}</li>' for k, v in found.items())
    return f"""<html><body>
<h1>Request Headers</h1>
<ul>{headers_html}</ul>
<p>Headers processed: {len(found)}</p>
</body></html>"""


@collab_bp.route('/headers', methods=['POST'])
def header_injection_post():
    """POST variant for header injection."""
    for header in ['X-Forwarded-For', 'X-Host', 'X-Forwarded-Host',
                   'Origin', 'Referer', 'X-Wap-Profile', 'Client-IP',
                   'True-Client-IP', 'X-Custom-IP-Authorization']:
        val = request.headers.get(header, '')
        if val:
            try:
                if val.startswith('http'):
                    import requests as req_lib
                    req_lib.get(val, timeout=3, verify=False)
                else:
                    subprocess.run(['nslookup', val], capture_output=True, timeout=3)
            except:
                pass
    return "<html><body><p>Processed</p></body></html>"


@collab_bp.route('/host')
def host_injection():
    """Host Header Injection. Triggers: Host_Header_Injection
    Processes the Host header value."""
    host = request.headers.get('Host', '')
    # Also check for GraphQL variable injection
    content_type = request.content_type or ''

    if host and host not in ('localhost', '127.0.0.1', 'localhost:8080', '0.0.0.0:8080'):
        try:
            subprocess.run(['nslookup', host.split(':')[0]], capture_output=True, timeout=3)
        except:
            pass

    return f"""<html><body>
<h1>Host Info</h1>
<p>Host: {host}</p>
<a href="http://{host}/collab/host">Self link</a>
</body></html>"""


@collab_bp.route('/forgot', methods=['GET', 'POST'])
def forgot_password():
    """Password Reset Header Injection. Triggers: Password-Reset-Headers,
    Password-Reset-Params, Password-Reset-URL
    Builds reset link using Host header (vulnerable to header injection)."""
    email = request.args.get('email', request.form.get('email', ''))
    host = request.headers.get('Host', 'localhost:8080')

    # Process custom headers that could override the host
    custom_host = (request.headers.get('X-Forwarded-Host', '') or
                   request.headers.get('X-Host', '') or
                   request.headers.get('X-Forwarded-For', '') or
                   request.headers.get('X-Original-URL', '') or
                   request.headers.get('X-Forwarded-Server', '') or
                   request.headers.get('X-Rewrite-URL', '') or
                   request.headers.get('Forwarded', '') or
                   request.headers.get('X-Custom-IP-Authorization', ''))

    if custom_host:
        host = custom_host
        # Try to resolve the custom host
        try:
            if custom_host.startswith('http'):
                import requests as req_lib
                req_lib.get(custom_host, timeout=3, verify=False)
            else:
                subprocess.run(['nslookup', custom_host.split(':')[0]], capture_output=True, timeout=3)
        except:
            pass

    if request.method == 'POST' or email:
        # Build reset link using potentially injected host
        reset_link = f"http://{host}/reset?token=abc123&email={email}"
        return f"""<html><body>
<h1>Password Reset</h1>
<p>Reset link sent to {email}</p>
<p>TESTDEMO</p>
<p>Reset URL: {reset_link}</p>
</body></html>"""

    return """<html><body>
<h1>Forgot Password</h1>
<form method="POST">
<input name="email" placeholder="Email" type="email"><br>
<button>Reset Password</button>
</form></body></html>"""
