"""RCE vulnerability endpoints - triggers 13 RCE profiles."""
import subprocess
import os
from flask import Blueprint, request, make_response

rce_bp = Blueprint('rce', __name__, url_prefix='/rce')


@rce_bp.route('/ping')
def ping():
    """Command injection via ping. Triggers: RCE_Linux, RCE_Windows, Echo_RCE, Expect_RCE"""
    host = request.args.get('host', '127.0.0.1')
    try:
        # Intentionally vulnerable - passes user input directly to shell
        result = subprocess.run(
            f"ping -c 1 {host}",
            shell=True, capture_output=True, text=True, timeout=30
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        output = "Command timed out"
    except Exception as e:
        output = str(e)
    return f"""<html><body>
<h1>Network Diagnostic</h1>
<form><input name="host" value="{host}" placeholder="Host"><button>Ping</button></form>
<pre>{output}</pre>
</body></html>"""


@rce_bp.route('/ping', methods=['POST'])
def ping_post():
    """POST variant for RCE profiles that test POST parameters."""
    host = request.form.get('host', '127.0.0.1')
    try:
        result = subprocess.run(
            f"ping -c 1 {host}",
            shell=True, capture_output=True, text=True, timeout=30
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        output = "Command timed out"
    except Exception as e:
        output = str(e)
    return f"<html><body><h1>Ping Result</h1><pre>{output}</pre></body></html>"


@rce_bp.route('/eval')
def eval_code():
    """PHP-style eval RCE. Triggers: PHP_RCE"""
    code = request.args.get('code', '')
    try:
        # Simulate PHP eval - actually evaluate simple expressions
        result = eval(code)
        # If someone sends phpinfo() equivalent, return PHP-like info
        if 'phpinfo' in code.lower() or 'php' in code.lower():
            return f"""<html><head><title>phpinfo()</title></head><body>
<h1>PHP Version 8.2.0</h1>
<table>
<tr><td>Build Date</td><td>Jan 1 2024 00:00:00</td></tr>
<tr><td>System</td><td>Linux vulnapp 5.15.0</td></tr>
<tr><td>Server API</td><td>Apache 2.0 Handler</td></tr>
</table></body></html>"""
        return f"<html><body><h1>Result</h1><pre>{result}</pre></body></html>"
    except:
        return f"""<html><body>
<h1>PHP Info</h1>
<p>Build Date: Jan 1 2024</p>
<p>PHP Version 8.2.0</p>
<pre>{code}</pre>
</body></html>"""


@rce_bp.route('/echo')
def echo_rce():
    """Echo-based RCE. Triggers: Echo_RCE"""
    inp = request.args.get('input', '')
    try:
        result = subprocess.run(
            f"echo {inp}",
            shell=True, capture_output=True, text=True, timeout=10
        )
        output = result.stdout + result.stderr
    except Exception as e:
        output = str(e)
    return f"<html><body><h1>Echo</h1><pre>{output}</pre></body></html>"


@rce_bp.route('/expect')
def expect_rce():
    """Expect-based RCE. Triggers: Expect_RCE"""
    cmd = request.args.get('cmd', 'id')
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=10
        )
        output = result.stdout + result.stderr
    except Exception as e:
        output = str(e)
    return f"<html><body><h1>Command Output</h1><pre>{output}</pre></body></html>"


@rce_bp.route('/blind')
def blind_rce():
    """Blind RCE - no output returned. Triggers: Blind_RCE_Linux, Blind_RCE_Windows
    Executes commands but doesn't show output (OOB detection via Collaborator)."""
    inp = request.args.get('input', '')
    try:
        # Execute in background - no output returned to user
        subprocess.Popen(
            f"echo {inp}",
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except:
        pass
    return """<html><body>
<h1>Processing</h1>
<p>Your input has been processed.</p>
<form><input name="input" placeholder="Input"><button>Submit</button></form>
</body></html>"""


@rce_bp.route('/blind', methods=['POST'])
def blind_rce_post():
    """POST variant for Blind RCE."""
    inp = request.form.get('input', '')
    try:
        subprocess.Popen(
            f"echo {inp}",
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except:
        pass
    return "<html><body><h1>Processed</h1><p>Input received.</p></body></html>"


@rce_bp.route('/log4j')
def log4j():
    """Log4j simulation. Triggers: CVE-2021-44228_RCE_Log4j*
    Logs user input - in a real Log4j app this would trigger JNDI lookup.
    The Collaborator-based detection will work if Burp sends the payload
    and the server processes it (which it does via echo command)."""
    search = request.args.get('search', '')
    # Simulate logging user input (real Log4j would process ${jndi:...})
    # We execute the input through shell to trigger DNS lookups for Collaborator
    try:
        subprocess.Popen(
            f"echo 'Log: {search}' > /dev/null",
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except:
        pass
    return f"""<html><body>
<h1>Search</h1>
<form><input name="search" value="{search}"><button>Search</button></form>
<p>No results for your query.</p>
</body></html>"""


@rce_bp.route('/log4j', methods=['POST'])
def log4j_post():
    search = request.form.get('search', '')
    try:
        subprocess.Popen(
            f"echo 'Log: {search}' > /dev/null",
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except:
        pass
    return f"<html><body><h1>Logged</h1><p>Query: {search}</p></body></html>"


@rce_bp.route('/react2shell', methods=['GET', 'POST'])
def react2shell():
    """React2Shell CVE-2025-55182. Triggers: CVE-2025-55182_React2Shell_RCE*
    Checks for Next-Action header and returns expected patterns."""
    next_action = request.headers.get('Next-Action', '')
    if next_action:
        # If Next-Action header is present, simulate vulnerable Next.js response
        body = request.get_data(as_text=True)
        resp = make_response("")
        resp.headers['x-action-redirect'] = '/login?a=982013569'
        resp.status_code = 303
        # Also try to execute any command in the body
        if body:
            try:
                subprocess.Popen(
                    f"echo '{body}' > /dev/null",
                    shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            except:
                pass
        return resp
    return """<html><body>
<h1>Next.js App</h1>
<form method="POST" action="/rce/react2shell">
<input name="data"><button>Submit</button>
</form></body></html>"""
