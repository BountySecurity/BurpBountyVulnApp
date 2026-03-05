"""Passive detection trigger pages.
These pages contain content/headers/params that trigger passive Burp Bounty profiles
when the crawler visits them."""
from flask import Blueprint, request, make_response

passive_bp = Blueprint('passive', __name__, url_prefix='/passive')


@passive_bp.route('/secrets')
def secrets_page():
    """Triggers passive Secrets profiles: AWS_Access_Key_ID, Google_API_Key,
    Private_Key, Authorization_Token, etc."""
    resp = make_response("""<html><body>
<h1>Configuration Panel</h1>
<script>
// AWS Configuration
var aws_config = {
    accessKeyId: "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    region: "us-east-1"
};

// Google API
var GOOGLE_API_KEY = "AIzaSyA1234567890abcdefghijklmnopqrstuv";
var google_oauth = "ya29.a0AfH6SMA1234567890abcdefghijklmnopqrstuvwxyz";

// Stripe
var stripe_key = "sk_live_1234567890abcdefghijklmnopqrstuvwxyz";

// Private RSA Key
var ssh_key = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIBAAKCAQEA1234567890\\n-----END RSA PRIVATE KEY-----";

// Slack token
var slack_token = "xoxa-2-1234567890-1234567890-1234567890abcdef";

// Heroku
var HEROKU_API_KEY = "12345678-abcd-efgh-ijkl-1234567890ab";

// Database
var DB_USERNAME = "admin";
var DB_PASSWORD = "super_secret_password";
var SESSION_TOKEN = "abc123def456ghi789";
</script>

<div class="config">
    <p>ConsumerKey: ck_1234567890abcdef</p>
    <p>ConsumerSecret: cs_1234567890abcdef</p>
    <p>ListBucketResult: enabled</p>
    <p>ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCexample</p>
</div>
</body></html>""")
    # Add Authorization header in response to trigger passive detection
    resp.headers['X-API-Key'] = 'sk_live_1234567890abcdef'
    return resp


@passive_bp.route('/cookies')
def cookies_page():
    """Triggers passive Cookie_Security profiles: HttpOnly, Secure, SameSite."""
    resp = make_response("""<html><body>
<h1>Cookie Test</h1>
<p>This page sets insecure cookies.</p>
</body></html>""")
    # Insecure cookies - missing HttpOnly, Secure, SameSite flags
    resp.headers.add('Set-Cookie', 'session=abc123; Path=/')
    resp.headers.add('Set-Cookie', 'user=admin; Path=/')
    resp.headers.add('Set-Cookie', 'token=xyz789; Path=/')
    # No HttpOnly, no Secure, no SameSite
    return resp


@passive_bp.route('/headers')
def headers_page():
    """Triggers passive Security_Headers profiles:
    Missing Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, etc.
    Intentionally does NOT set security headers."""
    resp = make_response("""<html><body>
<h1>Headers Test</h1>
<p>This page intentionally lacks security headers.</p>
</body></html>""")
    # Explicitly do NOT set these headers to trigger passive profiles:
    # Content-Security-Policy, X-Content-Type-Options, X-Frame-Options,
    # Strict-Transport-Security, Referrer-Policy
    resp.headers['Server'] = 'Apache/2.4.41 (Ubuntu)'
    resp.headers['X-Powered-By'] = 'PHP/8.2.0'
    return resp


@passive_bp.route('/tech')
def tech_page():
    """Triggers passive Technology profiles by including tech-specific paths and headers."""
    resp = make_response("""<html><body>
<h1>Technology Stack</h1>
<link rel="stylesheet" href="/wp-content/themes/default/style.css">
<script src="/wp-includes/js/jquery.js"></script>
<script src="https://s3.amazonaws.com/bucket/script.js"></script>
<meta name="generator" content="WordPress 6.4.2">
<img src="https://example.s3.amazonaws.com/image.png">
</body></html>""")
    resp.headers['Server'] = 'nginx/1.24.0'
    resp.headers['X-Powered-By'] = 'Express'
    return resp


@passive_bp.route('/params')
def params_page():
    """Triggers passive Vuln_Parameters and Parameters profiles.
    URL contains params that match vulnerability-indicative parameter names."""
    # Collect all parameters - their presence in the request triggers passive detection
    params = dict(request.args)
    param_list = ''.join(f'<li><b>{k}</b> = {v}</li>' for k, v in params.items())

    return f"""<html><body>
<h1>Parameter Test</h1>
<ul>{param_list}</ul>

<!-- Links with interesting parameter names for crawler to follow -->
<h2>User Management</h2>
<a href="/passive/params?id=1&user=admin&account=100&email=test@test.com&profile=1&user_id=1">User Profile</a>
<a href="/passive/params?username=admin&signup=true&register=true">Registration</a>

<h2>File Operations</h2>
<a href="/passive/params?file=test.txt&path=/var/www&folder=/home&include=header.php&page=home&doc=manual.pdf">Files</a>

<h2>Search & Queries</h2>
<a href="/passive/params?q=search&search=test&keyword=hello&query=select&sort=asc&filter=active&category=1">Search</a>

<h2>Redirects & URLs</h2>
<a href="/passive/params?url=http://example.com&redirect=http://example.com&next=/home&callback=http://example.com&dest=/page&redirect_uri=http://example.com">Redirects</a>

<h2>Commands & Debug</h2>
<a href="/passive/params?cmd=test&exec=ls&command=id&debug=true&admin=false&config=default&test=1">Debug</a>

<h2>Templates</h2>
<a href="/passive/params?template=home&preview=true&view=default&content=hello">Templates</a>

<h2>Tokens & Keys</h2>
<a href="/passive/params?token=abc123&key=xyz789&api_key=test123&access=read">Auth</a>

<h2>IDs & References</h2>
<a href="/passive/params?order_id=100&user_id=1&product_id=50&ref_id=200&uuid=550e8400-e29b-41d4-a716-446655440000">IDs</a>
</body></html>"""


@passive_bp.route('/api/v1/data')
def api_passive():
    """Triggers: Api_path passive detection."""
    return '{"data": [{"id": 1, "name": "test"}], "total": 1}', 200, {'Content-Type': 'application/json'}


@passive_bp.route('/graphql')
def graphql_passive():
    """Triggers: GraphQL_Endpoint passive detection."""
    return '{"data": {"__typename": "Query"}}', 200, {'Content-Type': 'application/json'}


@passive_bp.route('/errors')
def errors_page():
    """Triggers passive error detection profiles."""
    return """<html><body>
<h1>Error Page</h1>
<p>Warning: mysql_fetch_array(): supplied argument is not a valid MySQL result resource in /var/www/html/index.php on line 42</p>
<p>Fatal error: Uncaught Exception in /var/www/html/app.php on line 100</p>
<p>Stack trace: #0 /var/www/html/app.php(100): throwError()</p>
<pre>java.lang.NullPointerException
    at com.example.MyClass.myMethod(MyClass.java:42)</pre>
</body></html>""", 500


@passive_bp.route('/info')
def info_disclosure():
    """Triggers passive Information_Disclosure profiles."""
    resp = make_response("""<html><body>
<h1>Debug Info</h1>
<!-- Server: Apache/2.4.41 (Ubuntu) -->
<!-- PHP Version: 8.2.0 -->
<!-- Database: MySQL 8.0.35 -->
<pre>
Server IP: 192.168.1.100
Internal hostname: web-prod-01.internal.corp
Document root: /var/www/html
</pre>
</body></html>""")
    resp.headers['Server'] = 'Apache/2.4.41 (Ubuntu)'
    resp.headers['X-Powered-By'] = 'PHP/8.2.0'
    resp.headers['X-Debug-Token'] = 'abc123'
    return resp
