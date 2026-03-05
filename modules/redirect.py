"""Open Redirect endpoints - triggers 3 Open Redirect profiles."""
from flask import Blueprint, request, redirect, make_response

redirect_bp = Blueprint('redirect', __name__, url_prefix='/redirect')


@redirect_bp.route('/goto')
def goto():
    """Open redirect. Triggers: OpenRedirect, Openredirect_to_XSS, OpenRedirect_to_Account_Takeover"""
    url = request.args.get('url', '/')
    # Intentionally vulnerable - redirects to any URL
    return redirect(url)


@redirect_bp.route('/login')
def login_redirect():
    """Login redirect. Triggers: OpenRedirect, OpenRedirect-ParameterPollution"""
    next_url = request.args.get('next', request.args.get('redirect', request.args.get('url',
        request.args.get('return_url', request.args.get('callback',
        request.args.get('dest', request.args.get('rurl',
        request.args.get('target', '/'))))))))

    if request.method == 'GET':
        # Show login form with redirect parameter
        return f"""<html><body>
<h1>Login</h1>
<form method="POST" action="{next_url}">
<input name="username" placeholder="Username"><br>
<input name="password" type="password"><br>
<button>Login</button>
</form>
<p>After login you'll be redirected to: {next_url}</p>
</body></html>"""


@redirect_bp.route('/login', methods=['POST'])
def login_redirect_post():
    next_url = request.args.get('next', request.args.get('url', '/'))
    return redirect(next_url)


@redirect_bp.route('/out')
def outbound():
    """Outbound redirect. Triggers: OpenRedirect-ParameterPollution_Path"""
    url = request.args.get('url', '/')
    # Uses Location header directly
    resp = make_response('', 302)
    resp.headers['Location'] = url
    return resp


@redirect_bp.route('/out/<path:target>')
def outbound_path(target):
    """Path-based redirect. Triggers: OpenRedirect-ParameterPollution_Path"""
    resp = make_response('', 302)
    resp.headers['Location'] = target
    return resp


@redirect_bp.route('/pp')
def param_pollution():
    """Parameter pollution redirect. Triggers: OpenRedirect-ParameterPollution"""
    # Check all common redirect parameter names
    redirect_params = ['return_url', 'next', 'url', 'redirect', 'redirect_uri',
                       'redir', 'callback', 'dest', 'destination', 'go',
                       'target', 'rurl', 'out', 'view', 'to', 'ref', 'site']
    for param in redirect_params:
        val = request.args.get(param)
        if val and (val.startswith('http') or val.startswith('//')):
            return redirect(val)

    return """<html><body>
<h1>Page</h1>
<p>Normal content</p>
<a href="/redirect/pp?return_url=/">Home</a>
</body></html>"""


@redirect_bp.route('/meta')
def meta_redirect():
    """Meta refresh redirect. Triggers: OpenRedirect (meta refresh grep patterns)"""
    url = request.args.get('url', '/')
    return f"""<html>
<head><meta http-equiv="refresh" content="0;url={url}"></head>
<body><p>Redirecting to {url}...</p>
<script>location.replace("{url}");</script>
</body></html>"""
