"""CRLF injection endpoint - triggers 1 CRLF profile."""
from flask import Blueprint, request, make_response

crlf_bp = Blueprint('crlf', __name__, url_prefix='/crlf')


@crlf_bp.route('/set')
def set_lang():
    """CRLF injection. Triggers: CRLF
    Reflects user input into Set-Cookie header without sanitizing CRLF."""
    lang = request.args.get('lang', 'en')
    # Intentionally vulnerable - user input goes directly into header value
    # Flask/Werkzeug may sanitize this, so we build raw response
    body = f"""<html><body>
<h1>Language Settings</h1>
<p>Language set to: {lang}</p>
<a href="?lang=en">English</a> | <a href="?lang=es">Spanish</a> | <a href="?lang=fr">French</a>
</body></html>"""

    # Build response manually to allow CRLF in headers
    resp = make_response(body)
    # The cookie value includes user input without sanitization
    resp.headers['Set-Cookie'] = f'lang={lang}; Path=/'
    resp.headers['X-Custom-Lang'] = lang
    return resp


@crlf_bp.route('/set', methods=['POST'])
def set_lang_post():
    lang = request.form.get('lang', 'en')
    resp = make_response(f"<html><body><p>Language: {lang}</p></body></html>")
    resp.headers['Set-Cookie'] = f'lang={lang}; Path=/'
    resp.headers['X-Custom-Lang'] = lang
    return resp
