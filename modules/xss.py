"""XSS vulnerability endpoints - triggers 14 XSS profiles."""
from flask import Blueprint, request, make_response

xss_bp = Blueprint('xss', __name__, url_prefix='/xss')


@xss_bp.route('/reflect')
def reflect():
    """Reflected XSS - reflects input in body. Triggers: XSS, XSS_GETPOST, XSS_URLEncode, XSS_HtmlUrlEncode"""
    q = request.args.get('q', '')
    return f"""<html><body>
<h1>Search Results</h1>
<p>You searched for: {q}</p>
<form method="GET"><input name="q" value="{q}"><button>Search</button></form>
</body></html>"""


@xss_bp.route('/reflect', methods=['POST'])
def reflect_post():
    """POST variant for XSS_GETPOST"""
    q = request.form.get('q', '')
    return f"""<html><body>
<h1>Search Results</h1>
<p>You searched for: {q}</p>
<form method="POST"><input name="q" value="{q}"><button>Search</button></form>
</body></html>"""


@xss_bp.route('/attribute')
def attribute():
    """XSS in HTML attribute context. Triggers: XSS_HTML_Attribute_Context"""
    name = request.args.get('name', '')
    return f"""<html><body>
<h1>Profile</h1>
<input type="text" name="user" value="{name}">
<a href="{name}">Link</a>
<img src="{name}" alt="avatar">
<div data="{name}">Content</div>
</body></html>"""


@xss_bp.route('/comment')
def comment():
    """XSS in HTML comment context. Triggers: XSS_HTML_Comment_Context"""
    data = request.args.get('data', '')
    return f"""<html><body>
<h1>Page</h1>
<!-- Debug info: {data} -->
<!-- User input: {data} -->
<p>Welcome to the page</p>
</body></html>"""


@xss_bp.route('/tag')
def tag():
    """XSS in HTML tag context. Triggers: XSS_HTML_Tag_Context"""
    inp = request.args.get('input', '')
    return f"""<html><body>
<h1>Content</h1>
<div>{inp}</div>
<p>More content after: {inp}</p>
</body></html>"""


@xss_bp.route('/js')
def js_context():
    """XSS in JavaScript context. Triggers: XSS_JavaScript_Context"""
    value = request.args.get('value', '')
    return f"""<html><body>
<h1>Dashboard</h1>
<script>
var userData = "{value}";
var config = {{ name: "{value}" }};
console.log(userData);
</script>
<p>Dashboard loaded</p>
</body></html>"""


@xss_bp.route('/url')
def url_context():
    """XSS in URL context. Triggers: XSS_URL_Context"""
    link = request.args.get('link', '')
    return f"""<html><body>
<h1>Links</h1>
<a href="{link}">Visit Link</a>
<img src="{link}">
<form action="{link}"><button>Go</button></form>
<iframe src="{link}"></iframe>
</body></html>"""


@xss_bp.route('/dom')
def dom_context():
    """XSS in DOM context. Triggers: XSS_DOM_Context"""
    msg = request.args.get('msg', '')
    return f"""<html><body>
<h1>Messages</h1>
<div id="output"></div>
<script>
var msg = "{msg}";
document.getElementById("output").innerHTML = msg;
document.write("<p>" + msg + "</p>");
var x = location.hash;
eval("var data = '" + msg + "'");
</script>
</body></html>"""


@xss_bp.route('/discover')
def discover():
    """XSS parameter discovery. Triggers: Test_XSS_discover
    Has many common param names that the profile tests."""
    params = {}
    for key in ['page', 'search', 'q', 'lang', 'keyword', 'name', 'redirect',
                'view', 'topic', 'title', 'type', 'comment', 'url', 'next',
                'data', 'input', 'text', 'query', 'message', 'content',
                'value', 'id', 'ref', 'category', 'sort', 'filter']:
        params[key] = request.args.get(key, '')

    parts = []
    for k, v in params.items():
        if v:
            parts.append(f'<div class="param"><b>{k}</b>: {v}</div>')

    return f"""<html><body>
<h1>Parameter Test Page</h1>
{''.join(parts)}
<form method="GET">
{''.join(f'<input name="{k}" value="{v}" placeholder="{k}">' for k, v in params.items())}
<button>Submit</button>
</form>
</body></html>"""


@xss_bp.route('/blind')
def blind_xss():
    """Blind XSS - stores input and reflects in admin page. Triggers: Blind_XSS"""
    feedback = request.args.get('feedback', '')
    # Simulate storing and reflecting without sanitization
    return f"""<html><body>
<h1>Feedback Received</h1>
<p>Thank you for your feedback.</p>
<!-- Admin panel below simulates stored XSS rendering -->
<div style="display:none" id="admin-review">{feedback}</div>
<script>
// Simulating admin panel rendering the feedback
document.getElementById('admin-review').style.display = 'block';
</script>
</body></html>"""


@xss_bp.route('/blind', methods=['POST'])
def blind_xss_post():
    feedback = request.form.get('feedback', '')
    return f"""<html><body>
<h1>Feedback Stored</h1>
<div id="admin-review">{feedback}</div>
</body></html>"""


@xss_bp.route('/encoded')
def encoded():
    """XSS with encoded payloads. Triggers: XSS_URLEncode, XSS_HtmlUrlEncode"""
    q = request.args.get('q', '')
    return f"""<html><body>
<h1>Search</h1>
<p>Results for: {q}</p>
<input value="{q}">
</body></html>"""
