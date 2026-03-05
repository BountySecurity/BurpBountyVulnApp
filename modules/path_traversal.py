"""Path Traversal endpoints - triggers 2 generic + CVE path traversal profiles."""
import os
from flask import Blueprint, request, current_app

pt_bp = Blueprint('pt', __name__, url_prefix='/pt')


@pt_bp.route('/read')
def read_file():
    """Path traversal (Linux). Triggers: PathTraversal_Linux
    Reads file based on user-supplied path without sanitization."""
    filename = request.args.get('file', 'readme.txt')
    # Intentionally vulnerable - no path sanitization
    # Normalize URL-encoded sequences that Flask already decoded
    base_dir = '/app/files/'
    filepath = os.path.join(base_dir, filename)

    # Also try to read directly if the path looks absolute or has traversal
    if filename.startswith('/') or '..' in filename:
        filepath = filename
        # Handle double-encoded sequences
        filepath = filepath.replace('%2f', '/').replace('%2F', '/')
        filepath = filepath.replace('%252f', '/').replace('%252F', '/')
        filepath = filepath.replace('%00', '')
        # Resolve the actual path
        if not filepath.startswith('/'):
            filepath = os.path.join(base_dir, filepath)

    try:
        # Try to normalize path traversal
        resolved = os.path.normpath(filepath)
        with open(resolved, 'r') as f:
            content = f.read()
        return f"""<html><body>
<h1>File Viewer</h1>
<form><input name="file" value="{filename}"><button>Read</button></form>
<pre>{content}</pre>
</body></html>"""
    except Exception as e:
        return f"""<html><body>
<h1>File Viewer</h1>
<form><input name="file" value="{filename}"><button>Read</button></form>
<p>Error: Could not read file</p>
</body></html>""", 404


@pt_bp.route('/readwin')
def read_file_win():
    """Path traversal (Windows simulation). Triggers: PathTraversal_Windows
    Returns win.ini content for Windows-style path traversal."""
    filename = request.args.get('file', 'config.txt')

    # Check if the payload looks like it's trying to access win.ini
    lower = filename.lower().replace('\\', '/').replace('%5c', '/').replace('%255c', '/')
    if 'win.ini' in lower or 'windows' in lower:
        try:
            with open(current_app.config['FAKE_WIN_INI'], 'r') as f:
                content = f.read()
            return f"<html><body><pre>{content}</pre></body></html>"
        except:
            pass

    # Also check for general path traversal to /etc/passwd
    if '..' in filename or filename.startswith('/'):
        try:
            resolved = os.path.normpath(filename if filename.startswith('/') else f'/app/files/{filename}')
            with open(resolved, 'r') as f:
                content = f.read()
            return f"<html><body><pre>{content}</pre></body></html>"
        except:
            pass

    return f"""<html><body>
<h1>Config Viewer</h1>
<form><input name="file" value="{filename}"><button>Read</button></form>
<p>File not found</p>
</body></html>""", 404


@pt_bp.route('/include')
def include_page():
    """PHP-style file inclusion. Triggers: PathTraversal_Linux (php://filter payloads)"""
    page = request.args.get('page', 'home')

    # Handle php://filter wrapper simulation
    if 'php://' in page.lower() or 'file://' in page.lower():
        # Extract the actual file path
        import re
        file_match = re.search(r'resource=(.+?)$', page)
        if file_match:
            filepath = file_match.group(1)
        else:
            filepath = page.replace('php://filter/', '').replace('file://', '')

        try:
            with open(filepath, 'r') as f:
                content = f.read()
            # If convert.base64-encode is in the filter, base64 encode
            if 'base64' in page.lower():
                import base64
                content = base64.b64encode(content.encode()).decode()
            return f"<html><body><pre>{content}</pre></body></html>"
        except:
            pass

    # Handle data:// wrapper
    if page.startswith('data:'):
        import base64
        try:
            if 'base64,' in page:
                data = page.split('base64,')[1]
                content = base64.b64decode(data).decode()
                return f"<html><body><pre>{content}</pre></body></html>"
        except:
            pass

    # Normal path traversal
    if '..' in page or page.startswith('/'):
        try:
            filepath = page if page.startswith('/') else f'/app/files/{page}'
            with open(os.path.normpath(filepath), 'r') as f:
                content = f.read()
            return f"<html><body><pre>{content}</pre></body></html>"
        except:
            pass

    pages = {
        'home': '<h1>Home</h1><p>Welcome to the application.</p>',
        'about': '<h1>About</h1><p>About page.</p>',
        'contact': '<h1>Contact</h1><p>Contact us.</p>',
    }
    content = pages.get(page, '<h1>404</h1><p>Page not found</p>')
    return f"""<html><body>
<nav><a href="?page=home">Home</a> <a href="?page=about">About</a> <a href="?page=contact">Contact</a></nav>
{content}
</body></html>"""
