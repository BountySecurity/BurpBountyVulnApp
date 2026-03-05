"""SSTI (Server-Side Template Injection) endpoints - triggers 1 SSTI profile."""
import re
from flask import Blueprint, request, render_template_string

ssti_bp = Blueprint('ssti', __name__, url_prefix='/ssti')


def multi_engine_render(template):
    """Simulate multiple template engines by converting various syntaxes to Jinja2.
    This makes payloads like ${7948+7948}, #{7948+7948}, <%=7948*2%>, @(7948+7948)
    all work in addition to native Jinja2 {{...}} syntax."""
    processed = template
    # Convert ${expr} to {{expr}} (Velocity/FreeMarker/JSP EL)
    processed = re.sub(r'\$\{([^}]+)\}', r'{{\1}}', processed)
    # Convert #{expr} to {{expr}} (Ruby ERB / Pebble / EL)
    processed = re.sub(r'#\{([^}]+)\}', r'{{\1}}', processed)
    # Convert <%=expr%> to {{expr}} (ERB/ASP)
    processed = re.sub(r'<%=(.+?)%>', r'{{\1}}', processed)
    # Convert @(expr) to {{expr}} (Razor)
    processed = re.sub(r'@\(([^)]+)\)', r'{{\1}}', processed)
    return processed


def render_with_multi_engine(template):
    """Try rendering with multiple template syntaxes."""
    processed = multi_engine_render(template)
    try:
        return render_template_string(processed)
    except:
        # Fallback: try original template
        try:
            return render_template_string(template)
        except Exception as e:
            return f"Error: {e}"


@ssti_bp.route('/render')
def render_template_view():
    """SSTI endpoint. Triggers: SSTI
    Profile payloads: ${7948+7948}1337, #{7948+7948}1337, {{7949*2}}1337, etc.
    Expected grep: 158961337 (7948+7948=15896, or 7948*2=15896)"""
    template = request.args.get('template', 'Hello')
    result = render_with_multi_engine(template)
    return f"""<html><body>
<h1>Template Preview</h1>
<form><input name="template" value="" size="50"><button>Render</button></form>
<div class="output">{result}</div>
</body></html>"""


@ssti_bp.route('/render', methods=['POST'])
def render_template_post():
    template = request.form.get('template', 'Hello')
    result = render_with_multi_engine(template)
    return f"<html><body><div>{result}</div></body></html>"


@ssti_bp.route('/preview')
def preview():
    """Alternative SSTI endpoint. Triggers: SSTI"""
    content = request.args.get('content', 'Welcome')
    result = render_with_multi_engine(content)
    return f"<html><body><h1>Preview</h1><div>{result}</div></body></html>"
