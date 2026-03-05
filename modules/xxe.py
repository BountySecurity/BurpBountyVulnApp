"""XXE vulnerability endpoints - triggers 3 XXE profiles."""
from flask import Blueprint, request, make_response
from lxml import etree

xxe_bp = Blueprint('xxe', __name__, url_prefix='/xxe')


@xxe_bp.route('/parse', methods=['GET', 'POST'])
def parse_xml():
    """XXE parser. Triggers: XXE_Linux, XXE_Windows, Blind_XXE
    Parses XML with external entities enabled."""
    if request.method == 'GET':
        return """<html><body>
<h1>XML Parser</h1>
<form method="POST">
<textarea name="xml" rows="10" cols="60">&lt;?xml version="1.0"?&gt;
&lt;data&gt;
  &lt;name&gt;test&lt;/name&gt;
&lt;/data&gt;</textarea><br>
<button>Parse XML</button>
</form></body></html>"""

    xml_data = request.data or request.form.get('xml', '').encode()
    if not xml_data:
        return "<html><body><p>No XML provided</p></body></html>", 400

    try:
        # Intentionally vulnerable - external entities enabled
        parser = etree.XMLParser(
            resolve_entities=True,
            load_dtd=True,
            no_network=False,  # Allow network access for OOB XXE
            dtd_validation=False
        )
        doc = etree.fromstring(xml_data, parser=parser)
        result = etree.tostring(doc, pretty_print=True, encoding='unicode')
        # Also extract text content which may contain file contents
        text_content = doc.text or ''
        for elem in doc.iter():
            if elem.text:
                text_content += elem.text + '\n'

        return f"""<html><body>
<h1>Parsed XML</h1>
<pre>{result}</pre>
<h2>Extracted Data</h2>
<pre>{text_content}</pre>
</body></html>"""
    except Exception as e:
        return f"""<html><body>
<h1>XML Parse Error</h1>
<pre>{e}</pre>
</body></html>""", 500


@xxe_bp.route('/upload', methods=['GET', 'POST'])
def upload_xml():
    """XXE via file upload. Triggers: XXE_Linux, Blind_XXE"""
    if request.method == 'GET':
        return """<html><body>
<h1>XML File Upload</h1>
<form method="POST" enctype="multipart/form-data">
<input type="file" name="xmlfile" accept=".xml"><br>
<button>Upload & Parse</button>
</form></body></html>"""

    f = request.files.get('xmlfile')
    if not f:
        # Also accept raw XML body
        xml_data = request.data
    else:
        xml_data = f.read()

    if not xml_data:
        return "<html><body><p>No XML</p></body></html>", 400

    try:
        parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
        doc = etree.fromstring(xml_data, parser=parser)
        result = etree.tostring(doc, pretty_print=True, encoding='unicode')
        return f"<html><body><pre>{result}</pre></body></html>"
    except Exception as e:
        return f"<html><body><p>Error: {e}</p></body></html>", 500


@xxe_bp.route('/soap', methods=['GET', 'POST'])
def soap_endpoint():
    """SOAP endpoint vulnerable to XXE. Triggers: XXE_Linux, Blind_XXE"""
    if request.method == 'GET':
        return """<html><body>
<h1>SOAP Service</h1>
<p>POST XML SOAP envelope to this endpoint.</p>
<form method="POST">
<textarea name="xml" rows="10" cols="60">&lt;?xml version="1.0"?&gt;
&lt;soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"&gt;
  &lt;soap:Body&gt;
    &lt;GetUser&gt;&lt;id&gt;1&lt;/id&gt;&lt;/GetUser&gt;
  &lt;/soap:Body&gt;
&lt;/soap:Envelope&gt;</textarea><br>
<button>Send SOAP Request</button>
</form></body></html>"""

    xml_data = request.data or request.form.get('xml', '').encode()
    if not xml_data:
        return "", 400

    try:
        parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
        doc = etree.fromstring(xml_data, parser=parser)

        # Extract text from all elements
        texts = []
        for elem in doc.iter():
            if elem.text and elem.text.strip():
                texts.append(elem.text.strip())

        resp_xml = f"""<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUserResponse>
      <result>{'|'.join(texts)}</result>
      <status>OK</status>
    </GetUserResponse>
  </soap:Body>
</soap:Envelope>"""
        resp = make_response(resp_xml)
        resp.headers['Content-Type'] = 'text/xml'
        return resp
    except Exception as e:
        error_xml = f"""<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><soap:Fault><faultstring>{e}</faultstring></soap:Fault></soap:Body>
</soap:Envelope>"""
        resp = make_response(error_xml, 500)
        resp.headers['Content-Type'] = 'text/xml'
        return resp
