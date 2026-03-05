"""CVE-specific vulnerability endpoints - triggers 42 CVE profiles."""
import os
import subprocess
from flask import Blueprint, request, make_response

cves_bp = Blueprint('cves', __name__)

# ============================================================================
# JIRA CVEs
# ============================================================================

@cves_bp.route('/jira/dashboard')
@cves_bp.route('/secure/Dashboard.jspa')
def jira_dashboard():
    """Jira dashboard. Triggers: Jira_Request passive detection."""
    return """<html><body><h1>Jira Dashboard</h1>
<p>System Dashboard</p></body></html>"""


@cves_bp.route('/jira/plugins/servlet/oauth/users/icon-uri')
@cves_bp.route('/plugins/servlet/oauth/users/icon-uri')
def cve_2017_9506():
    """CVE-2017-9506 Jira SSRF. Fetches consumerUri parameter."""
    uri = request.args.get('consumerUri', '')
    if uri:
        try:
            import requests as req_lib
            resp = req_lib.get(uri, timeout=10, verify=False)
            return resp.text[:5000]
        except:
            pass
    return "<html><body><p>OAuth icon</p></body></html>"


@cves_bp.route('/jira/rest/api/latest/groupuserpicker')
@cves_bp.route('/rest/api/latest/groupuserpicker')
def cve_2019_8449():
    """CVE-2019-8449 Jira user/group info disclosure."""
    query = request.args.get('query', '')
    return make_json_response('{"users":{"users":[{"name":"admin","key":"admin","html":"admin","displayName":"Admin User"}],"total":1,"header":"Showing 1 of 1 matching users"},"groups":{"total":2,"header":"Showing 2 groups","groups":[{"name":"jira-administrators","html":"jira-administrators"},{"name":"jira-users","html":"jira-users"}]}}')


@cves_bp.route('/jira/secure/QueryComponent!Default.jspa')
@cves_bp.route('/secure/QueryComponent!Default.jspa')
def cve_2020_14179():
    """CVE-2020-14179 Jira information disclosure."""
    return make_json_response('{"searchers":[{"id":"com.atlassian.jira.plugin.system.search:searcher-text","name":"Text","key":"text"}],"groups":[{"id":"com.atlassian.jira.plugin.system.search:searcher-group","name":"Group"}]}')


@cves_bp.route('/jira/secure/ViewUserHover.jspa')
@cves_bp.route('/secure/ViewUserHover.jspa')
def cve_2020_14181():
    """CVE-2020-14181 Jira user enumeration."""
    user = request.args.get('name', 'nonexistent')
    # Returns "User does not exist" for non-existent users
    return f"""<html><body><p>User does not exist</p></body></html>"""


@cves_bp.route('/jira/rest/api/2/dashboard')
@cves_bp.route('/rest/api/2/dashboard')
def jira_dashboard_api():
    """Jira unauthenticated dashboard info."""
    return make_json_response('{"startAt":0,"maxResults":20,"total":1,"dashboards":[{"id":"10000","name":"System Dashboard","self":"http://localhost/rest/api/2/dashboard/10000"}]}')


@cves_bp.route('/jira/rest/api/2/user/picker')
@cves_bp.route('/rest/api/2/user/picker')
def jira_user_picker():
    """Jira unauthenticated user picker."""
    return make_json_response('{"users":[{"name":"admin","key":"admin","html":"admin","displayName":"Admin"}],"total":1,"header":"Showing 1 users"}')


@cves_bp.route('/jira/s/<path:subpath>')
@cves_bp.route('/s/<path:subpath>')
def cve_2021_26086(subpath):
    """CVE-2021-26086 Jira LFI / CVE-2019-8442."""
    lower = subpath.lower()
    if 'meta-inf' in lower or 'web-inf' in lower:
        if 'pom.xml' in lower:
            return """<?xml version="1.0"?>
<project><groupId>com.atlassian.jira</groupId><artifactId>jira-webapp</artifactId></project>"""
        if 'web.xml' in lower:
            return """<?xml version="1.0"?>
<web-app><display-name>Confluence</display-name></web-app>"""
    return "<html><body><p>Not found</p></body></html>", 404


# ============================================================================
# CONFLUENCE CVEs
# ============================================================================

@cves_bp.route('/confluence/')
def confluence_index():
    return """<html><body><h1>Confluence</h1><p>Welcome to Confluence.</p></body></html>"""


@cves_bp.route('/confluence/<path:subpath>')
def cve_2022_26134(subpath):
    """CVE-2022-26134 Confluence OGNL RCE."""
    # If the path contains encoded OGNL expression, execute command
    decoded = request.full_path
    if '$' in decoded or '%24' in decoded:
        try:
            result = subprocess.run(
                'id', shell=True, capture_output=True, text=True, timeout=5
            )
            resp = make_response(result.stdout)
            resp.headers['X-Cmd-Response'] = result.stdout.strip()
            return resp
        except:
            pass
    return "<html><body><p>Confluence page</p></body></html>"


# ============================================================================
# GRAFANA CVEs
# ============================================================================

@cves_bp.route('/grafana/')
def grafana_index():
    return """<html><body><title>Grafana</title>
<div class="main-view">
<div>your home dashboard</div>
<div>LoadingGrafana</div>
</div></body></html>"""


@cves_bp.route('/grafana/public/plugins/<path:plugin>')
def cve_2021_43798(plugin):
    """CVE-2021-43798 Grafana LFI via plugin paths.
    Flask normalizes .. before routing. The profile sends
    /public/plugins/{plugin}/../../../../etc/passwd
    which Flask resolves. We detect known plugin names in the path."""
    known_plugins = ['alertlist', 'annolist', 'barchart', 'bargauge', 'candlestick',
                     'canvas', 'cloudwatch', 'dashlist', 'elasticsearch', 'flamegraph',
                     'gauge', 'geomap', 'gettingstarted', 'grafana-azure-monitor',
                     'grafana-clock-panel', 'graph', 'graphite', 'heatmap', 'histogram',
                     'influxdb', 'jaeger', 'logs', 'loki', 'mssql', 'mysql', 'news',
                     'nodeGraph', 'opentsdb', 'piechart', 'pluginlist', 'postgres',
                     'prometheus', 'stackdriver', 'stat', 'state-timeline',
                     'status-history', 'table', 'table-old', 'tempo', 'testdata',
                     'text', 'timeseries', 'welcome', 'xychart', 'zipkin']
    for p in known_plugins:
        if p in plugin:
            try:
                with open('/etc/passwd', 'r') as f:
                    return f.read()
            except:
                return "root:x:0:0:root:/root:/bin/bash\n"
    return "Plugin not found", 404


@cves_bp.route('/grafana/avatar/<path:subpath>')
def cve_2020_13379(subpath):
    """CVE-2020-13379 Grafana SSRF via avatar redirect."""
    if subpath:
        try:
            import requests as req_lib
            req_lib.get(f'http://{subpath}', timeout=5, verify=False)
        except:
            pass
    return "", 302, {'Location': f'/{subpath}'}


@cves_bp.route('/grafana/login')
@cves_bp.route('/grafana/d/<path:subpath>')
def cve_2022_32276(subpath=''):
    """CVE-2022-32276 Grafana URL path confusion."""
    return """<html><body>
<title>Grafana</title>
<div>your home dashboard</div>
<div>LoadingGrafana</div>
</body></html>"""


# ============================================================================
# FORTIOS / PULSE SECURE / CITRIX CVEs
# ============================================================================

@cves_bp.route('/fortios/remote/login')
@cves_bp.route('/cve/fortios/remote/login')
def fortios_login():
    return """<html><body><h1>FortiOS</h1><p>SSL VPN Login</p></body></html>"""


@cves_bp.route('/remote/fgt_lang')
def cve_2018_13379():
    """CVE-2018-13379 FortiOS path traversal."""
    lang = request.args.get('lang', '')
    if '..' in lang:
        return """var fgt_lang = |\nsslvpn_session_data|"""
    return "Language not found", 404


@cves_bp.route('/dana-na/<path:subpath>')
def cve_2019_11510(subpath):
    """CVE-2019-11510 Pulse Secure arbitrary file read."""
    if '..' in request.full_path:
        try:
            with open('/etc/passwd', 'r') as f:
                return f.read()
        except:
            return "root:x:0:0:root:/root:/bin/bash\n"
    return "Not found", 404


@cves_bp.route('/vpn/<path:subpath>')
@cves_bp.route('/vpns/<path:subpath>')
def cve_2019_19781(subpath=''):
    """CVE-2019-19781 Citrix ADC path traversal."""
    if '..' in request.full_path or 'smb.conf' in subpath:
        return """[global]
workgroup = WORKGROUP
server string = Samba Server
security = user"""
    return "Not found", 404


@cves_bp.route('/cve/citrix/')
def citrix_index():
    return """<html><body><h1>Citrix</h1></body></html>"""


@cves_bp.route('/oauth/idp/logout')
def cve_2023_24488():
    """CVE-2023-24488 Citrix XSS."""
    redirect_uri = request.args.get('post_logout_redirect_uri', '')
    # Reflect the parameter in the response (including headers for CRLF)
    resp = make_response(f"""<html><body>
<h1>Logged Out</h1>
<p>Redirect: {redirect_uri}</p>
</body></html>""")
    return resp


@cves_bp.route('/jsp/help-sb-download.jsp')
def cve_2020_8209():
    """CVE-2020-8209 Citrix XenMobile LFI."""
    filename = request.args.get('sbFileName', '')
    if '..' in filename:
        try:
            with open('/etc/passwd', 'r') as f:
                return f.read()
        except:
            return "root:x:0:0:root:/root:/bin/bash\n"
    return "Not found", 404


@cves_bp.route('/citrix/sharefile/<path:subpath>')
def cve_2020_8982(subpath=''):
    """CVE-2020-8982 Citrix ShareFile LFI."""
    if '..' in request.full_path or 'win.ini' in request.full_path.lower():
        return """[fonts]
; for 16-bit app support
[extensions]
[mci extensions]
[files]"""
    return "Not found", 404


# ============================================================================
# F5 BIGIP CVEs
# ============================================================================

@cves_bp.route('/cve/f5/')
def f5_index():
    return """<html><body><h1>F5 BIG-IP</h1></body></html>"""


@cves_bp.route('/tmui/login.jsp/<path:subpath>')
@cves_bp.route('/tmui/<path:subpath>')
def cve_2020_5902(subpath=''):
    """CVE-2020-5902 F5 BigIP RCE/LFI."""
    if 'fileRead' in subpath:
        filename = request.args.get('fileName', '')
        if filename:
            try:
                with open(filename, 'r') as f:
                    return f.read()
            except:
                return "root:x:0:0:root:/root:/bin/bash\n"
    return """<html><body><h1>BIG-IP</h1><p>Login</p></body></html>"""


@cves_bp.route('/mgmt/tm/util/bash', methods=['POST'])
def cve_2022_1388():
    """CVE-2022-1388 F5 Big-IP RCE."""
    auth = request.headers.get('Authorization', '')
    if 'YWRtaW46' in auth:  # base64 of admin:
        try:
            body = request.get_json(force=True) or {}
            cmd = body.get('utilCmdArgs', '-c id')
            result = subprocess.run(
                cmd.replace('-c ', ''), shell=True,
                capture_output=True, text=True, timeout=10
            )
            return make_json_response(f'{{"commandResult":"uid=0(root) gid=0(root) groups=0(root)\\n{result.stdout}"}}')
        except:
            return make_json_response('{"commandResult":"uid=0(root) gid=0(root) groups=0(root)"}')
    return "Unauthorized", 401


# ============================================================================
# SPRING CVEs
# ============================================================================

@cves_bp.route('/cve/spring/')
def spring_index():
    return """<html><body><h1>Spring Application</h1></body></html>"""


@cves_bp.route('/static/<path:subpath>')
def cve_2018_1271(subpath=''):
    """CVE-2018-1271 Spring MVC directory traversal."""
    if '..' in request.full_path or '%255c' in request.full_path:
        return """[fonts]
; for 16-bit app support
[extensions]"""
    return "Not found", 404


@cves_bp.route('/cve/spring/<path:subpath>')
def spring_cloud_cves(subpath=''):
    """CVE-2019-3799, CVE-2020-5410, CVE-2020-5412 Spring Cloud."""
    full = request.full_path
    if '..' in full or '%252f' in full.lower() or '%2f' in full.lower():
        try:
            with open('/etc/passwd', 'r') as f:
                return f.read()
        except:
            return "root:x:0:0:root:/root:/bin/bash\n"
    if 'proxy.stream' in full:
        origin = request.args.get('origin', '')
        if origin:
            try:
                import requests as req_lib
                req_lib.get(origin, timeout=5, verify=False)
            except:
                pass
    return "<html><body>Spring Cloud Config</body></html>"


# ============================================================================
# APACHE CVEs
# ============================================================================

@cves_bp.route('/cve/apache/')
@cves_bp.route('/cve/apache/<path:subpath>')
def cve_2021_40438(subpath=''):
    """CVE-2021-40438 Apache mod_proxy SSRF."""
    full = request.full_path
    if 'unix:' in full.lower() or '%7c' in full or '|' in full:
        # Extract the target URL after the pipe
        parts = full.split('|')
        if len(parts) > 1:
            target = parts[-1].rstrip('?')
            try:
                import requests as req_lib
                req_lib.get(target, timeout=5, verify=False)
            except:
                pass
    return "<html><body>Apache Server</body></html>"


@cves_bp.route('/cgi-bin/<path:subpath>')
def apache_cgi(subpath=''):
    """Apache CGI path traversal."""
    if '..' in request.full_path or '%2e' in request.full_path.lower():
        try:
            with open('/etc/passwd', 'r') as f:
                return f.read()
        except:
            return "root:x:0:0:root:/root:/bin/bash\n"
    return "CGI script output", 200


# ============================================================================
# WEBLOGIC CVEs
# ============================================================================

@cves_bp.route('/console/login/LoginForm.jsp')
def cve_2020_2551():
    """CVE-2020-2551 WebLogic version disclosure."""
    return """<html><body>
<h1>Oracle WebLogic Server Administration Console</h1>
<p>Version: 12.2.1.3.0</p>
<p>10.3.6.0</p>
<p>12.1.3.0</p>
</body></html>"""


@cves_bp.route('/uddiexplorer/searchpublicregistries.jsp')
def weblogic_uddi():
    """WebLogic UDDI Explorer."""
    return """<html><body><h1>UDDI Explorer</h1><p>Search public registries</p></body></html>"""


# ============================================================================
# CISCO CVEs
# ============================================================================

@cves_bp.route('/cve/cisco/')
def cisco_index():
    return """<html><body><h1>Cisco</h1></body></html>"""


@cves_bp.route('/cgi-bin/config.exp')
@cves_bp.route('/cve/cisco/cgi-bin/config.exp')
def cve_2019_1653():
    """CVE-2019-1653 Cisco WAN VPN config exposure."""
    return """sysconfig
hostname=router1
user=admin
password_hash=5f4dcc3b5aa765d61d8327deb882cf99"""


@cves_bp.route('/+CSCOE+/logon.html')
@cves_bp.route('/+CSCOT+/translation-table')
def cisco_asa():
    """CVE-2020-3452 Cisco ASA LFI."""
    if 'translation-table' in request.path:
        return """INTERNAL_PASSWORD_ENABLED=true
CONF_VIRTUAL_KEYBOARD=true
TUNNEL_GROUP_LIST=DefaultWEBVPNGroup"""
    return """<html><body><h1>Cisco ASA SSL VPN</h1></body></html>"""


# ============================================================================
# TOMCAT / RUBY / CROWD / MISC CVEs
# ============================================================================

@cves_bp.route('/cve/tomcat/')
@cves_bp.route('/cve/tomcat/<path:subpath>')
def cve_2020_9484(subpath=''):
    """CVE-2020-9484 Tomcat session deserialization."""
    cookie = request.cookies.get('JSESSIONID', '')
    if '..' in cookie or 'groovy' in cookie.lower():
        return """<html><body>
<p>PersistentManagerBase: swapping out session</p>
</body></html>"""
    return "<html><body><h1>Apache Tomcat</h1></body></html>"


@cves_bp.route('/cve/ruby/')
@cves_bp.route('/cve/ruby/<path:subpath>')
def cve_2019_5418(subpath=''):
    """CVE-2019-5418 Ruby on Rails file read via Accept header."""
    accept = request.headers.get('Accept', '')
    if '..' in accept or '{{' in accept:
        try:
            with open('/etc/passwd', 'r') as f:
                return f.read()
        except:
            return "root:x:0:0:root:/root:/bin/bash\n"
    return "<html><body><h1>Ruby on Rails App</h1></body></html>"


@cves_bp.route('/crowd/plugins/servlet/exp')
def cve_2019_11580():
    """CVE-2019-11580 Atlassian Crowd RCE."""
    cmd = request.args.get('cmd', '')
    if cmd:
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=10
            )
            return result.stdout or "root:x:0:0:root:/root:/bin/bash\n"
        except:
            return "root:x:0:0:root:/root:/bin/bash\n"
    return "<html><body><h1>Atlassian Crowd</h1></body></html>"


@cves_bp.route('/cve/crowd/')
def crowd_index():
    return """<html><body><h1>Atlassian Crowd</h1></body></html>"""


# ============================================================================
# SOLARWINDS / COUCHDB / KUBERNETES / FIREBASE / MISC
# ============================================================================

@cves_bp.route('/cve/solarwinds/')
def solarwinds_index():
    return """<html><body><h1>SolarWinds Orion</h1></body></html>"""


@cves_bp.route('/Orion/Login.aspx')
def solarwinds_login():
    return """<html><body><h1>SolarWinds Orion - Login</h1></body></html>"""


@cves_bp.route('/api/2/databases')
@cves_bp.route('/SolarWinds/InformationService/v3/Json/Query')
def solarwinds_api():
    """Solarwinds_default_admin - checks for default admin creds."""
    auth = request.headers.get('Authorization', '')
    if 'YWRtaW46' in auth:  # admin: base64
        return make_json_response('{"results":[{"NodeID":1,"ObjectSubType":"ICMP","IPAddress":"192.168.1.1","Caption":"Orion Poller","MachineType":"net-snmp"}]}')
    return "Unauthorized", 401


@cves_bp.route('/cve/couchdb/_all_dbs')
@cves_bp.route('/_all_dbs')
def couchdb_alldbs():
    return make_json_response('["_replicator","_users","mydb","testdb"]')


@cves_bp.route('/_users/_all_docs')
@cves_bp.route('/cve/couchdb/_users/_all_docs')
def couchdb_users():
    """CouchDB_Admin_Exposure."""
    return make_json_response('{"total_rows":2,"offset":0,"rows":[{"id":"org.couchdb.user:admin","key":"org.couchdb.user:admin","value":{"rev":"1-abc"}},{"id":"org.couchdb.user:test","key":"org.couchdb.user:test","value":{"rev":"1-def"}}]}')


@cves_bp.route('/cve/kubernetes/api/v1/')
@cves_bp.route('/api/v1/')
@cves_bp.route('/k8s/api/v1/')
def kubernetes_api():
    """Kubernetes_API_Exposed."""
    return make_json_response('{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"v1","resources":[{"name":"pods","namespaced":true,"kind":"Pod","verbs":["get","list"]},{"name":"services","namespaced":true,"kind":"Service","verbs":["get","list"]}],"containers":[{"name":"kube-system"}],"objectRef":{"resource":"secrets","namespace":"kube-system"}}')


@cves_bp.route('/kube-system/<path:subpath>')
def kubernetes_secrets(subpath=''):
    return make_json_response('{"apiVersion":"v1","kind":"SecretList","items":[{"metadata":{"name":"default-token"}}],"containers":[{"name":"api-server"}],"objectRef":{"resource":"secrets"}}')


@cves_bp.route('/cve/firebase/.json')
@cves_bp.route('/.json')
def firebase_open():
    """Open Firebase Database."""
    return make_json_response('{"users":{"user1":{"email":"admin@example.com","name":"Admin"}},"config":{"debug":true}}')


# ============================================================================
# NETSWEEPER / ARTICA / MAGMI / TRAEFIK / ZOHO / N8N / SYMFONY
# ============================================================================

@cves_bp.route('/cve/netsweeper/')
@cves_bp.route('/webadmin/start/')
def netsweeper():
    return """<html><body><h1>Netsweeper WebAdmin</h1></body></html>"""


@cves_bp.route('/webadmin/tools/systemstatus_remote.php')
def netsweeper_status():
    return """<html><body><h1>System Status</h1></body></html>"""


@cves_bp.route('/webadmin/authx/login.php')
def cve_2020_13167():
    """CVE-2020-13167 Netsweeper code injection."""
    # Returns expected grep pattern
    return """<html><body><p>nonexistent: command not found</p></body></html>"""


@cves_bp.route('/cve/artica/fw.login.php')
@cves_bp.route('/fw.login.php')
def artica_login():
    """Artica web proxy. CVE-2020-17506 SQL injection."""
    api_key = request.args.get('apikey', request.form.get('apikey', ''))
    if "'" in api_key or "1=1" in api_key:
        resp = make_response("""<html><body><p>artica-appliance v4.30</p></body></html>""")
        resp.set_cookie('PHPSESSID', 'abc123def456')
        return resp
    return """<html><body><h1>Artica Web Proxy</h1>
<form method="POST"><input name="apikey"><button>Login</button></form></body></html>"""


@cves_bp.route('/cve/magmi/')
@cves_bp.route('/magmi/web/js/magmi_utils.js')
def magmi():
    """MAGMI request detection."""
    return """// MAGMI Utils JS
var magmi = {};"""


@cves_bp.route('/magmi/web/magmi.php')
def cve_2020_5777():
    """CVE-2020-5777 MAGMI auth bypass."""
    return """<html><body><p>Too many connections</p></body></html>"""


@cves_bp.route('/cve/traefik/')
@cves_bp.route('/cve/traefik/<path:subpath>')
def cve_2020_15129(subpath=''):
    """CVE-2020-15129 Traefik open redirect via X-Forwarded-Prefix."""
    prefix = request.headers.get('X-Forwarded-Prefix', '')
    if prefix:
        try:
            import requests as req_lib
            req_lib.get(prefix, timeout=5, verify=False)
        except:
            pass
    return """<html><body><h1>Traefik Dashboard</h1></body></html>"""


@cves_bp.route('/cve/zoho/')
def zoho_index():
    return """<html><body><h1>ManageEngine</h1></body></html>"""


@cves_bp.route('/./RestAPI/LogonCustomization', methods=['POST'])
@cves_bp.route('/RestAPI/LogonCustomization', methods=['POST'])
def cve_2021_40539():
    """CVE-2021-40539 Zoho ManageEngine ADSelfService auth bypass."""
    return """<html><body>
<script>window.parent.$("#mobLogo").attr("src","./images/mob_logo.png");</script>
</body></html>"""


@cves_bp.route('/cve/n8n/rest/settings')
@cves_bp.route('/rest/settings')
def cve_2025_68613():
    """CVE-2025-68613 n8n version detection."""
    return make_json_response('{"n8nVersion":"1.71.2","releaseChannel":"stable","authenticationMethod":"email","enterprise":{"sharing":false}}')


@cves_bp.route('/cve/symfony/profiler/phpinfo')
@cves_bp.route('/profiler/phpinfo')
def symfony_phpinfo():
    """Symfony debug profiler."""
    return """<html><head><title>phpinfo()</title></head><body>
<h1>PHP Version 8.2.0</h1>
<table><tr><td>Build Date</td><td>Jan 2024</td></tr></table>
</body></html>"""


@cves_bp.route('/profiler/empty/search/results')
def symfony_profiler():
    """Symfony profiler."""
    return """<html><body>
<div class="symfony/profiler">Profiler Results</div>
</body></html>"""


@cves_bp.route('/cve/text4shell')
def cve_2022_42889():
    """CVE-2022-42889 Text4Shell."""
    inp = request.args.get('input', '')
    # Process input - in real app, Apache Commons Text would evaluate ${...}
    if inp:
        try:
            subprocess.Popen(
                f"echo '{inp}' > /dev/null",
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except:
            pass
    return f"<html><body><p>Processed: {inp}</p></body></html>"


@cves_bp.route('/cve/text4shell', methods=['POST'])
def cve_2022_42889_post():
    inp = request.form.get('input', request.data.decode('utf-8', errors='replace'))
    if inp:
        try:
            subprocess.Popen(
                f"echo '{inp}' > /dev/null",
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except:
            pass
    return f"<html><body><p>Processed</p></body></html>"


# WordPress CVE paths (separate from main WordPress module)
@cves_bp.route('/cve/wp/local-file-inclusion')
def cve_2020_11738():
    """CVE-2020-11738 WordPress Duplicator LFI."""
    file_param = request.args.get('file', '')
    if '..' in file_param:
        try:
            with open('/etc/passwd', 'r') as f:
                return f.read()
        except:
            return "root:x:0:0:root:/root:/bin/bash\n"
    return "Not found", 404


@cves_bp.route('/cve/pulse/')
def pulse_index():
    return """<html><body><h1>Pulse Secure</h1></body></html>"""


# ============================================================================
# HELPER
# ============================================================================

def make_json_response(json_str):
    resp = make_response(json_str)
    resp.headers['Content-Type'] = 'application/json'
    return resp
