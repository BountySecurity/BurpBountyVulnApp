"""Miscellaneous endpoints - DWR, Swagger, Git/SVN, Source code, Fuzzing."""
import os
from flask import Blueprint, request, make_response, send_from_directory

misc_bp = Blueprint('misc', __name__)


# ============================================================================
# DWR (Direct Web Remoting) - Triggers: DWR_endpoints
# ============================================================================

@misc_bp.route('/dwr/interface')
@misc_bp.route('/dwr/interface/')
@misc_bp.route('/dwr/interface/DWREngine')
def dwr_interface():
    return """// DWR Interface
// Available classes:
var DWREngine = {};
DWREngine._execute = function() {};
dwr.engine._execute = function() {};"""


@misc_bp.route('/dwr/engine.js')
def dwr_engine():
    return """// DWREngine JavaScript
if (typeof dwr == 'undefined') dwr = {};
if (typeof dwr.engine == 'undefined') dwr.engine = {};
DWREngine = dwr.engine;
dwr.engine._execute = function(p1, p2, p3) {};
dwr.engine._poll = function() {};"""


@misc_bp.route('/dwr/util.js')
def dwr_util():
    return """// DWRUtil JavaScript
if (typeof dwr == 'undefined') dwr = {};
if (typeof dwr.util == 'undefined') dwr.util = {};
DWRUtil = dwr.util;
dwr.util.getValue = function(id) {};"""


@misc_bp.route('/dwr/index.html')
@misc_bp.route('/dwr/test/index.html')
def dwr_test():
    return """<html><body>
<h1>DWR Test Page</h1>
<script src="/dwr/engine.js"></script>
<script src="/dwr/util.js"></script>
</body></html>"""


@misc_bp.route('/dwr/call/plaincall/<path:subpath>', methods=['POST'])
def dwr_call(subpath=''):
    return """dwr.engine._remoteHandleCallback('1','0',{});"""


# ============================================================================
# GIT / SVN exposure - Triggers: GitFinder, SVNFinder
# ============================================================================

@misc_bp.route('/.git/HEAD')
def git_head():
    return "ref: refs/heads/main\n"


@misc_bp.route('/.git/config')
def git_config():
    return """[core]
\trepositoryformatversion = 0
\tfileversion = 0
\tbare = false
[remote "origin"]
\turl = https://github.com/example/repo.git
\tfetch = +refs/heads/*:refs/remotes/origin/*"""


@misc_bp.route('/.git/<path:subpath>')
def git_files(subpath):
    """Serve .git directory files."""
    git_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'static', '.git')
    try:
        filepath = os.path.join(git_dir, subpath)
        if os.path.isfile(filepath):
            with open(filepath, 'r') as f:
                return f.read()
    except:
        pass
    return "ref: refs/heads/main\n" if 'HEAD' in subpath else "Not found", 404


@misc_bp.route('/.svn/entries')
def svn_entries():
    return """10
dir
123
url=https://svn.example.com/repo/trunk
committed-date=2024-01-01T00:00:00Z
committed-rev=123"""


@misc_bp.route('/.svn/wc.db')
def svn_wcdb():
    return "SQLite format 3\x00", 200


# ============================================================================
# SWAGGER - Triggers: Swagger-Finder
# ============================================================================

@misc_bp.route('/swagger-ui.html')
@misc_bp.route('/swagger-ui/')
def swagger_ui():
    return """<html><body>
<div id="swagger-ui"></div>
<script>
// Swagger UI initialization
SwaggerUIBundle({url: "/api-docs", dom_id: '#swagger-ui'});
</script></body></html>"""


@misc_bp.route('/api-docs')
@misc_bp.route('/api-docs/')
@misc_bp.route('/v2/api-docs')
@misc_bp.route('/v3/api-docs')
def api_docs():
    import json
    return make_response(json.dumps({
        "openapi": "3.0.0",
        "info": {"title": "VulnApp API", "version": "1.0.0"},
        "paths": {
            "/api/v1/users": {"get": {"summary": "List users"}},
            "/api/v1/products": {"get": {"summary": "List products"}}
        }
    })), 200, {'Content-Type': 'application/json'}


@misc_bp.route('/swagger.json')
@misc_bp.route('/swagger.yaml')
def swagger_json():
    return make_response('{"openapi":"3.0.0","info":{"title":"API","version":"1.0"}}'), 200, {'Content-Type': 'application/json'}


@misc_bp.route('/swagger/v1/swagger.json')
def swagger_v1():
    return make_response('{"openapi":"3.0.0"}'), 200, {'Content-Type': 'application/json'}


# ============================================================================
# SOURCE CODE DISCLOSURE - Triggers: Source_code
# ============================================================================

@misc_bp.route('/source/<path:filename>')
def source_code(filename):
    """Source code disclosure via backup files (~, .bak, etc.)."""
    if filename.endswith('~') or filename.endswith('.bak') or filename.endswith('.old'):
        return """<?php
// Database configuration
$db_host = 'localhost';
$db_user = 'root';
$db_pass = 'password123';
$db_name = 'myapp';

// Connect to database
$conn = mysqli_connect($db_host, $db_user, $db_pass, $db_name);
if (!$conn) { die("Connection failed"); }

echo "Connected successfully";
?>"""
    if filename.endswith('.aspx') or filename.endswith('.asp'):
        return """<% @Page Language="C#" %>
<%@ Import Namespace="System.Data.SqlClient" %>
<%
string connStr = "Server=localhost;Database=mydb;User Id=sa;Password=admin123;";
SqlConnection conn = new SqlConnection(connStr);
conn.Open();
Response.Write("Connected");
%>"""
    if filename.endswith('.jsp'):
        return """<%@ page import="java.sql.*" %>
<%
out.write("Database connection test");
Class.forName("com.mysql.jdbc.Driver");
Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/mydb", "root", "pass");
%>"""
    return """<?php
echo "Hello World";
phpinfo();
?>"""


# ============================================================================
# API PATHS - Triggers: Api_path passive detection
# ============================================================================

@misc_bp.route('/api/v1/status')
@misc_bp.route('/api/v1/data')
@misc_bp.route('/api/v2/status')
def api_status():
    return '{"status":"ok","version":"1.0.0","uptime":"24h"}', 200, {'Content-Type': 'application/json'}


# ============================================================================
# FUZZING DIRECTORIES - Triggers: Fuzzing_directories
# Some common paths that should return 200 instead of 404
# ============================================================================

@misc_bp.route('/admin/')
def admin_page():
    return """<html><body><h1>Admin Panel</h1><p>Login required</p></body></html>"""


@misc_bp.route('/backup/')
def backup_dir():
    return """<html><body><h1>Index of /backup/</h1><pre>
<a href="db_backup.sql">db_backup.sql</a>    2024-01-15  10485760
<a href="site_backup.tar.gz">site_backup.tar.gz</a> 2024-01-15  52428800
</pre></body></html>"""


@misc_bp.route('/config/')
@misc_bp.route('/conf/')
def config_dir():
    return """<html><body><h1>Index of /config/</h1><pre>
<a href="database.yml">database.yml</a>    2024-01-15  256
<a href="settings.json">settings.json</a>   2024-01-15  512
</pre></body></html>"""


@misc_bp.route('/phpinfo.php')
@misc_bp.route('/info.php')
def phpinfo():
    return """<html><head><title>phpinfo()</title></head><body>
<h1>PHP Version 8.2.0</h1>
<table><tr><td>Build Date</td><td>Jan 1 2024</td></tr></table>
</body></html>"""


@misc_bp.route('/robots.txt')
def robots():
    return """User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /config/
Disallow: /api/
Disallow: /.git/
Sitemap: http://localhost:8080/sitemap.xml"""


@misc_bp.route('/sitemap.xml')
def sitemap():
    return """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://localhost:8080/</loc></url>
  <url><loc>http://localhost:8080/xss/reflect?q=test</loc></url>
  <url><loc>http://localhost:8080/sqli/search?q=test</loc></url>
</urlset>""", 200, {'Content-Type': 'text/xml'}
