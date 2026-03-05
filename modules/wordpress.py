"""WordPress simulation endpoints - triggers 10 WordPress profiles."""
import os
from flask import Blueprint, request, make_response

wp_bp = Blueprint('wp', __name__, url_prefix='/wp')


@wp_bp.route('/wp-login.php')
def wp_login():
    return """<html><body>
<h1>WordPress Login</h1>
<form method="POST" action="/wp/wp-login.php">
<input name="log" placeholder="Username"><br>
<input name="pwd" type="password"><br>
<button>Log In</button>
</form></body></html>"""


@wp_bp.route('/wp-login.php', methods=['POST'])
def wp_login_post():
    return """<html><body><p>Invalid username or password.</p></body></html>"""


@wp_bp.route('/xmlrpc.php', methods=['GET', 'POST'])
def xmlrpc():
    """WordPress XMLRPC. Triggers: Wordpress_XMLRPC_ListMethods, Wordpress_XMLRPC_Pingback"""
    if request.method == 'GET':
        return """<html><body><p>XML-RPC server accepts POST requests only.</p></body></html>"""

    data = request.data.decode('utf-8', errors='replace')

    if 'system.listMethods' in data:
        return make_xml_response("""<?xml version="1.0"?>
<methodResponse>
  <params><param><value><array><data>
    <value><string>system.listMethods</string></value>
    <value><string>system.getCapabilities</string></value>
    <value><string>pingback.ping</string></value>
    <value><string>pingback.extensions.getPingbacks</string></value>
    <value><string>wp.getUsersBlogs</string></value>
    <value><string>wp.getOptions</string></value>
  </data></array></value></param></params>
</methodResponse>""")

    if 'pingback.ping' in data:
        # Extract the URL from pingback and try to fetch it (SSRF)
        import re
        urls = re.findall(r'<string>(https?://[^<]+)</string>', data)
        if urls:
            try:
                import requests as req_lib
                req_lib.get(urls[0], timeout=5, verify=False)
            except:
                pass
        return make_xml_response("""<?xml version="1.0"?>
<methodResponse>
  <params><param><value><string>Pingback registered</string></value></param></params>
</methodResponse>""")

    return make_xml_response("""<?xml version="1.0"?>
<methodResponse>
  <fault><value><struct>
    <member><name>faultCode</name><value><int>-32601</int></value></member>
    <member><name>faultString</name><value><string>Method not found</string></value></member>
  </struct></value></fault>
</methodResponse>""")


@wp_bp.route('/wp-json/wp/v2/users')
def wp_users_json():
    """WordPress user enum via REST API. Triggers: Wordpress_user_enum_json"""
    return make_json_response("""[
  {"id":1,"name":"admin","url":"http://localhost","description":"","link":"http://localhost/author/admin/","slug":"admin","avatar_urls":{"24":"http://secure.gravatar.com/avatar/?s=24"}},
  {"id":2,"name":"editor","url":"","description":"","link":"http://localhost/author/editor/","slug":"editor","avatar_urls":{"24":"http://secure.gravatar.com/avatar/?s=24"}}
]""")


@wp_bp.route('/wp-json/oembed/1.0/embed')
def wp_oembed():
    """WordPress oEmbed endpoint. Triggers: Wordpress_user_enum_oembed"""
    url = request.args.get('url', '')
    if not url:
        return make_json_response('{"code":"oembed_invalid_url","message":"Not a valid oembed URL.","data":{"status":404}}'), 404
    return make_json_response('{"code":"oembed_invalid_url","message":"Not a valid oembed URL.","data":{"status":404}}'), 404


@wp_bp.route('/author-sitemap.xml')
def wp_author_sitemap():
    """WordPress author sitemap. Triggers: Wordpress_users_enum_yoastseo"""
    return make_xml_response("""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>http://localhost/author/admin/</loc>
    <lastmod>2024-01-15T10:00:00+00:00</lastmod>
  </url>
  <url>
    <loc>http://localhost/author/editor/</loc>
    <lastmod>2024-01-10T08:00:00+00:00</lastmod>
  </url>
</urlset>""")


@wp_bp.route('/wp-config.php')
@wp_bp.route('/wp-config.php.bak')
@wp_bp.route('/wp-config.php.old')
@wp_bp.route('/wp-config.php.save')
@wp_bp.route('/wp-config.php~')
@wp_bp.route('/wp-config.php.swp')
@wp_bp.route('/wp-config.bak')
@wp_bp.route('/wp-config.old')
@wp_bp.route('/wp-config.txt')
def wp_config():
    """WordPress config exposure. Triggers: Wordpress_Config_Accessible"""
    return """<?php
define('DB_NAME', 'wordpress');
define('DB_USER', 'wp_admin');
define('DB_PASSWORD', 'sup3r_s3cr3t_p4ssw0rd');
define('DB_HOST', 'localhost');
define('WPENGINE_ACCOUNT', 'mysite');
define('AUTH_KEY', 'put your unique phrase here');
define('SECURE_AUTH_KEY', 'put your unique phrase here');
$table_prefix = 'wp_';
define('WP_DEBUG', true);
"""


@wp_bp.route('/debug.log')
@wp_bp.route('/wp-content/debug.log')
def wp_debug_log():
    """WordPress debug log. Triggers: Wordpress_Config_Accessible"""
    return """[15-Jan-2024 10:00:00 UTC] PHP Notice: Undefined variable: user_id in /var/www/html/wp-content/plugins/myplugin/myplugin.php on line 42
[15-Jan-2024 10:01:00 UTC] PHP Warning: include(/etc/passwd): failed to open stream
DB_NAME = wordpress
DB_PASSWORD = sup3r_s3cr3t
"""


@wp_bp.route('/wp-admin/')
@wp_bp.route('/wp-content/')
@wp_bp.route('/wp-includes/')
@wp_bp.route('/wp-content/uploads/')
def wp_directory_listing():
    """WordPress directory listing. Triggers: Wordpress_directory_listing"""
    path = request.path.rstrip('/')
    return f"""<html><body>
<h1>Index of {path}</h1>
<pre>
<a href="../">../</a>
<a href="index.php">index.php</a>                2024-01-15 10:00  1234
<a href="admin.php">admin.php</a>                2024-01-15 10:00  5678
<a href="includes/">includes/</a>                2024-01-15 10:00  -
<a href="plugins/">plugins/</a>                 2024-01-15 10:00  -
<a href="themes/">themes/</a>                  2024-01-15 10:00  -
</pre>
</body></html>"""


@wp_bp.route('/wp-content/plugins/easy-wp-smtp/')
def wp_easy_smtp():
    """Easy WP SMTP directory listing. Triggers: Easy_wp_smtp_listing_enabled"""
    return """<html><body>
<h1>Index of /wp-content/plugins/easy-wp-smtp/</h1>
<pre>
<a href="../">../</a>
<a href="easy-wp-smtp.php">easy-wp-smtp.php</a>     2024-01-15  4096
<a href="readme.txt">readme.txt</a>             2024-01-15  2048
</pre>
</body></html>"""


@wp_bp.route('/wp-content/plugins/insert-php/readme.txt')
def wp_insert_php():
    """WordPress insert-php plugin. Triggers: Woody_Wordpress_RCE"""
    return """=== Starter Templates - Starter Sites for WordPress ===
Contributors: developer
Tags: insert, php, exec
Requires at least: 5.0
Tested up to: 6.4
Stable tag: 2.2.5
Version: 2.2.5

== Description ==
Insert PHP Code Snippet into WordPress Posts and Pages.
"""


@wp_bp.route('/wp-admin/admin-ajax.php')
def wp_admin_ajax():
    """WordPress admin-ajax. Triggers: Wordpress_Path_Traversal (Duplicator)"""
    action = request.args.get('action', '')
    file_param = request.args.get('file', '')

    if action == 'duplicator_download' and file_param:
        if '..' in file_param or 'wp-config' in file_param:
            return """<?php
define('DB_NAME', 'wordpress');
define('DB_USER', 'wp_admin');
define('DB_PASSWORD', 'sup3r_s3cr3t_p4ssw0rd');
"""
    return """{"success":false,"data":"Invalid action"}"""


@wp_bp.route('/wp-content/backups/')
@wp_bp.route('/wp-content/backup-db/')
def wp_backup_listing():
    """CVE-2020-24312 WordPress backup listing."""
    return """<html><body>
<h1>Index of /wp-content/backups/</h1>
<pre>
<a href="../">../</a>
<a href="backup-2024.sql">backup-2024.sql</a>     2024-01-15  1048576
<a href="wp-config.bak">wp-config.bak</a>       2024-01-15  4096
</pre></body></html>"""


# BackupBuddy LFI
@wp_bp.route('/wp-admin/admin-post.php')
def cve_2022_31474():
    """CVE-2022-31474 BackupBuddy LFI."""
    local_download = request.args.get('local_download', '')
    if local_download and '..' in local_download:
        try:
            with open('/etc/passwd', 'r') as f:
                return f.read()
        except:
            return "root:x:0:0:root:/root:/bin/bash\n"
    return "", 404


# ============================================================================
# HELPERS
# ============================================================================

def make_json_response(json_str):
    resp = make_response(json_str)
    resp.headers['Content-Type'] = 'application/json'
    return resp


def make_xml_response(xml_str):
    resp = make_response(xml_str)
    resp.headers['Content-Type'] = 'text/xml'
    return resp
