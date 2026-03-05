"""Drupal simulation endpoints - triggers 2 Drupal profiles."""
from flask import Blueprint, request, make_response, redirect

drupal_bp = Blueprint('drupal', __name__, url_prefix='/drupal')


@drupal_bp.route('/admin/views/ajax/autocomplete/user/<query>')
@drupal_bp.route('/autocomplete/user/<query>')
@drupal_bp.route('/user/autocomplete/<query>')
@drupal_bp.route('/entity_reference/autocomplete/tags/user/<query>')
def drupal_user_autocomplete(query):
    """Drupal user enumeration via autocomplete. Triggers: Drupal_User_Enum"""
    # Returns JSON starting with {"a... which matches the grep pattern \{"a
    users = {}
    if query.lower().startswith('a'):
        users = {"admin": "admin", "alice": "alice"}
    elif query.lower().startswith('b'):
        users = {"bob": "bob"}
    else:
        users = {query: query}
    import json
    resp = make_response(json.dumps(users))
    resp.headers['Content-Type'] = 'application/json'
    return resp


@drupal_bp.route('/user/<int:uid>')
def drupal_user_redirect(uid):
    """Drupal user profile redirect. Triggers: Drupal_User_Enum_Redirect"""
    users = {0: 'anonymous', 1: 'admin', 2: 'editor', 3: 'moderator'}
    username = users.get(uid, f'user{uid}')
    return redirect(f'/drupal/users/{username}', code=302)


@drupal_bp.route('/users/<username>')
def drupal_user_profile(username):
    return f"""<html><body>
<h1>User: {username}</h1>
<p>Member since: January 2024</p>
</body></html>"""
