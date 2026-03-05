"""CORS misconfiguration endpoint - triggers 1 CORS profile."""
from flask import Blueprint, request, make_response, jsonify

cors_bp = Blueprint('cors', __name__, url_prefix='/cors')


@cors_bp.route('/api/data')
def api_data():
    """CORS misconfiguration. Triggers: CORS Misconfiguration
    Reflects Origin header in Access-Control-Allow-Origin and sets credentials."""
    origin = request.headers.get('Origin', '')
    resp = make_response(jsonify({
        "users": [
            {"id": 1, "username": "admin", "email": "admin@example.com"},
            {"id": 2, "username": "john", "email": "john@example.com"}
        ],
        "status": "success"
    }))
    # Vulnerable: reflects any origin and allows credentials
    if origin:
        resp.headers['Access-Control-Allow-Origin'] = origin
    else:
        resp.headers['Access-Control-Allow-Origin'] = 'null'
    resp.headers['Access-Control-Allow-Credentials'] = 'true'
    resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return resp


@cors_bp.route('/api/data', methods=['OPTIONS'])
def api_data_options():
    """CORS preflight."""
    origin = request.headers.get('Origin', '*')
    resp = make_response('', 204)
    resp.headers['Access-Control-Allow-Origin'] = origin
    resp.headers['Access-Control-Allow-Credentials'] = 'true'
    resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return resp
