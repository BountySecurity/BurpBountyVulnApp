"""GraphQL vulnerability endpoints - triggers 6 GraphQL profiles."""
import json
from flask import Blueprint, request, make_response, render_template_string

graphql_bp = Blueprint('graphql', __name__)

# Simple GraphQL schema data
SCHEMA = {
    "types": [
        {"name": "Query", "fields": [
            {"name": "user", "type": {"name": "User", "fields": [
                {"name": "id", "type": {"name": "Int"}},
                {"name": "name", "type": {"name": "String"}},
                {"name": "email", "type": {"name": "String"}}
            ]}},
            {"name": "users", "type": {"name": "[User]"}},
            {"name": "product", "type": {"name": "Product"}}
        ]},
        {"name": "User", "fields": [
            {"name": "id", "type": {"name": "Int"}},
            {"name": "name", "type": {"name": "String"}},
            {"name": "email", "type": {"name": "String"}},
            {"name": "posts", "type": {"name": "[Post]", "fields": [
                {"name": "title", "type": {"name": "String"}},
                {"name": "body", "type": {"name": "String"}}
            ]}}
        ]},
        {"name": "Post", "fields": [
            {"name": "title", "type": {"name": "String"}},
            {"name": "body", "type": {"name": "String"}},
            {"name": "author", "type": {"name": "User"}}
        ]},
        {"name": "Product", "fields": [
            {"name": "id", "type": {"name": "Int"}},
            {"name": "name", "type": {"name": "String"}},
            {"name": "price", "type": {"name": "Float"}}
        ]}
    ],
    "queryType": {"name": "Query"},
    "mutationType": None,
    "subscriptionType": None,
    "directives": [
        {"name": "include", "locations": ["FIELD"]},
        {"name": "skip", "locations": ["FIELD"]},
        {"name": "deprecated", "locations": ["FIELD_DEFINITION"]}
    ]
}


def process_graphql(query_str, variables=None):
    """Process GraphQL query and return appropriate response."""
    if not query_str:
        return {"errors": [{"message": "No query provided"}]}

    lower_q = query_str.lower().strip()

    # Introspection query - Triggers: Graphql Introspection
    if '__schema' in lower_q:
        return {"data": {"__schema": SCHEMA}}

    # __typename queries - Triggers: GraphQL Batching, Alias Overloading, Field Duplication
    if '__typename' in lower_q:
        # Check for aliases (alias1:__typename, alias2:__typename, etc.)
        import re
        aliases = re.findall(r'(\w+)\s*:\s*__typename', query_str)
        if aliases:
            data = {alias: "Query" for alias in aliases}
            return {"data": data}
        return {"data": {"__typename": "Query"}}

    # Directive overloading - Triggers: GraphQL Directives Overloading
    if '@' in query_str and ('foo' in lower_q or 'bar' in lower_q or 'baz' in lower_q):
        unknown_directives = []
        import re
        for d in re.findall(r'@(\w+)', query_str):
            if d not in ('include', 'skip', 'deprecated'):
                unknown_directives.append(d)
        if unknown_directives:
            return {
                "errors": [
                    {"message": f"Unknown directive \"{d}\"", "locations": [{"line": 1, "column": 1}]}
                    for d in unknown_directives
                ]
            }

    # Circular/deep queries - Triggers: GraphQL Circular Queries
    if query_str.count('{') > 5:
        # Return the query content reflected (MatchType=Payload in response)
        depth = query_str.count('{')
        return {
            "data": {
                "__schema": {
                    "types": [{"name": "Query", "fields": [
                        {"name": "user", "type": {"fields": [
                            {"name": "posts", "type": {"fields": [
                                {"name": "author", "type": {"fields": []}}
                            ]}}
                        ]}}
                    ]}]
                }
            }
        }

    # Default user query
    return {
        "data": {
            "user": {"id": 1, "name": "admin", "email": "admin@example.com"}
        }
    }


@graphql_bp.route('/graphql', methods=['GET', 'POST'])
def graphql_endpoint():
    """GraphQL endpoint. Triggers: GraphQL Alias Overloading, Batching, Circular Queries,
    Directives Overloading, Field Duplication, Graphql Introspection"""
    if request.method == 'GET':
        query = request.args.get('query', '')
        variables = request.args.get('variables', '{}')
        if not query:
            return """<html><body>
<h1>GraphQL API</h1>
<p>Send POST requests with JSON body: {"query": "..."}</p>
<p><a href="/graphql/ide">GraphQL IDE</a></p>
</body></html>"""
        try:
            variables = json.loads(variables) if variables else {}
        except:
            variables = {}
        result = process_graphql(query, variables)
        resp = make_response(json.dumps(result))
        resp.headers['Content-Type'] = 'application/json'
        return resp

    # POST request
    content_type = request.content_type or ''

    if 'application/json' in content_type:
        try:
            data = request.get_json(force=True)
        except:
            data = {}

        # Handle batched queries - Triggers: GraphQL Batching
        if isinstance(data, list):
            results = []
            for item in data:
                query = item.get('query', '')
                variables = item.get('variables', {})
                results.append(process_graphql(query, variables))
            resp = make_response(json.dumps(results))
            resp.headers['Content-Type'] = 'application/json'
            return resp

        query = data.get('query', '')
        variables = data.get('variables', {})
    else:
        query = request.form.get('query', '') or request.data.decode('utf-8', errors='replace')
        variables = {}

    result = process_graphql(query, variables)
    resp = make_response(json.dumps(result))
    resp.headers['Content-Type'] = 'application/json'
    return resp


@graphql_bp.route('/graphql/ide')
def graphql_ide():
    """GraphQL IDE page (also detected by passive profiles)."""
    return """<html><body>
<h1>GraphQL IDE</h1>
<textarea id="query" rows="10" cols="60">{ user { id name email } }</textarea><br>
<button onclick="runQuery()">Run Query</button>
<pre id="result"></pre>
<script>
function runQuery() {
    fetch('/graphql', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({query: document.getElementById('query').value})
    }).then(r => r.json()).then(d => {
        document.getElementById('result').textContent = JSON.stringify(d, null, 2);
    });
}
</script></body></html>"""
