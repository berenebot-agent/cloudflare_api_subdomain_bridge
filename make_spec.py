#!/usr/bin/env python3
"""Generate the checked-in OpenAPI document. Requires Python stdlib only.

Field schemas are declared explicitly per operation so generated clients model
optional/conditional fields, value constraints, and the status codes the server
actually returns.
"""
import json
from pathlib import Path

P = {}

COMMON_ERRORS = {
    '200': 'Operation successful',
    '201': 'Resource created',
    '400': 'Invalid request',
    '401': 'Invalid or missing Bearer key',
    '403': 'Outside scope or feature not granted',
    '404': 'Not found or resource not owned by client',
    '405': 'Method not allowed',
    '409': 'Resource conflict or configuration drift',
    '429': 'Rate limit exceeded',
    '502': 'Upstream or storage operation failed',
}

# Response-code sets, chosen per operation from the codes the handler can
# actually emit (see the *_test.go suite and failure() in main.go). Advertising
# codes an endpoint can never return makes generated clients model failure modes
# that do not exist.
ME = {'401', '405', '429'}
READ = {'401', '403', '405', '429', '502'}
READ_ID = {'400', '401', '403', '404', '405', '429', '502'}
READ_ID_409 = {'400', '401', '403', '404', '405', '409', '429', '502'}
CREATE = {'400', '401', '403', '405', '429', '502'}
CREATE_409 = {'400', '401', '403', '405', '409', '429', '502'}
MUT_ID = {'400', '401', '403', '404', '405', '409', '429', '502'}
EMAIL_READ = {'401', '403', '405', '409', '429', '502'}


def schema_for(field):
    if field == 'priority':
        return {'type': 'integer', 'minimum': 0, 'maximum': 65535}
    if field == 'proxied':
        return {'type': 'boolean'}
    if field == 'ttl':
        return {'type': 'integer', 'description': '1 means automatic; otherwise 60..86400'}
    if field == 'content':
        return {'type': 'string', 'description': 'Record content; format depends on record type'}
    if field == 'type':
        return {'type': 'string', 'enum': ['A', 'AAAA', 'CNAME', 'MX', 'TXT']}
    if field == 'id':
        return {'type': 'string', 'pattern': '^[a-zA-Z0-9_-]{1,128}$'}
    if field == 'hostname':
        return {'type': 'string'}
    if field == 'destination':
        return {'type': 'string', 'description': 'Required for forward/worker; must be omitted for drop'}
    if field == 'action':
        return {'type': 'string', 'enum': ['drop', 'forward', 'worker']}
    if field == 'script':
        return {'type': 'string', 'description': 'JavaScript module; 1..524288 bytes'}
    if field == 'label':
        return {'type': 'string', 'pattern': '^[a-z0-9][a-z0-9_-]{0,40}$'}
    return {'type': 'string'}


def op(path, method, summary, tag, codes, create=False, body=None, required=None,
       example=None, desc=None):
    statuses = {'200', *codes}
    if create:
        statuses.add('201')
    responses = {code: {'description': COMMON_ERRORS[code]} for code in sorted(statuses)}
    item = {'summary': summary, 'tags': [tag], 'responses': responses}
    if desc:
        item['description'] = desc
    if body:
        props = {k: schema_for(k) for k in body}
        schema = {'type': 'object', 'properties': props}
        req = required if required is not None else list(body)
        if req:
            schema['required'] = req
        item['requestBody'] = {'required': True, 'content': {'application/json': {'schema': schema}}}
    if example:
        item['x-example'] = example
    params = [v[1:-1] for v in path.split('/') if v.startswith('{') and v.endswith('}')]
    if params:
        item['parameters'] = [
            {'in': 'path', 'name': v, 'required': True,
             'schema': {'type': 'string', 'pattern': '^[a-zA-Z0-9_@.-]{1,253}$'} if v in ('id', 'hostname') else {'type': 'string'}}
            for v in params
        ]
    if path not in ['/healthz', '/openapi.json', '/docs']:
        item['security'] = [{'bearerAuth': []}]
    P.setdefault(path, {})[method.lower()] = item


op('/healthz', 'GET', 'Process health check', 'System', set())
op('/api/v1/me', 'GET', 'Authenticated client scope and capabilities', 'System', ME)
op('/api/v1/dns', 'GET', 'List DNS records under client scope', 'DNS', READ)
op('/api/v1/dns', 'POST', 'Create scoped DNS record', 'DNS', CREATE_409, create=True,
   body=['name', 'type', 'content', 'ttl', 'proxied', 'priority'],
   required=['name', 'type', 'content'],
   example={'name': 'app.hermes.example.com', 'type': 'A', 'content': '198.51.100.10', 'ttl': 1})
op('/api/v1/dns/{id}', 'GET', 'Read DNS record after current-name scope check', 'DNS', READ_ID_409)
op('/api/v1/dns/{id}', 'PATCH', 'Replace DNS record; old and new names checked', 'DNS', MUT_ID,
   body=['name', 'type', 'content', 'ttl', 'proxied', 'priority'],
   required=['name', 'type', 'content'])
op('/api/v1/dns/{id}', 'DELETE', 'Delete scoped DNS record', 'DNS', MUT_ID)
op('/api/v1/tunnels', 'GET', 'List tunnels created by this bridge for client', 'Tunnels', READ)
op('/api/v1/tunnels', 'POST', 'Create remotely managed dedicated tunnel', 'Tunnels', CREATE, create=True,
   body=['name'], required=['name'], example={'name': 'backend'})
op('/api/v1/tunnels/{id}', 'GET', 'Read owned tunnel information', 'Tunnels', READ_ID)
op('/api/v1/tunnels/{id}', 'DELETE', 'Delete empty owned tunnel', 'Tunnels', MUT_ID)
op('/api/v1/tunnels/{id}/token', 'GET', 'Retrieve connector token for owned tunnel; sensitive', 'Tunnels', READ_ID_409)
op('/api/v1/tunnels/{id}/hostnames', 'GET', 'List managed ingress hostnames on tunnel', 'Tunnels', READ_ID)
op('/api/v1/tunnels/{id}/hostnames', 'POST', 'Publish scoped hostname; create proxied CNAME and ingress', 'Tunnels', MUT_ID, create=True,
   body=['hostname', 'service'], required=['hostname', 'service'],
   example={'hostname': 'app.hermes.example.com', 'service': 'http://localhost:8080'})
op('/api/v1/tunnels/{id}/hostnames/{hostname}', 'DELETE', 'Unpublish hostname and managed DNS record', 'Tunnels', MUT_ID)
op('/api/v1/workers', 'GET', 'List owned Workers', 'Workers', READ)
op('/api/v1/workers', 'POST', 'Upload module Worker without external bindings; public worker subdomain disabled', 'Workers', CREATE, create=True,
   body=['label', 'script'], required=['label', 'script'],
   example={'label': 'hello', 'script': 'export default {async fetch(){return new Response("ok")}}'})
op('/api/v1/workers/{id}', 'PUT', 'Replace script of owned Worker', 'Workers', MUT_ID,
   body=['script'], required=['script'])
op('/api/v1/workers/{id}', 'DELETE', 'Delete owned Worker after routes removed', 'Workers', MUT_ID)
op('/api/v1/workers/{id}/routes', 'POST', 'Create scoped host-only Worker route', 'Workers', MUT_ID, create=True,
   body=['hostname'], required=['hostname'], example={'hostname': 'service.hermes.example.com'})
op('/api/v1/workers/routes', 'GET', 'List owned Worker routes', 'Workers', READ)
op('/api/v1/workers/routes/{id}', 'DELETE', 'Delete owned Worker route after drift check', 'Workers', MUT_ID)
op('/api/v1/email', 'GET', 'List owned literal-address Email Routing rules', 'Email', EMAIL_READ)
op('/api/v1/email', 'POST', 'Create literal-address forward, drop or owned Worker rule', 'Email', CREATE_409, create=True,
   body=['address', 'action', 'destination'], required=['address', 'action'],
   example={'address': 'support@hermes.example.com', 'action': 'forward', 'destination': 'verified@example.net'})
op('/api/v1/email/{id}', 'DELETE', 'Delete owned email rule after drift check', 'Email', MUT_ID)

spec = {
    'openapi': '3.1.0',
    'info': {
        'title': 'Cloudflare Subdomain Bridge',
        'version': '1.0.0-alpha',
        'description': 'Self-hosted, API-only Cloudflare subdomain permissions bridge. Credentials and scopes are env-only. Do not expose unauthenticated over public HTTP. See README for limits.',
    },
    'servers': [{'url': '/'}],
    'tags': [{'name': x} for x in ['System', 'DNS', 'Tunnels', 'Workers', 'Email']],
    'components': {'securitySchemes': {'bearerAuth': {'type': 'http', 'scheme': 'bearer', 'bearerFormat': 'API key'}}},
    'paths': P,
}
Path(__file__).with_name('openapi.json').write_text(json.dumps(spec, indent=2) + '\n')
