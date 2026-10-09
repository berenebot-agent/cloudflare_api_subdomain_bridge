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

# Endpoints that do not create resources never return 201.
NO_CREATE = {'/api/v1/me', '/api/v1/dns', '/api/v1/dns/{id}',
             '/api/v1/tunnels', '/api/v1/tunnels/{id}',
             '/api/v1/tunnels/{id}/hostnames',
             '/api/v1/workers', '/api/v1/workers/{id}',
             '/api/v1/workers/routes', '/api/v1/email'}


def schema_for(field):
    if field == 'priority':
        return {'type': 'integer', 'minimum': 0, 'maximum': 65535}
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


def op(path, method, summary, tag, body=None, required=None, example=None, desc=None,
       extra_responses=None):
    if path == '/healthz':
        statuses = {'200', '405'}
    else:
        statuses = {'200'}
        if path not in NO_CREATE:
            statuses.add('201')
        statuses.update({'400', '401', '403', '404', '405', '409', '429', '502'})
        statuses.update(extra_responses or set())
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


op('/healthz', 'GET', 'Process health check', 'System')
op('/api/v1/me', 'GET', 'Authenticated client scope and capabilities', 'System')
op('/api/v1/dns', 'GET', 'List DNS records under client scope', 'DNS')
op('/api/v1/dns', 'POST', 'Create scoped DNS record', 'DNS',
   body=['name', 'type', 'content', 'ttl', 'proxied', 'priority'],
   required=['name', 'type', 'content'],
   example={'name': 'app.hermes.example.com', 'type': 'A', 'content': '198.51.100.10', 'ttl': 1})
op('/api/v1/dns/{id}', 'GET', 'Read DNS record after current-name scope check', 'DNS')
op('/api/v1/dns/{id}', 'PATCH', 'Replace DNS record; old and new names checked', 'DNS',
   body=['name', 'type', 'content', 'ttl', 'proxied', 'priority'],
   required=['name', 'type', 'content'])
op('/api/v1/dns/{id}', 'DELETE', 'Delete scoped DNS record', 'DNS')
op('/api/v1/tunnels', 'GET', 'List tunnels created by this bridge for client', 'Tunnels')
op('/api/v1/tunnels', 'POST', 'Create remotely managed dedicated tunnel', 'Tunnels',
   body=['name'], required=['name'], example={'name': 'backend'})
op('/api/v1/tunnels/{id}', 'GET', 'Read owned tunnel information', 'Tunnels')
op('/api/v1/tunnels/{id}', 'DELETE', 'Delete empty owned tunnel', 'Tunnels')
op('/api/v1/tunnels/{id}/token', 'GET', 'Retrieve connector token for owned tunnel; sensitive', 'Tunnels')
op('/api/v1/tunnels/{id}/hostnames', 'GET', 'List managed ingress hostnames on tunnel', 'Tunnels')
op('/api/v1/tunnels/{id}/hostnames', 'POST', 'Publish scoped hostname; create proxied CNAME and ingress', 'Tunnels',
   body=['hostname', 'service'], required=['hostname', 'service'],
   example={'hostname': 'app.hermes.example.com', 'service': 'http://localhost:8080'})
op('/api/v1/tunnels/{id}/hostnames/{hostname}', 'DELETE', 'Unpublish hostname and managed DNS record', 'Tunnels')
op('/api/v1/workers', 'GET', 'List owned Workers', 'Workers')
op('/api/v1/workers', 'POST', 'Upload module Worker without external bindings; public worker subdomain disabled', 'Workers',
   body=['label', 'script'], required=['label', 'script'],
   example={'label': 'hello', 'script': 'export default {async fetch(){return new Response("ok")}}'})
op('/api/v1/workers/{id}', 'PUT', 'Replace script of owned Worker', 'Workers',
   body=['script'], required=['script'])
op('/api/v1/workers/{id}', 'DELETE', 'Delete owned Worker after routes removed', 'Workers')
op('/api/v1/workers/{id}/routes', 'POST', 'Create scoped host-only Worker route', 'Workers',
   body=['hostname'], required=['hostname'], example={'hostname': 'service.hermes.example.com'})
op('/api/v1/workers/routes', 'GET', 'List owned Worker routes', 'Workers')
op('/api/v1/workers/routes/{id}', 'DELETE', 'Delete owned Worker route after drift check', 'Workers')
op('/api/v1/email', 'GET', 'List owned literal-address Email Routing rules', 'Email')
op('/api/v1/email', 'POST', 'Create literal-address forward, drop or owned Worker rule', 'Email',
   body=['address', 'action', 'destination'], required=['address', 'action'],
   example={'address': 'support@hermes.example.com', 'action': 'forward', 'destination': 'verified@example.net'})
op('/api/v1/email/{id}', 'DELETE', 'Delete owned email rule after drift check', 'Email')

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
