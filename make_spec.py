#!/usr/bin/env python3
"""Generate the checked-in OpenAPI document. Requires Python stdlib only."""
import json
from pathlib import Path
P={}
def op(path,method,summary,tag,body=None,example=None,desc=None):
    item={'summary':summary,'tags':[tag],'responses':{'200':{'description':'Operation successful'},'201':{'description':'Resource created'},'400':{'description':'Invalid request'},'401':{'description':'Invalid or missing Bearer key'},'403':{'description':'Outside scope or feature not granted'},'409':{'description':'Resource conflict or configuration drift'},'502':{'description':'Upstream or storage operation failed'}}}
    if desc:item['description']=desc
    if body:
        item['requestBody']={'required':True,'content':{'application/json':{'schema':{'type':'object','properties':{k:{'type':v} for k,v in body.items()},'required':list(body)}}}}
    if example:item['x-example']=example
    for v in [p[1:-1] for p in path.split('/') if p.startswith('{') and p.endswith('}')]:
        pass
    params=[v[1:-1] for v in path.split('/') if v.startswith('{') and v.endswith('}')]
    if params:item['parameters']=[{'in':'path','name':v,'required':True,'schema':{'type':'string'}} for v in params]
    if path not in ['/healthz','/openapi.json','/docs']:item['security']=[{'bearerAuth':[]}]
    P.setdefault(path,{})[method.lower()]=item
op('/healthz','GET','Process health check','System')
op('/api/v1/me','GET','Authenticated client scope and capabilities','System')
op('/api/v1/dns','GET','List DNS records under client scope','DNS')
op('/api/v1/dns','POST','Create scoped DNS record','DNS',{'name':'string','type':'string','content':'string','ttl':'integer','proxied':'boolean'},{'name':'app.hermes.example.com','type':'A','content':'198.51.100.10','ttl':1,'proxied':False})
op('/api/v1/dns/{id}','GET','Read DNS record after current-name scope check','DNS')
op('/api/v1/dns/{id}','PATCH','Replace DNS record; old and new names checked','DNS',{'name':'string','type':'string','content':'string','ttl':'integer','proxied':'boolean'})
op('/api/v1/dns/{id}','DELETE','Delete scoped DNS record','DNS')
op('/api/v1/tunnels','GET','List tunnels created by this bridge for client','Tunnels')
op('/api/v1/tunnels','POST','Create remotely managed dedicated tunnel','Tunnels',{'name':'string'},{'name':'backend'})
op('/api/v1/tunnels/{id}','GET','Read owned tunnel information','Tunnels')
op('/api/v1/tunnels/{id}','DELETE','Delete empty owned tunnel','Tunnels')
op('/api/v1/tunnels/{id}/token','GET','Retrieve connector token for owned tunnel; sensitive','Tunnels')
op('/api/v1/tunnels/{id}/hostnames','GET','List managed ingress hostnames on tunnel','Tunnels')
op('/api/v1/tunnels/{id}/hostnames','POST','Publish scoped hostname; create proxied CNAME and ingress','Tunnels',{'hostname':'string','service':'string'},{'hostname':'app.hermes.example.com','service':'http://localhost:8080'})
op('/api/v1/tunnels/{id}/hostnames/{hostname}','DELETE','Unpublish hostname and managed DNS record','Tunnels')
op('/api/v1/workers','GET','List owned Workers','Workers')
op('/api/v1/workers','POST','Upload module Worker without external bindings; public worker subdomain disabled','Workers',{'label':'string','script':'string'},{'label':'hello','script':'export default {async fetch(){return new Response("ok")}}'})
op('/api/v1/workers/{id}','PUT','Replace script of owned Worker','Workers',{'script':'string'})
op('/api/v1/workers/{id}','DELETE','Delete owned Worker after routes removed','Workers')
op('/api/v1/workers/{id}/routes','POST','Create scoped host-only Worker route','Workers',{'hostname':'string'},{'hostname':'service.hermes.example.com'})
op('/api/v1/workers/routes','GET','List owned Worker routes','Workers')
op('/api/v1/workers/routes/{id}','DELETE','Delete owned Worker route after drift check','Workers')
op('/api/v1/email','GET','List owned literal-address Email Routing rules','Email')
op('/api/v1/email','POST','Create literal-address forward, drop or owned Worker rule','Email',{'address':'string','action':'string','destination':'string'},{'address':'support@hermes.example.com','action':'forward','destination':'verified@example.net'})
op('/api/v1/email/{id}','DELETE','Delete owned email rule after drift check','Email')
spec={'openapi':'3.1.0','info':{'title':'Cloudflare Subdomain Bridge','version':'1.0.0-alpha','description':'Self-hosted, API-only Cloudflare subdomain permissions bridge. Credentials and scopes are env-only. Do not expose unauthenticated over public HTTP. See README for limits.'},'servers':[{'url':'/'}],'tags':[{'name':x} for x in ['System','DNS','Tunnels','Workers','Email']],'components':{'securitySchemes':{'bearerAuth':{'type':'http','scheme':'bearer','bearerFormat':'API key'}}},'paths':P}
Path(__file__).with_name('openapi.json').write_text(json.dumps(spec,indent=2)+'\n')
