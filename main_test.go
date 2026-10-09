package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var clients = []Client{
	{Name: "hermes", Key: strings.Repeat("a", 32), Scope: "hermes.example.com", Descendants: true, Permissions: []string{"dns", "workers", "tunnels", "email"}},
	{Name: "mail", Key: strings.Repeat("b", 32), Scope: "mail.example.com", Descendants: true, Permissions: []string{"dns", "workers", "tunnels", "email"}},
}

func newServer(t *testing.T, upstream http.HandlerFunc) (*Server, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	db, e := OpenStore(filepath.Join(dir, "bridge.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(db.Close)
	up := httptest.NewServer(upstream)
	t.Cleanup(up.Close)
	s := &Server{cfg: Config{ZoneID: "zone", AccountID: "account", ZoneName: "example.com", Clients: clients}, cf: &Cloudflare{Base: up.URL, Token: "fake-upstream"}, store: db}
	return s, up
}
func req(s *Server, method, path, token, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.route(w, r)
	return w
}
func cfok(w http.ResponseWriter, result any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
}
func TestConfigValidAndOverlaps(t *testing.T) {
	env := []string{"CF_ACCOUNT_ID=a", "CF_ZONE_ID=z", "CF_ZONE_NAME=example.com", "CF_API_TOKEN=some-token", "BRIDGE_CLIENT_A=" + `{"key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","scope":"a.example.com","descendants":true,"permissions":["dns"]}`}
	c, e := LoadConfigFrom(env)
	if e != nil || len(c.Clients) != 1 {
		t.Fatalf("valid config: %v", e)
	}
	fail := func(add string) {
		t.Helper()
		_, e := LoadConfigFrom(append(append([]string{}, env...), add))
		if e == nil {
			t.Fatalf("overlap or key reuse accepted: %s", add)
		}
	}
	fail("BRIDGE_CLIENT_B=" + `{"key":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","scope":"child.a.example.com","descendants":false,"permissions":["dns"]}`)
	fail("BRIDGE_CLIENT_B=" + `{"key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","scope":"b.example.com","descendants":false,"permissions":["dns"]}`)
	fail("BRIDGE_CLIENT_B=" + `{"key":"REPLACE_WITH_A_LONG_RANDOM_CLIENT_KEY","scope":"b.example.com","descendants":false,"permissions":["dns"]}`)
	for _, host := range []string{"evil.example.com.hermes.example.org", "*.hermes.example.com", "evil..hermes.example.com", "hermes.example.com.", "hermes.example.com:443"} {
		if validHost(host) && inside(host, clients[0]) {
			t.Errorf("accepted %q", host)
		}
	}
	if inside("not-hermes.example.com", clients[0]) {
		t.Fatal("substring bypass")
	}
}
func TestDNSIsolationAndMutations(t *testing.T) {
	var mu sync.Mutex
	mutations := 0
	cf := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method != "GET" {
			mutations++
		}
		switch r.URL.Path {
		case "/zones/zone/dns_records":
			cfok(w, []any{map[string]any{"id": "a1", "name": "app.hermes.example.com", "type": "A", "content": "198.51.100.1"}, map[string]any{"id": "b1", "name": "mail.example.com", "type": "A", "content": "198.51.100.2"}})
		case "/zones/zone/dns_records/a1":
			cfok(w, map[string]any{"id": "a1", "name": "app.hermes.example.com", "type": "A", "content": "198.51.100.1"})
		case "/zones/zone/dns_records/b1":
			cfok(w, map[string]any{"id": "b1", "name": "mail.example.com", "type": "A", "content": "198.51.100.2"})
		default:
			cfok(w, map[string]any{"id": "other"})
		}
	}
	s, _ := newServer(t, cf)
	token := clients[0].Key
	w := req(s, "GET", "/api/v1/dns", token, "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "mail.example.com") {
		t.Fatalf("list leaked data: %d %s", w.Code, w.Body.String())
	}
	w = req(s, "PATCH", "/api/v1/dns/b1", token, `{"name":"app.hermes.example.com","type":"A","content":"198.51.100.3"}`)
	if w.Code != 403 {
		t.Fatalf("foreign record patched: %d", w.Code)
	}
	w = req(s, "PATCH", "/api/v1/dns/a1", token, `{"name":"mail.example.com","type":"A","content":"198.51.100.3"}`)
	if w.Code != 403 {
		t.Fatalf("record moved out of scope: %d", w.Code)
	}
	w = req(s, "POST", "/api/v1/dns", token, `{"name":"evilhermes.example.com","type":"A","content":"198.51.100.3"}`)
	if w.Code != 403 {
		t.Fatalf("prefix trick accepted: %d", w.Code)
	}
	w = req(s, "GET", "/api/v1/dns/a1", clients[1].Key, "")
	if w.Code != 403 {
		t.Fatal("client mail accessed hermes record")
	}
	mu.Lock()
	n := mutations
	mu.Unlock()
	if n != 0 {
		t.Errorf("out-of-scope request caused %d upstream mutations", n)
	}
	if e := s.store.Put(Resource{Owner: "hermes", Kind: "tunnel_dns", ID: "a1", Name: "app.hermes.example.com"}); e != nil {
		t.Fatal(e)
	}
	w = req(s, "DELETE", "/api/v1/dns/a1", token, "")
	if w.Code != 409 {
		t.Fatalf("managed tunnel DNS deleted: %d", w.Code)
	}
}
func TestTunnelOwnershipAndToken(t *testing.T) {
	calls := 0
	cf := func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch r.URL.Path {
		case "/accounts/account/cfd_tunnel":
			cfok(w, map[string]any{"id": "tunnel-123"})
		case "/accounts/account/cfd_tunnel/tunnel-123/configurations":
			if r.Method == "GET" {
				cfok(w, map[string]any{"config": map[string]any{"ingress": []any{map[string]any{"service": "http_status:404"}}}})
			} else {
				cfok(w, map[string]any{"ok": true})
			}
		case "/accounts/account/cfd_tunnel/tunnel-123/token":
			cfok(w, "secret-connector-token")
		case "/accounts/account/cfd_tunnel/tunnel-123":
			cfok(w, map[string]any{"id": "tunnel-123"})
		default:
			cfok(w, map[string]any{"id": "random"})
		}
	}
	s, _ := newServer(t, cf)
	w := req(s, "POST", "/api/v1/tunnels", clients[0].Key, `{"name":"backend"}`)
	if w.Code != 201 {
		t.Fatalf("create failed: %d %s", w.Code, w.Body.String())
	}
	before := calls
	for _, path := range []string{"/api/v1/tunnels/tunnel-123", "/api/v1/tunnels/tunnel-123/token"} {
		w = req(s, "GET", path, clients[1].Key, "")
		if w.Code != 404 {
			t.Errorf("foreign tunnel visible: %d %s", w.Code, path)
		}
	}
	if calls != before {
		t.Errorf("foreign client triggered upstream Cloudflare calls")
	}
	w = req(s, "GET", "/api/v1/tunnels/tunnel-123/token", clients[0].Key, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "secret-connector-token") {
		t.Fatalf("owner denied token: %d %s", w.Code, w.Body.String())
	}
	w = req(s, "POST", "/api/v1/tunnels/tunnel-123/hostnames", clients[0].Key, `{"hostname":"app.mail.example.com","service":"http://localhost:8080"}`)
	if w.Code != 403 {
		t.Fatalf("out of scope tunnel hostname accepted: %d", w.Code)
	}
	w = req(s, "POST", "/api/v1/tunnels/tunnel-123/hostnames", clients[0].Key, `{"hostname":"app.hermes.example.com","service":"file:///etc/passwd"}`)
	if w.Code != 400 {
		t.Fatalf("unwanted service accepted: %d", w.Code)
	}
}
func TestWorkerAndEmailOwnership(t *testing.T) {
	cf := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/zones/zone/workers/routes", "/zones/zone/email/routing/rules":
			cfok(w, []any{})
		case "/accounts/account/workers/scripts/cfb-hermes-123/subdomain":
			cfok(w, map[string]any{"enabled": false})
		default:
			cfok(w, map[string]any{"id": "id123"})
		}
	}
	s, _ := newServer(t, cf)
	w := req(s, "POST", "/api/v1/workers", clients[0].Key, `{"label":"hello","script":"export default {fetch(){return new Response('ok')}}"}`)
	if w.Code != 201 {
		t.Fatalf("Worker creation failed: %d %s", w.Code, w.Body.String())
	}
	var body struct {
		ID string `json:"id"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &body); e != nil {
		t.Fatal(e)
	}
	w = req(s, "POST", "/api/v1/workers/"+body.ID+"/routes", clients[1].Key, `{"hostname":"app.mail.example.com"}`)
	if w.Code != 404 {
		t.Errorf("client 2 routed client 1 Worker: %d", w.Code)
	}
	w = req(s, "POST", "/api/v1/workers/"+body.ID+"/routes", clients[0].Key, `{"hostname":"app.mail.example.com"}`)
	if w.Code != 403 {
		t.Errorf("own Worker routed out of scope: %d", w.Code)
	}
	w = req(s, "POST", "/api/v1/email", clients[0].Key, `{"address":"team@mail.example.com","action":"drop"}`)
	if w.Code != 403 {
		t.Errorf("client 1 captured client 2 mail: %d", w.Code)
	}
	w = req(s, "POST", "/api/v1/email", clients[0].Key, `{"address":"team@hermes.example.com","action":"worker","destination":"someone-elses-worker"}`)
	if w.Code != 403 {
		t.Errorf("unowned Email Worker accepted: %d", w.Code)
	}
}
func TestDocsAndAuth(t *testing.T) {
	s, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) { cfok(w, []any{}) })
	for _, p := range []string{"/docs", "/openapi.json", "/healthz"} {
		w := req(s, "GET", p, "", "")
		if w.Code != 200 {
			t.Errorf("doc endpoint %s not available: %d", p, w.Code)
		}
	}
	w := req(s, "GET", "/api/v1/me", "", "")
	if w.Code != 401 {
		t.Fatal("unauthenticated API access")
	}
	w = req(s, "GET", "/api/v1/me", clients[0].Key, "")
	if w.Code != 200 {
		t.Fatal("authenticated me failed")
	}
}
func TestStorePersistentOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.sqlite")
	s, e := OpenStore(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Put(Resource{Owner: "hermes", Kind: "tunnel", ID: "xx", Name: "t"}); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = OpenStore(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	_, ok, e := s.Get("hermes", "tunnel", "xx")
	if e != nil || !ok {
		t.Fatal("missing persisted ownership record")
	}
	_, ok, e = s.Get("mail", "tunnel", "xx")
	if e != nil || ok {
		t.Fatal("foreign ownership permitted")
	}

}
