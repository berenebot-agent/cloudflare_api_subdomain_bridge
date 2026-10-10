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
func TestDuplicateClientNamesRejected(t *testing.T) {
	base := []string{"CF_ACCOUNT_ID=a", "CF_ZONE_ID=z", "CF_ZONE_NAME=example.com", "CF_API_TOKEN=some-token",
		"BRIDGE_CLIENT_A=" + `{"key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","scope":"a.example.com","descendants":true,"permissions":["dns"]}`}
	if _, e := LoadConfigFrom(base); e != nil {
		t.Fatalf("single client rejected: %v", e)
	}
	clash := append(append([]string{}, base...), "BRIDGE_CLIENT_a="+`{"key":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","scope":"b.example.com","descendants":true,"permissions":["dns"]}`)
	if _, e := LoadConfigFrom(clash); e == nil {
		t.Fatal("case-colliding client names accepted")
	}
}

func TestAuthMinimumKeyLength(t *testing.T) {
	short := strings.Repeat("c", 24)
	s, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) { cfok(w, []any{}) })
	s.cfg.Clients = []Client{{Name: "shortkey", Key: short, Scope: "short.example.com", Descendants: true, Permissions: []string{"dns"}}}
	if w := req(s, "GET", "/api/v1/me", short, ""); w.Code != 200 {
		t.Fatalf("24-byte key rejected: %d %s", w.Code, w.Body.String())
	}
	if w := req(s, "GET", "/api/v1/me", strings.Repeat("c", 23), ""); w.Code != 401 {
		t.Fatalf("too-short key accepted: %d", w.Code)
	}
}

func TestScopeRecheckBlocksStaleAuthority(t *testing.T) {
	s, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/zones/zone/workers/routes":
			cfok(w, []any{map[string]any{"id": "r1", "pattern": "app.mail.example.com/*", "script": "cfb-hermes-x"}})
		default:
			cfok(w, map[string]any{"id": "ok"})
		}
	})
	if e := s.store.Put(Resource{Owner: "hermes", Kind: "worker", ID: "cfb-hermes-x", Name: "x"}); e != nil {
		t.Fatal(e)
	}
	w := req(s, "PUT", "/api/v1/workers/cfb-hermes-x", clients[0].Key, `{"script":"export default {fetch(){return new Response('hi')}}"}`)
	if w.Code != 409 {
		t.Fatalf("worker with out-of-scope route updated: %d %s", w.Code, w.Body.String())
	}

	if e := s.store.Put(Resource{Owner: "hermes", Kind: "tunnel", ID: "t1", Name: "t"}); e != nil {
		t.Fatal(e)
	}
	if e := s.store.Put(Resource{Owner: "hermes", Kind: "tunnel_host", ID: "t1|app.mail.example.com", Name: "app.mail.example.com", Details: `{"hostname":"app.mail.example.com","service":"http://x"}`}); e != nil {
		t.Fatal(e)
	}
	w = req(s, "GET", "/api/v1/tunnels/t1/token", clients[0].Key, "")
	if w.Code != 409 {
		t.Fatalf("token for out-of-scope tunnel returned: %d %s", w.Code, w.Body.String())
	}
}

func TestTunnelHostnameDeleteResumes(t *testing.T) {
	dnsPresent := true
	cf := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/accounts/account/cfd_tunnel/t1/configurations":
			cfok(w, map[string]any{"config": map[string]any{"ingress": []any{map[string]any{"service": "http_status:404"}}, "warp-routing": map[string]any{"enabled": false}}})
			return
		case "/zones/zone/dns_records/d1":
			if r.Method == "GET" && dnsPresent {
				cfok(w, map[string]any{"id": "d1", "name": "app.hermes.example.com", "type": "CNAME", "content": "t1.cfargotunnel.com"})
				return
			}
		}
		cfok(w, map[string]any{"ok": true})
	}
	s, _ := newServer(t, cf)
	if e := s.store.Put(Resource{Owner: "hermes", Kind: "tunnel", ID: "t1", Name: "t"}); e != nil {
		t.Fatal(e)
	}
	if e := s.store.Put(Resource{Owner: "hermes", Kind: "tunnel_host", ID: "t1|app.hermes.example.com", Name: "app.hermes.example.com", Details: `{"hostname":"app.hermes.example.com","service":"http://x","dns_id":"d1"}`}); e != nil {
		t.Fatal(e)
	}
	if e := s.store.Put(Resource{Owner: "hermes", Kind: "tunnel_dns", ID: "d1", Name: "app.hermes.example.com"}); e != nil {
		t.Fatal(e)
	}
	// Ingress already lacks the hostname and DNS is gone: a retry must succeed.
	dnsPresent = false
	w := req(s, "DELETE", "/api/v1/tunnels/t1/hostnames/app.hermes.example.com", clients[0].Key, "")
	if w.Code != 200 {
		t.Fatalf("resumable delete failed: %d %s", w.Code, w.Body.String())
	}
	if _, ok, _ := s.store.Get("hermes", "tunnel_dns", "d1"); ok {
		t.Fatal("tunnel_dns guard row not cleaned up")
	}
}

func TestDNSPriorityZeroAndProxiedFalseSerialized(t *testing.T) {
	var got map[string]any
	cf := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			cfok(w, []any{})
			return
		}
		json.NewDecoder(r.Body).Decode(&got)
		cfok(w, map[string]any{"id": "d1", "name": "app.hermes.example.com", "type": "MX", "content": "mx.example.com"})
	}
	s, _ := newServer(t, cf)
	w := req(s, "POST", "/api/v1/dns", clients[0].Key, `{"name":"app.hermes.example.com","type":"MX","content":"mx.example.com","priority":0,"proxied":false}`)
	if w.Code != 201 {
		t.Fatalf("mx create failed: %d %s", w.Code, w.Body.String())
	}
	if p, ok := got["priority"]; !ok || p.(float64) != 0 {
		t.Fatalf("priority 0 not serialized: %v", got["priority"])
	}
	if _, ok := got["proxied"]; !ok {
		t.Fatal("proxied false not serialized")
	}
}

func TestStorePutAllAtomic(t *testing.T) {
	s, e := OpenStore(filepath.Join(t.TempDir(), "db.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.Put(Resource{Owner: "a", Kind: "k", ID: "x", Name: "x"}); e != nil {
		t.Fatal(e)
	}
	e = s.PutAll(
		Resource{Owner: "a", Kind: "k", ID: "y", Name: "y"},
		Resource{Owner: "b", Kind: "k", ID: "x", Name: "x"},
	)
	if e == nil {
		t.Fatal("conflicting PutAll succeeded")
	}
	if _, ok, _ := s.Get("a", "k", "y"); ok {
		t.Fatal("PutAll left a partial write after rollback")
	}
}

func TestStoreGetFailsClosedOnError(t *testing.T) {
	s, e := OpenStore(filepath.Join(t.TempDir(), "db.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.exec("DROP TABLE resources"); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Get("a", "k", "x"); e == nil {
		t.Fatal("Get hid a storage error as not-found")
	}
}

func TestInstanceBinding(t *testing.T) {
	dir := t.TempDir()
	s, e := OpenStore(filepath.Join(dir, "db.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	if e = s.BindInstance("zone1", "acct1"); e != nil {
		t.Fatal(e)
	}
	if e = s.BindInstance("zone1", "acct1"); e != nil {
		t.Fatalf("idempotent rebind rejected: %v", e)
	}
	if e = s.BindInstance("zone2", "acct2"); e == nil {
		t.Fatal("database accepted a different zone/account")
	}
	s.Close()
	s, e = OpenStore(filepath.Join(dir, "db.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.BindInstance("zone2", "acct2"); e == nil {
		t.Fatal("rebinding after reopen accepted a different instance")
	}
}

func TestEmailPaginationPageSize(t *testing.T) {
	var perPage string
	cf := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			cfok(w, map[string]any{"id": "rule1"})
			return
		}
		perPage = r.URL.Query().Get("per_page")
		cfok(w, []any{})
	}
	s, _ := newServer(t, cf)
	w := req(s, "POST", "/api/v1/email", clients[0].Key, `{"address":"team@hermes.example.com","action":"drop"}`)
	if w.Code != 201 {
		t.Fatalf("email create failed: %d %s", w.Code, w.Body.String())
	}
	if perPage != "50" {
		t.Fatalf("email list per_page = %q, want 50", perPage)
	}
}

func TestWorkerMockRejectsUnexpected(t *testing.T) {
	s, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/accounts/account/workers/scripts/cfb-hermes-x":
			if r.Method == http.MethodPut {
				cfok(w, map[string]any{"id": "cfb-hermes-x"})
				return
			}
		case "/accounts/account/workers/scripts/cfb-hermes-x/subdomain":
			cfok(w, map[string]any{"enabled": false})
			return
		case "/zones/zone/workers/routes":
			cfok(w, []any{})
			return
		}
		t.Errorf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
		cfok(w, map[string]any{"id": "unexpected"})
	})
	if e := s.store.Put(Resource{Owner: "hermes", Kind: "worker", ID: "cfb-hermes-x", Name: "x"}); e != nil {
		t.Fatal(e)
	}
	w := req(s, "PUT", "/api/v1/workers/cfb-hermes-x", clients[0].Key, `{"script":"export default {fetch(){return new Response('hi')}}"}`)
	if w.Code != 200 {
		t.Fatalf("worker update failed: %d %s", w.Code, w.Body.String())
	}
}

func TestEmailDriftOnActionChange(t *testing.T) {
	cf := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/zones/zone/email/routing/rules/rule1":
			// Stored rule was forward; Cloudflare now says drop.
			cfok(w, map[string]any{
				"id":       "rule1",
				"matchers": []any{map[string]any{"type": "literal", "field": "to", "value": "team@hermes.example.com"}},
				"actions":  []any{map[string]any{"type": "drop"}},
			})
		default:
			cfok(w, map[string]any{})
		}
	}
	s, _ := newServer(t, cf)
	if e := s.store.Put(Resource{Owner: "hermes", Kind: "email_rule", ID: "rule1", Name: "team@hermes.example.com", Details: "forward:dest@example.net"}); e != nil {
		t.Fatal(e)
	}
	w := req(s, "DELETE", "/api/v1/email/rule1", clients[0].Key, "")
	if w.Code != 409 {
		t.Fatalf("action change not detected: %d %s", w.Code, w.Body.String())
	}
}

func TestDNSManagedRecordFailClosed(t *testing.T) {
	cf := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/zones/zone/dns_records/a1":
			cfok(w, map[string]any{"id": "a1", "name": "app.hermes.example.com", "type": "A", "content": "198.51.100.1"})
		default:
			cfok(w, map[string]any{"ok": true})
		}
	}
	s, _ := newServer(t, cf)
	if e := s.store.exec("DROP TABLE resources"); e != nil {
		t.Fatal(e)
	}
	w := req(s, "DELETE", "/api/v1/dns/a1", clients[0].Key, "")
	if w.Code != 502 {
		t.Fatalf("storage error not surfaced: %d %s", w.Code, w.Body.String())
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

func TestDNSCreateRejectsExistingName(t *testing.T) {
	var mu sync.Mutex
	mutations := 0
	existing := []any{map[string]any{"id": "a1", "name": "app.hermes.example.com", "type": "CNAME", "content": "target.example.net"}}
	cf := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == "GET" {
			cfok(w, existing)
			return
		}
		mutations++
		cfok(w, map[string]any{"id": "new"})
	}
	s, _ := newServer(t, cf)
	w := req(s, "POST", "/api/v1/dns", clients[0].Key, `{"name":"app.hermes.example.com","type":"A","content":"198.51.100.9"}`)
	if w.Code != 409 {
		t.Fatalf("CNAME collision not rejected: %d %s", w.Code, w.Body.String())
	}
	mu.Lock()
	n := mutations
	mu.Unlock()
	if n != 0 {
		t.Fatalf("collision caused %d upstream mutation(s)", n)
	}
}

func TestDNSSameTypeRecordsAllowed(t *testing.T) {
	cases := []struct {
		name     string
		existing []any
		body     string
	}{
		{"second A", []any{map[string]any{"id": "a1", "name": "app.hermes.example.com", "type": "A", "content": "198.51.100.1"}}, `{"name":"app.hermes.example.com","type":"A","content":"198.51.100.2"}`},
		{"AAAA beside A", []any{map[string]any{"id": "a1", "name": "app.hermes.example.com", "type": "A", "content": "198.51.100.1"}}, `{"name":"app.hermes.example.com","type":"AAAA","content":"2001:db8::1"}`},
		{"different TXT", []any{map[string]any{"id": "t1", "name": "app.hermes.example.com", "type": "TXT", "content": "v=spf1 -all"}}, `{"name":"app.hermes.example.com","type":"TXT","content":"verify=abc"}`},
		{"second MX", []any{map[string]any{"id": "m1", "name": "app.hermes.example.com", "type": "MX", "content": "mx1.example.net", "priority": 10}}, `{"name":"app.hermes.example.com","type":"MX","content":"mx2.example.net","priority":20}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cf := func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					cfok(w, tc.existing)
					return
				}
				cfok(w, map[string]any{"id": "new"})
			}
			s, _ := newServer(t, cf)
			w := req(s, "POST", "/api/v1/dns", clients[0].Key, tc.body)
			if w.Code != 201 {
				t.Fatalf("legitimate record rejected: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestDNSCreateRejectsExactDuplicate(t *testing.T) {
	existing := []any{map[string]any{"id": "m1", "name": "app.hermes.example.com", "type": "MX", "content": "mx1.example.net", "priority": 10}}
	cf := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			cfok(w, existing)
			return
		}
		cfok(w, map[string]any{"id": "new"})
	}
	s, _ := newServer(t, cf)
	w := req(s, "POST", "/api/v1/dns", clients[0].Key, `{"name":"app.hermes.example.com","type":"MX","content":"mx1.example.net","priority":10}`)
	if w.Code != 409 {
		t.Fatalf("exact duplicate not rejected: %d %s", w.Code, w.Body.String())
	}
	w = req(s, "POST", "/api/v1/dns", clients[0].Key, `{"name":"app.hermes.example.com","type":"CNAME","content":"target.example.net"}`)
	if w.Code != 409 {
		t.Fatalf("CNAME beside MX not rejected: %d %s", w.Code, w.Body.String())
	}
}

func TestDNSCreateMapsUpstreamConflict(t *testing.T) {
	cf := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			cfok(w, []any{})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "result": nil, "errors": []any{map[string]any{"code": 81057, "message": "Record already exists"}}})
	}
	s, _ := newServer(t, cf)
	w := req(s, "POST", "/api/v1/dns", clients[0].Key, `{"name":"app.hermes.example.com","type":"A","content":"198.51.100.9"}`)
	if w.Code != 409 {
		t.Fatalf("upstream conflict not mapped: %d %s", w.Code, w.Body.String())
	}
}

func TestDNSNonexistentIDReturns404(t *testing.T) {
	cf := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "result": nil, "errors": []any{map[string]any{"code": 81044, "message": "Record not found"}}})
	}
	s, _ := newServer(t, cf)
	for _, method := range []string{"GET", "PATCH", "DELETE"} {
		body := ""
		if method == "PATCH" {
			body = `{"name":"app.hermes.example.com","type":"A","content":"198.51.100.3"}`
		}
		w := req(s, method, "/api/v1/dns/00000000000000000000000000000000", clients[0].Key, body)
		if w.Code != 404 {
			t.Fatalf("%s nonexistent id: got %d %s", method, w.Code, w.Body.String())
		}
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
				cfok(w, map[string]any{"config": map[string]any{"ingress": []any{map[string]any{"service": "http_status:404"}}, "warp-routing": map[string]any{"enabled": false}}})
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

func TestTunnelTokenRefusesConfigDrift(t *testing.T) {
	tokenCalled := false
	cf := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/accounts/account/cfd_tunnel/t1/configurations":
			// Live tunnel has no published ingress, but the bridge has a stored
			// hostname: the configuration has drifted.
			cfok(w, map[string]any{"config": map[string]any{"ingress": []any{map[string]any{"service": "http_status:404"}}, "warp-routing": map[string]any{"enabled": false}}})
		case "/accounts/account/cfd_tunnel/t1/token":
			tokenCalled = true
			cfok(w, "secret-connector-token")
		default:
			cfok(w, map[string]any{"ok": true})
		}
	}
	s, _ := newServer(t, cf)
	if e := s.store.Put(Resource{Owner: "hermes", Kind: "tunnel", ID: "t1", Name: "t"}); e != nil {
		t.Fatal(e)
	}
	if e := s.store.Put(Resource{Owner: "hermes", Kind: "tunnel_host", ID: "t1|app.hermes.example.com", Name: "app.hermes.example.com", Details: `{"hostname":"app.hermes.example.com","service":"http://x"}`}); e != nil {
		t.Fatal(e)
	}
	w := req(s, "GET", "/api/v1/tunnels/t1/token", clients[0].Key, "")
	if w.Code != 409 {
		t.Fatalf("token issued despite drift: %d %s", w.Code, w.Body.String())
	}
	if tokenCalled {
		t.Fatal("token endpoint reached despite drift")
	}
}

func TestRuleMatchesWorkerDestination(t *testing.T) {
	mk := func(action string, values ...string) json.RawMessage {
		b, _ := json.Marshal(map[string]any{
			"matchers": []any{map[string]any{"type": "literal", "field": "to", "value": "team@hermes.example.com"}},
			"actions":  []any{map[string]any{"type": action, "value": values}},
		})
		return b
	}
	cases := []struct {
		name    string
		raw     json.RawMessage
		details string
		want    bool
	}{
		{"worker match", mk("worker", "w1"), "worker:w1", true},
		{"worker changed", mk("worker", "w2"), "worker:w1", false},
		{"worker extra destination", mk("worker", "w1", "w2"), "worker:w1", false},
		{"worker missing destination", mk("worker"), "worker:w1", false},
		{"worker action change", mk("forward", "d@example.net"), "worker:w1", false},
		{"forward match", mk("forward", "d@example.net"), "forward:d@example.net", true},
		{"forward case-insensitive", mk("forward", "D@Example.net"), "forward:d@example.net", true},
		{"forward extra destination", mk("forward", "d@example.net", "e@example.net"), "forward:d@example.net", false},
		{"drop", mk("drop"), "drop:", true},
		{"drop with destination", mk("drop", "d@example.net"), "drop:", false},
	}
	for _, tc := range cases {
		if got := ruleMatchesDetails(tc.raw, tc.details); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestEmailWorkerDestinationDrift(t *testing.T) {
	cf := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/zones/zone/email/routing/rules/rule1":
			cfok(w, map[string]any{
				"id":       "rule1",
				"matchers": []any{map[string]any{"type": "literal", "field": "to", "value": "team@hermes.example.com"}},
				"actions":  []any{map[string]any{"type": "worker", "value": []string{"some-other-worker"}}},
			})
		default:
			cfok(w, map[string]any{})
		}
	}
	s, _ := newServer(t, cf)
	if e := s.store.Put(Resource{Owner: "hermes", Kind: "email_rule", ID: "rule1", Name: "team@hermes.example.com", Details: "worker:w1"}); e != nil {
		t.Fatal(e)
	}
	w := req(s, "DELETE", "/api/v1/email/rule1", clients[0].Key, "")
	if w.Code != 409 {
		t.Fatalf("worker destination change not detected: %d %s", w.Code, w.Body.String())
	}
}

func TestWorkerCreateRollsBackOnPersistFailure(t *testing.T) {
	deleted := false
	cf := func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/workers/scripts/"):
			deleted = true
			cfok(w, map[string]any{"ok": true})
		case strings.HasSuffix(r.URL.Path, "/subdomain"):
			cfok(w, map[string]any{"enabled": false})
		default:
			cfok(w, map[string]any{"id": "cfb-hermes-x"})
		}
	}
	s, _ := newServer(t, cf)
	if e := s.store.exec("DROP TABLE resources"); e != nil {
		t.Fatal(e)
	}
	w := req(s, "POST", "/api/v1/workers", clients[0].Key, `{"label":"x","script":"export default {fetch(){return new Response('hi')}}"}`)
	if w.Code != 502 {
		t.Fatalf("persist failure not surfaced: %d %s", w.Code, w.Body.String())
	}
	if !deleted {
		t.Fatal("orphaned Worker was not rolled back")
	}
}

// TestTunnelDisabledWarpRoutingDoesNotBlock reproduces the live Cloudflare
// response shape: every remotely-managed tunnel returns a "warp-routing" object
// even when the feature is off. Treating the mere presence of that key as drift
// made publish, token and delete fail with 409 for every tunnel the bridge
// created itself.
func TestTunnelDisabledWarpRoutingDoesNotBlock(t *testing.T) {
	// Track the live ingress so a publish is reflected on the next config read,
	// as Cloudflare would.
	ingress := []any{map[string]any{"service": "http_status:404"}}
	cf := func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/accounts/account/cfd_tunnel":
			if r.Method == "POST" {
				cfok(w, map[string]any{"id": "t1"})
				return
			}
			cfok(w, []any{})
		case strings.HasSuffix(r.URL.Path, "/configurations"):
			if r.Method == "GET" {
				// Exactly what Cloudflare returns: the warp-routing object is
				// present even though the feature is off.
				cfok(w, map[string]any{"config": map[string]any{
					"ingress":      ingress,
					"warp-routing": map[string]any{"enabled": false},
				}})
				return
			}
			var body struct {
				Config struct {
					Ingress []any `json:"ingress"`
				} `json:"config"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if len(body.Config.Ingress) > 0 {
				ingress = body.Config.Ingress
			}
			cfok(w, map[string]any{"ok": true})
		case strings.HasSuffix(r.URL.Path, "/token"):
			cfok(w, "secret-connector-token")
		case strings.Contains(r.URL.Path, "/dns_records"):
			if r.Method == "GET" {
				cfok(w, []any{})
				return
			}
			cfok(w, map[string]any{"id": "d1", "name": "app.hermes.example.com", "type": "CNAME", "content": "t1.cfargotunnel.com"})
		default:
			cfok(w, map[string]any{"id": "t1"})
		}
	}
	s, _ := newServer(t, cf)
	w := req(s, "POST", "/api/v1/tunnels", clients[0].Key, `{"name":"backend"}`)
	if w.Code != 201 {
		t.Fatalf("tunnel create failed: %d %s", w.Code, w.Body.String())
	}

	// Publish a hostname: the disabled warp-routing field must not read as drift.
	w = req(s, "POST", "/api/v1/tunnels/t1/hostnames", clients[0].Key, `{"hostname":"app.hermes.example.com","service":"http://127.0.0.1:8080"}`)
	if w.Code != 201 {
		t.Fatalf("publish blocked by disabled warp-routing: %d %s", w.Code, w.Body.String())
	}

	// Fetch a connector token: same guard, same requirement.
	w = req(s, "GET", "/api/v1/tunnels/t1/token", clients[0].Key, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "secret-connector-token") {
		t.Fatalf("token blocked by disabled warp-routing: %d %s", w.Code, w.Body.String())
	}
}

// TestTunnelEnabledWarpRoutingStillBlocks pins the guard's real purpose: an
// actual enabled warp-routing configuration must still refuse the operation.
func TestTunnelEnabledWarpRoutingStillBlocks(t *testing.T) {
	cf := func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/configurations"):
			cfok(w, map[string]any{"config": map[string]any{
				"ingress":      []any{map[string]any{"service": "http_status:404"}},
				"warp-routing": map[string]any{"enabled": true},
			}})
		default:
			cfok(w, map[string]any{"id": "t1"})
		}
	}
	s, _ := newServer(t, cf)
	if e := s.store.Put(Resource{Owner: "hermes", Kind: "tunnel", ID: "t1", Name: "t"}); e != nil {
		t.Fatal(e)
	}
	w := req(s, "DELETE", "/api/v1/tunnels/t1", clients[0].Key, "")
	if w.Code != 409 {
		t.Fatalf("enabled warp-routing did not block delete: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "warp-routing") {
		t.Fatalf("wrong refusal reason: %s", w.Body.String())
	}
}

// TestWarpRoutingEnabledShapes pins the decoder directly, including the
// fail-closed path for a shape the bridge does not recognise.
func TestWarpRoutingEnabledShapes(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{``, false},
		{`null`, false},
		{`{}`, false},
		{`[]`, false},
		{`{"enabled":false}`, false},
		{`{"enabled":true}`, true},
		{`{"enabled":false,"unknown":1}`, false},
		{`{"enabled":true,"unknown":1}`, true},
		{`"unexpected"`, true}, // unrecognised shape fails closed
	}
	for _, c := range cases {
		if got := warpRoutingEnabled(json.RawMessage(c.raw)); got != c.want {
			t.Errorf("warpRoutingEnabled(%s) = %v, want %v", c.raw, got, c.want)
		}
	}
}
