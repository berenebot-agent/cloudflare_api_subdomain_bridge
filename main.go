package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Server struct {
	cfg    Config
	cf     *Cloudflare
	store  *Store
	mu     sync.Mutex
	rateMu sync.Mutex
	rates  map[string][]time.Time
}
type apiError struct {
	Status  int
	Message string
}

func bad(status int, msg string) error { return apiError{status, msg} }
func (e apiError) Error() string       { return e.Message }
func send(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func failure(w http.ResponseWriter, e error) {
	var a apiError
	if errors.As(e, &a) {
		send(w, a.Status, map[string]any{"error": a.Message})
		return
	}
	log.Printf("operation failed: %v", e)
	send(w, 502, map[string]any{"error": "upstream or storage operation failed; see server logs"})
}
func decode(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1024*1024)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return bad(400, "invalid JSON body: "+err.Error())
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return bad(400, "expected one JSON object")
	}
	return nil
}
func secureKey(token, expected string) bool {
	a := sha256.Sum256([]byte(token))
	b := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}
func (s *Server) authenticate(r *http.Request) (Client, error) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return Client{}, bad(401, "Bearer API key required")
	}
	t := strings.TrimPrefix(h, "Bearer ")
	if len(t) < 24 {
		return Client{}, bad(401, "invalid API key")
	}
	var c Client
	match := 0
	for _, x := range s.cfg.Clients {
		if secureKey(t, x.Key) {
			c = x
			match++
		}
	}
	if match != 1 {
		return Client{}, bad(401, "invalid API key")
	}
	return c, nil
}
func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.URL.Path == "/healthz" {
		if r.Method != "GET" {
			failure(w, bad(405, "method not allowed"))
			return
		}
		send(w, 200, map[string]any{"status": "ok"})
		return
	}
	if r.URL.Path == "/openapi.json" && r.Method == "GET" {
		serveSpec(w)
		return
	}
	if (r.URL.Path == "/docs" || r.URL.Path == "/") && r.Method == "GET" {
		serveDocs(w)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/v1/") {
		failure(w, bad(404, "not found"))
		return
	}
	c, e := s.authenticate(r)
	if e != nil {
		s.auditDenied("", r, 401)
		failure(w, e)
		return
	}
	if !s.rateAllow(c.Name) {
		s.auditDenied(c.Name, r, 429)
		failure(w, bad(429, "rate limit exceeded"))
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/"), "/")
	if len(parts) > 5 {
		s.auditDenied(c.Name, r, 404)
		failure(w, bad(404, "not found"))
		return
	}
	permission := parts[0]
	if permission != "me" && !hasPermission(c, permission) {
		s.auditDenied(c.Name, r, 403)
		failure(w, bad(403, "capability not granted"))
		return
	}
	if r.Method != "GET" {
		s.mu.Lock()
		defer s.mu.Unlock()
	}
	status := 200
	var result any
	switch parts[0] {
	case "me":
		if len(parts) != 1 || r.Method != "GET" {
			e = bad(405, "method not allowed")
		} else {
			result = map[string]any{"client": c.Name, "scope": c.Scope, "descendants": c.Descendants, "permissions": c.Permissions}
		}
	case "dns":
		status, result, e = s.dns(r, c, parts)
	case "tunnels":
		status, result, e = s.tunnels(r, c, parts)
	case "workers":
		status, result, e = s.workers(r, c, parts)
	case "email":
		status, result, e = s.email(r, c, parts)
	default:
		e = bad(404, "not found")
	}
	if e != nil {
		var a apiError
		if errors.As(e, &a) {
			status = a.Status
		} else {
			status = 502
		}
		failure(w, e)
	} else {
		send(w, status, result)
	}
	if ae := s.store.Audit(c.Name, r.Method, r.URL.Path, status); ae != nil {
		log.Printf("audit write failed: %v", ae)
	}
}

// auditDenied records an early rejection (bad key, rate limit, missing
// capability) so authentication and authorization failures leave a trail.
func (s *Server) auditDenied(client string, r *http.Request, status int) {
	if s.store == nil {
		return
	}
	if ae := s.store.Audit(client, r.Method, r.URL.Path, status); ae != nil {
		log.Printf("audit write failed: %v", ae)
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
		host, _, e := net.SplitHostPort(r.RemoteAddr)
		if e != nil {
			host = r.RemoteAddr
		}
		if host == "127.0.0.1" || host == "::1" {
			return
		}
		log.Printf("%s %s %s -> %d %s", host, r.Method, r.URL.Path, rec.status, time.Since(start).Round(time.Millisecond))
	})
}
func (s *Server) rateAllow(name string) bool {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	if s.rates == nil {
		s.rates = make(map[string][]time.Time)
	}
	now := time.Now()
	cutoff := now.Add(-time.Minute)
	kept := s.rates[name][:0]
	for _, t := range s.rates[name] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	limit := s.cfg.RatePerMin
	if limit == 0 {
		limit = 120
	}
	if len(kept) >= limit {
		s.rates[name] = kept
		return false
	}
	s.rates[name] = append(kept, now)
	return true
}
func (s *Server) scope(host string, c Client) error {
	if !validHost(host) || !inside(host, c) {
		return bad(403, "hostname outside assigned scope")
	}
	return nil
}

// hostFromPattern recovers the hostname from the exact "host/*" Worker route
// pattern the bridge creates.
func hostFromPattern(pattern string) string { return strings.TrimSuffix(pattern, "/*") }

// workerRoutesInScope fails when a Worker is still routed to a hostname outside
// the caller's current scope. It stops a client whose scope changed (or shrank)
// from mutating a Worker that now serves another client's namespace.
func (s *Server) workerRoutesInScope(r *http.Request, c Client, script string) error {
	existing, e := s.cf.all(r.Context(), s.zone("/workers/routes"))
	if e != nil {
		return e
	}
	for _, v := range existing {
		var x struct {
			Pattern string `json:"pattern"`
			Script  string `json:"script"`
		}
		if json.Unmarshal(v, &x) == nil && x.Script == script {
			if e := s.scope(hostFromPattern(x.Pattern), c); e != nil {
				return bad(409, "Worker is routed to a hostname outside your current scope; reconcile before changing it")
			}
		}
	}
	return nil
}

var resourceID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

func validateID(id string) error {
	if !resourceID.MatchString(id) {
		return bad(400, "invalid resource identifier")
	}
	return nil
}
func (s *Server) owned(c Client, kind, id string) (Resource, error) {
	if err := validateID(id); err != nil {
		return Resource{}, err
	}
	item, ok, e := s.store.Get(c.Name, kind, id)
	if e != nil {
		return Resource{}, e
	}
	if !ok {
		return Resource{}, bad(404, "resource not owned by client")
	}
	return item, nil
}

// advisoryScopeCheck logs (but does not block) when stored resources carry
// hostnames outside the owning client's current scope, which usually means a
// client scope changed without a matching migration.
func (s *Server) advisoryScopeCheck() {
	rows, e := s.store.ListAll()
	if e != nil {
		log.Printf("scope advisory check skipped: %v", e)
		return
	}
	byName := map[string]Client{}
	for _, c := range s.cfg.Clients {
		byName[c.Name] = c
	}
	for _, row := range rows {
		c, ok := byName[row.Owner]
		if !ok {
			log.Printf("WARNING: stored %s %q is owned by unknown client %q (client removed?)", row.Kind, row.Name, row.Owner)
			continue
		}
		if row.Kind == "tunnel_dns" || row.Kind == "tunnel_host" || row.Kind == "worker_route" || row.Kind == "email_rule" {
			host := hostFromPattern(row.Name)
			if row.Kind == "email_rule" {
				if at := strings.LastIndex(row.Name, "@"); at >= 0 {
					host = row.Name[at+1:]
				}
			}
			if validHost(host) && !inside(host, c) {
				log.Printf("WARNING: stored %s %q for client %q is outside its current scope %q; reconcile or clear BRIDGE_DATA_DIR", row.Kind, row.Name, row.Owner, c.Scope)
			}
		}
	}
}

func randomID() string {
	b := make([]byte, 10)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func (s *Server) zone(p string) string    { return "/zones/" + enc(s.cfg.ZoneID) + p }
func (s *Server) account(p string) string { return "/accounts/" + enc(s.cfg.AccountID) + p }
func cfID(raw json.RawMessage) (string, error) {
	var v struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &v) != nil || v.ID == "" {
		return "", errors.New("missing Cloudflare resource ID")
	}
	return v.ID, nil
}
func parsed[T any](raw json.RawMessage) (T, error) {
	var v T
	e := json.Unmarshal(raw, &v)
	return v, e
}
func main() {
	if len(os.Args) == 2 && os.Args[1] == "--healthcheck" {
		port := os.Getenv("BRIDGE_PORT")
		if port == "" {
			port = "8080"
		}
		resp, e := (&http.Client{Timeout: 3 * time.Second}).Get("http://127.0.0.1:" + port + "/healthz")
		if e != nil || resp.StatusCode != 200 {
			os.Exit(1)
		}
		resp.Body.Close()
		return
	}
	c, e := LoadConfig()
	if e != nil {
		const bar = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
		log.Printf("\n%s\n!! CONFIGURATION ERROR - refusing to start\n!! %v\n%s", bar, e, bar)
		os.Exit(1)
	}
	if e = os.MkdirAll(c.DataDir, 0700); e != nil {
		log.Fatal(e)
	}
	dbPath := filepath.Join(c.DataDir, "bridge.db")
	store, e := OpenStore(dbPath)
	if e != nil {
		log.Fatal(e)
	}
	defer store.Close()
	if e = store.BindInstance(c.ZoneID, c.AccountID); e != nil {
		log.Fatalf("refusing to start: %v", e)
	}
	s := &Server{cfg: c, cf: &Cloudflare{Base: "https://api.cloudflare.com/client/v4", Token: c.Token, Client: &http.Client{Timeout: 25 * time.Second}}, store: store}
	srv := &http.Server{Addr: c.Listen, Handler: s.logRequests(http.HandlerFunc(s.route)), ReadHeaderTimeout: 8 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 50 * time.Second, IdleTimeout: 60 * time.Second}
	s.advisoryScopeCheck()
	log.Printf("listening on %s (%d clients; zone %s)", c.Listen, len(c.Clients), c.ZoneName)
	log.Fatal(srv.ListenAndServe())
}
