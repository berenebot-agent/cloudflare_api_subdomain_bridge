package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type TunnelHost struct {
	Hostname string `json:"hostname"`
	Service  string `json:"service"`
	DNSID    string `json:"dns_id,omitempty"`
}

func validService(v string) bool {
	u, e := url.Parse(v)
	return e == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil && u.Fragment == "" && u.RawQuery == "" && u.Path == "" && !strings.ContainsAny(v, "\r\n\\")
}
func (s *Server) tunnelHosts(c Client, id string) ([]TunnelHost, error) {
	resources, e := s.store.List(c.Name, "tunnel_host")
	if e != nil {
		return nil, e
	}
	out := []TunnelHost{}
	for _, item := range resources {
		if !strings.HasPrefix(item.ID, id+"|") {
			continue
		}
		var h TunnelHost
		if json.Unmarshal([]byte(item.Details), &h) != nil {
			return nil, fmt.Errorf("corrupt tunnel host metadata")
		}
		out = append(out, h)
	}
	return out, nil
}
func ingress(hosts []TunnelHost) map[string]any {
	items := []any{}
	for _, h := range hosts {
		items = append(items, map[string]any{"hostname": h.Hostname, "service": h.Service})
	}
	items = append(items, map[string]any{"service": "http_status:404"})
	return map[string]any{"config": map[string]any{"ingress": items}}
}

// hostsInScope fails when any of the tunnel's published hostnames falls outside
// the caller's current scope, guarding against a scope change leaving stale
// authority over another client's namespace.
func (s *Server) hostsInScope(hosts []TunnelHost, c Client) error {
	for _, h := range hosts {
		if e := s.scope(h.Hostname, c); e != nil {
			return bad(409, "tunnel publishes a hostname outside your current scope; reconcile before changing it")
		}
	}
	return nil
}

type tunnelConfig struct {
	Config struct {
		Ingress []struct {
			Hostname      string          `json:"hostname"`
			Service       string          `json:"service"`
			Path          string          `json:"path"`
			OriginRequest json.RawMessage `json:"originRequest"`
		} `json:"ingress"`
		OriginRequest json.RawMessage `json:"originRequest"`
		WarpRouting   json.RawMessage `json:"warp-routing"`
	} `json:"config"`
}

// set reports whether a raw JSON field holds a meaningful (non-null/empty)
// value. Cloudflare returns defaults such as {} or null for unset fields.
func set(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s != "" && s != "null" && s != "{}" && s != "[]"
}

// warpRoutingEnabled reports whether the tunnel's warp-routing is actually on.
// Cloudflare returns the field for every remotely-managed tunnel — an untouched
// tunnel reports {"enabled": false} — so the mere presence of the key is not
// evidence the tunnel was changed outside the bridge. Only an enabled value
// blocks; an unrecognised shape fails closed so an unexpected configuration is
// never silently ignored.
func warpRoutingEnabled(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" || s == "{}" || s == "[]" {
		return false
	}
	var cfg struct {
		Enabled bool `json:"enabled"`
	}
	if json.Unmarshal(raw, &cfg) != nil {
		return true
	}
	return cfg.Enabled
}

func (s *Server) fetchTunnelConfig(r *http.Request, id string) (tunnelConfig, error) {
	var actual tunnelConfig
	raw, e := s.cf.json(r.Context(), "GET", s.account("/cfd_tunnel/"+enc(id)+"/configurations"), nil)
	if e != nil {
		return actual, e
	}
	if json.Unmarshal(raw, &actual) != nil {
		return actual, fmt.Errorf("unreadable tunnel configuration")
	}
	return actual, nil
}

// configMatches reports whether the live tunnel configuration exactly reflects
// the supplied host list. A non-nil error means the live state could not be
// read or parsed (as opposed to differing), so callers can tell upstream
// failures apart from drift.
func (s *Server) configMatches(r *http.Request, id string, hosts []TunnelHost) (bool, error) {
	actual, e := s.fetchTunnelConfig(r, id)
	if e != nil {
		return false, e
	}
	expected := map[string]string{}
	for _, h := range hosts {
		expected[h.Hostname] = h.Service
	}
	if len(actual.Config.Ingress) != len(hosts)+1 {
		return false, nil
	}
	for i, item := range actual.Config.Ingress {
		if i == len(actual.Config.Ingress)-1 {
			if item.Hostname != "" || item.Service != "http_status:404" || item.Path != "" || set(item.OriginRequest) {
				return false, nil
			}
			continue
		}
		if expected[item.Hostname] != item.Service || item.Path != "" || set(item.OriginRequest) {
			return false, nil
		}
		delete(expected, item.Hostname)
	}
	if len(expected) > 0 || set(actual.Config.OriginRequest) || warpRoutingEnabled(actual.Config.WarpRouting) {
		return false, nil
	}
	return true, nil
}

func (s *Server) verifyTunnelConfig(r *http.Request, c Client, id string, hosts []TunnelHost) error {
	ok, e := s.configMatches(r, id, hosts)
	if e != nil {
		return e
	}
	if !ok {
		return bad(409, "tunnel configuration drift detected; reconcile in Cloudflare")
	}
	return nil
}

// tunnelLiveEmpty confirms the live tunnel has no published ingress hostnames,
// so a delete does not remove a tunnel that was changed outside the bridge.
func (s *Server) tunnelLiveEmpty(r *http.Request, id string) error {
	actual, e := s.fetchTunnelConfig(r, id)
	if e != nil {
		return e
	}
	for _, item := range actual.Config.Ingress {
		if item.Hostname != "" {
			return bad(409, "tunnel has live ingress not managed by the bridge; reconcile in Cloudflare")
		}
	}
	if warpRoutingEnabled(actual.Config.WarpRouting) {
		return bad(409, "tunnel has warp-routing enabled; reconcile in Cloudflare")
	}
	return nil
}
func (s *Server) tunnels(r *http.Request, c Client, p []string) (int, any, error) {
	base := s.account("/cfd_tunnel")
	if len(p) == 1 {
		switch r.Method {
		case "GET":
			items, e := s.store.List(c.Name, "tunnel")
			return 200, items, e
		case "POST":
			var input struct {
				Name string `json:"name"`
			}
			if e := decode(r, &input); e != nil {
				return 0, nil, e
			}
			if len(input.Name) > 50 || !idPattern.MatchString(strings.ToLower(input.Name)) {
				return 0, nil, bad(400, "invalid tunnel label")
			}
			name := "cfb-" + c.Name + "-" + randomID()
			raw, e := s.cf.json(r.Context(), "POST", base, map[string]any{"name": name, "config_src": "cloudflare"})
			if e != nil {
				return 0, nil, e
			}
			id, e := cfID(raw)
			if e != nil {
				return 0, nil, e
			}
			path := base + "/" + enc(id) + "/configurations"
			if _, e = s.cf.json(r.Context(), "PUT", path, ingress(nil)); e != nil {
				return 0, nil, fmt.Errorf("tunnel created (%s) but configuration failed: %w", id, e)
			}
			if e = s.store.Put(Resource{Owner: c.Name, Kind: "tunnel", ID: id, Name: input.Name}); e != nil {
				return 0, nil, e
			}
			return 201, map[string]any{"id": id, "name": input.Name}, nil
		}
		return 0, nil, bad(405, "method not allowed")
	}
	if len(p) < 2 {
		return 0, nil, bad(404, "not found")
	}
	t, e := s.owned(c, "tunnel", p[1])
	if e != nil {
		return 0, nil, e
	}
	tpath := base + "/" + enc(t.ID)
	if len(p) == 2 {
		switch r.Method {
		case "GET":
			raw, e := s.cf.json(r.Context(), "GET", tpath, nil)
			if e != nil {
				return 0, nil, e
			}
			return 200, map[string]any{"tunnel": json.RawMessage(raw), "label": t.Name}, nil
		case "DELETE":
			hosts, e := s.tunnelHosts(c, t.ID)
			if e != nil {
				return 0, nil, e
			}
			if len(hosts) > 0 {
				return 0, nil, bad(409, "delete published hostnames before deleting tunnel")
			}
			if e = s.tunnelLiveEmpty(r, t.ID); e != nil {
				return 0, nil, e
			}
			if _, e = s.cf.json(r.Context(), "DELETE", tpath, nil); e != nil {
				return 0, nil, e
			}
			if e = s.store.Delete(c.Name, "tunnel", t.ID); e != nil {
				return 0, nil, e
			}
			return 200, map[string]any{"deleted": true}, nil
		}
		return 0, nil, bad(405, "method not allowed")
	}
	if len(p) == 3 && p[2] == "token" && r.Method == "GET" {
		hosts, e := s.tunnelHosts(c, t.ID)
		if e != nil {
			return 0, nil, e
		}
		if e = s.hostsInScope(hosts, c); e != nil {
			return 0, nil, e
		}
		if e = s.verifyTunnelConfig(r, c, t.ID, hosts); e != nil {
			return 0, nil, e
		}
		raw, e := s.cf.json(r.Context(), "GET", tpath+"/token", nil)
		if e != nil {
			return 0, nil, e
		}
		return 200, map[string]any{"token": json.RawMessage(raw)}, nil
	}
	if p[2] != "hostnames" {
		return 0, nil, bad(404, "not found")
	}
	hosts, e := s.tunnelHosts(c, t.ID)
	if e != nil {
		return 0, nil, e
	}
	if len(p) == 3 {
		switch r.Method {
		case "GET":
			return 200, hosts, nil
		case "POST":
			var h TunnelHost
			if e = decode(r, &h); e != nil {
				return 0, nil, e
			}
			if h.DNSID != "" {
				return 0, nil, bad(400, "dns_id is server-controlled")
			}
			if e = s.scope(h.Hostname, c); e != nil {
				return 0, nil, e
			}
			if !validService(h.Service) {
				return 0, nil, bad(400, "service must be a simple http:// or https:// origin URL")
			}
			for _, existing := range hosts {
				if existing.Hostname == h.Hostname {
					return 0, nil, bad(409, "hostname already published")
				}
			}
			if e = s.verifyTunnelConfig(r, c, t.ID, hosts); e != nil {
				return 0, nil, e
			}
			if len(hosts) >= 20 {
				return 0, nil, bad(409, "maximum 20 hostnames per tunnel")
			}
			dnsList, e := s.cf.all(r.Context(), s.zone("/dns_records?name="+url.QueryEscape(h.Hostname)))
			if e != nil {
				return 0, nil, e
			}
			for _, record := range dnsList {
				var d DNSRecord
				if json.Unmarshal(record, &d) == nil && d.Name == h.Hostname {
					return 0, nil, bad(409, "hostname already has a DNS record")
				}
			}
			dns, e := s.cf.json(r.Context(), "POST", s.zone("/dns_records"), map[string]any{"name": h.Hostname, "type": "CNAME", "content": t.ID + ".cfargotunnel.com", "proxied": true, "ttl": 1})
			if e != nil {
				return 0, nil, e
			}
			h.DNSID, e = cfID(dns)
			if e != nil {
				return 0, nil, e
			}
			newHosts := append(append([]TunnelHost{}, hosts...), h)
			if _, e = s.cf.json(r.Context(), "PUT", tpath+"/configurations", ingress(newHosts)); e != nil {
				_, _ = s.cf.json(r.Context(), "DELETE", s.zone("/dns_records/"+enc(h.DNSID)), nil)
				return 0, nil, e
			}
			details, _ := json.Marshal(h)
			if e = s.store.PutAll(
				Resource{Owner: c.Name, Kind: "tunnel_host", ID: t.ID + "|" + h.Hostname, Name: h.Hostname, Details: string(details)},
				Resource{Owner: c.Name, Kind: "tunnel_dns", ID: h.DNSID, Name: h.Hostname},
			); e != nil {
				return 0, nil, bad(502, "hostname published in Cloudflare but ownership could not be recorded; reconcile DNS record "+h.DNSID)
			}
			return 201, h, nil
		}
		return 0, nil, bad(405, "method not allowed")
	}
	if len(p) == 4 && r.Method == "DELETE" {
		hostname := p[3]
		if e = s.scope(hostname, c); e != nil {
			return 0, nil, e
		}
		var found *TunnelHost
		newHosts := []TunnelHost{}
		for i := range hosts {
			if hosts[i].Hostname == hostname {
				found = &hosts[i]
			} else {
				newHosts = append(newHosts, hosts[i])
			}
		}
		if found == nil {
			return 0, nil, bad(404, "hostname not owned by this tunnel")
		}
		// Accept either the pre-delete ingress (build) or post-delete ingress
		// (already removed), so an interrupted delete can be retried safely.
		preOK, e := s.configMatches(r, t.ID, hosts)
		if e != nil {
			return 0, nil, e
		}
		postOK := false
		if !preOK {
			postOK, e = s.configMatches(r, t.ID, newHosts)
			if e != nil {
				return 0, nil, e
			}
		}
		if !preOK && !postOK {
			return 0, nil, bad(409, "tunnel configuration drift detected; reconcile in Cloudflare")
		}
		// Verify the DNS record while it exists; a 404 means a prior attempt
		// already removed it, which is success for this idempotent delete.
		dnsRaw, e := s.cf.json(r.Context(), "GET", s.zone("/dns_records/"+enc(found.DNSID)), nil)
		if e == nil {
			var dns DNSRecord
			_ = json.Unmarshal(dnsRaw, &dns)
			if dns.Name != "" && (dns.Name != hostname || dns.Type != "CNAME" || dns.Content != t.ID+".cfargotunnel.com") {
				return 0, nil, bad(409, "tunnel DNS drift detected")
			}
		}
		if preOK {
			if _, e = s.cf.json(r.Context(), "PUT", tpath+"/configurations", ingress(newHosts)); e != nil {
				return 0, nil, e
			}
		}
		if _, e = s.cf.json(r.Context(), "DELETE", s.zone("/dns_records/"+enc(found.DNSID)), nil); e != nil {
			return 0, nil, e
		}
		if e = s.store.Delete(c.Name, "tunnel_host", t.ID+"|"+hostname); e != nil {
			return 0, nil, e
		}
		_ = s.store.Delete(c.Name, "tunnel_dns", found.DNSID)
		return 200, map[string]any{"deleted": true}, nil
	}
	return 0, nil, bad(404, "not found")
}
