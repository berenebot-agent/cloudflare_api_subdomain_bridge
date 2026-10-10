package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

type DNSRecord struct {
	ID       string `json:"id,omitempty"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl,omitempty"`
	Priority int    `json:"priority,omitempty"`
	Proxied  bool   `json:"proxied,omitempty"`
}

// dnsWrite is the request body sent upstream. Pointers let the bridge transmit
// meaningful zero values (MX priority 0, proxied false) that omitempty would
// otherwise drop.
type dnsWrite struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl"`
	Priority *int   `json:"priority,omitempty"`
	Proxied  *bool  `json:"proxied,omitempty"`
}

func (d DNSRecord) writeBody() dnsWrite {
	w := dnsWrite{Name: d.Name, Type: d.Type, Content: d.Content, TTL: d.TTL}
	if d.Type == "MX" {
		p := d.Priority
		w.Priority = &p
	}
	p := d.Proxied
	w.Proxied = &p
	return w
}

var dnsLabelPattern = regexp.MustCompile(`^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$`)

func validDNSName(s string) bool {
	if len(s) < 4 || len(s) > 253 || strings.TrimSpace(s) != s || s != strings.ToLower(s) || strings.HasSuffix(s, ".") {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	for _, label := range parts {
		if !dnsLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}
func (s *Server) scopeDNS(name string, c Client) error {
	if !validDNSName(name) || !inside(name, c) {
		return bad(403, "DNS hostname outside assigned scope")
	}
	return nil
}
func dnsInputValid(d DNSRecord, c Client) error {
	if err := (&Server{}).scopeDNS(d.Name, c); err != nil {
		return err
	}
	switch d.Type {
	case "A":
		if p := net.ParseIP(d.Content); p == nil || p.To4() == nil {
			return bad(400, "invalid IPv4 address")
		}
	case "AAAA":
		if p := net.ParseIP(d.Content); p == nil || p.To4() != nil {
			return bad(400, "invalid IPv6 address")
		}
	case "CNAME":
		if !validHost(strings.TrimSuffix(strings.ToLower(d.Content), ".")) {
			return bad(400, "invalid CNAME target")
		}
	case "MX":
		if !validHost(strings.TrimSuffix(strings.ToLower(d.Content), ".")) || d.Priority < 0 || d.Priority > 65535 {
			return bad(400, "invalid MX target or priority")
		}
	case "TXT":
		if d.Content == "" || len(d.Content) > 4096 {
			return bad(400, "invalid TXT content")
		}
	default:
		return bad(400, "V1 DNS supports A, AAAA, CNAME, MX and TXT only")
	}
	if d.TTL != 0 && d.TTL != 1 && (d.TTL < 60 || d.TTL > 86400) {
		return bad(400, "TTL must be 1 or 60..86400")
	}
	if (d.Type == "TXT" || d.Type == "MX") && d.Proxied {
		return bad(400, "TXT and MX records cannot be proxied")
	}
	if d.Type != "MX" && d.Priority != 0 {
		return bad(400, "priority only applies to MX records")
	}
	return nil
}
func (s *Server) dns(r *http.Request, c Client, p []string) (int, any, error) {
	base := s.zone("/dns_records")
	if len(p) == 1 {
		switch r.Method {
		case "GET":
			items, e := s.cf.all(r.Context(), base)
			if e != nil {
				return 0, nil, e
			}
			out := []DNSRecord{}
			for _, v := range items {
				var d DNSRecord
				if json.Unmarshal(v, &d) == nil && inside(d.Name, c) {
					out = append(out, d)
				}
			}
			return 200, out, nil
		case "POST":
			var d DNSRecord
			if e := decode(r, &d); e != nil {
				return 0, nil, e
			}
			if d.ID != "" {
				return 0, nil, bad(400, "id cannot be set")
			}
			if e := dnsInputValid(d, c); e != nil {
				return 0, nil, e
			}
			existing, e := s.cf.all(r.Context(), base+"?name="+url.QueryEscape(d.Name))
			if e != nil {
				return 0, nil, e
			}
			for _, record := range existing {
				var x DNSRecord
				if json.Unmarshal(record, &x) == nil && x.Name == d.Name {
					return 0, nil, bad(409, "hostname already has a DNS record")
				}
			}
			if d.TTL == 0 {
				d.TTL = 1
			}
			raw, e := s.cf.json(r.Context(), "POST", base, d.writeBody())
			if e != nil {
				return 0, nil, e
			}
			return 201, json.RawMessage(raw), nil
		}
		return 0, nil, bad(405, "method not allowed")
	}
	if len(p) != 2 {
		return 0, nil, bad(404, "not found")
	}
	if e := validateID(p[1]); e != nil {
		return 0, nil, e
	}
	recPath := base + "/" + enc(p[1])
	raw, e := s.cf.json(r.Context(), "GET", recPath, nil)
	if e != nil {
		var ue upstreamError
		if errors.As(e, &ue) && ue.Status == 404 {
			return 0, nil, bad(404, "DNS record not found")
		}
		return 0, nil, e
	}
	var current DNSRecord
	if e = json.Unmarshal(raw, &current); e != nil {
		return 0, nil, e
	}
	if e = s.scopeDNS(current.Name, c); e != nil {
		return 0, nil, e
	}
	_, managed, me := s.store.Get(c.Name, "tunnel_dns", p[1])
	if me != nil {
		return 0, nil, me
	}
	if managed {
		return 0, nil, bad(409, "DNS record is managed by a tunnel; use tunnel hostname operations")
	}
	switch r.Method {
	case "GET":
		return 200, json.RawMessage(raw), nil
	case "PATCH":
		var patch DNSRecord
		if e = decode(r, &patch); e != nil {
			return 0, nil, e
		}
		if patch.ID != "" {
			return 0, nil, bad(400, "id cannot be changed")
		}
		if e = dnsInputValid(patch, c); e != nil {
			return 0, nil, e
		}
		if patch.TTL == 0 {
			patch.TTL = 1
		}
		raw, e = s.cf.json(r.Context(), "PUT", recPath, patch.writeBody())
		if e != nil {
			return 0, nil, e
		}
		return 200, json.RawMessage(raw), nil
	case "DELETE":
		_, e = s.cf.json(r.Context(), "DELETE", recPath, nil)
		if e != nil {
			return 0, nil, e
		}
		return 200, map[string]any{"deleted": true, "id": p[1]}, nil
	}
	return 0, nil, bad(405, "method not allowed")
}
