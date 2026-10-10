package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

type MailRule struct {
	ID          string `json:"id,omitempty"`
	Address     string `json:"address"`
	Action      string `json:"action"`
	Destination string `json:"destination,omitempty"`
}
type cfMailRule struct {
	ID       string `json:"id"`
	Matchers []struct {
		Type  string `json:"type"`
		Field string `json:"field"`
		Value string `json:"value"`
	} `json:"matchers"`
	Actions []struct {
		Type  string   `json:"type"`
		Value []string `json:"value"`
	} `json:"actions"`
}

func matcherAddress(raw json.RawMessage) string {
	var rule cfMailRule
	if json.Unmarshal(raw, &rule) != nil || len(rule.Matchers) != 1 {
		return ""
	}
	m := rule.Matchers[0]
	if m.Type != "literal" || m.Field != "to" {
		return ""
	}
	return strings.ToLower(m.Value)
}

// ruleMatchesDetails reports whether a live rule still matches the stored
// "<action>:<destination>" fingerprint. The action type is always compared.
// Forward destinations are compared case-insensitively; Worker destinations are
// compared exactly against the stored Worker ID. Any rule must have exactly one
// action value for forward/worker (or none for drop), so an extra destination
// added outside the bridge is treated as drift.
func ruleMatchesDetails(raw json.RawMessage, details string) bool {
	if details == "" {
		return true
	}
	var rule cfMailRule
	if json.Unmarshal(raw, &rule) != nil || len(rule.Actions) != 1 {
		return false
	}
	a := rule.Actions[0]
	stored := strings.SplitN(details, ":", 2)
	if !strings.EqualFold(a.Type, stored[0]) {
		return false
	}
	storedDest := ""
	if len(stored) > 1 {
		storedDest = stored[1]
	}
	switch strings.ToLower(a.Type) {
	case "drop":
		return len(a.Value) == 0
	case "forward":
		return len(a.Value) == 1 && strings.EqualFold(a.Value[0], storedDest)
	case "worker":
		return len(a.Value) == 1 && a.Value[0] == storedDest
	default:
		return false
	}
}
func (s *Server) mailAddress(address string, c Client) error {
	if len(address) > 90 || strings.Count(address, "@") != 1 {
		return bad(400, "invalid email address")
	}
	v := strings.Split(address, "@")
	if len(v[0]) < 1 || len(v[0]) > 64 || strings.ContainsAny(v[0], "\t\r\n <>\"\\/(),:;") {
		return bad(400, "invalid email local part")
	}
	return s.scope(strings.ToLower(v[1]), c)
}
func (s *Server) email(r *http.Request, c Client, p []string) (int, any, error) {
	base := s.zone("/email/routing/rules")
	if len(p) == 1 {
		switch r.Method {
		case "GET":
			owned, e := s.store.List(c.Name, "email_rule")
			if e != nil {
				return 0, nil, e
			}
			out := []any{}
			for _, item := range owned {
				raw, e := s.cf.json(r.Context(), "GET", base+"/"+enc(item.ID), nil)
				if e != nil {
					return 0, nil, e
				}
				if matcherAddress(raw) != item.Name {
					return 0, nil, bad(409, "Email rule drift detected")
				}
				if !ruleMatchesDetails(raw, item.Details) {
					return 0, nil, bad(409, "Email rule drift detected")
				}
				out = append(out, json.RawMessage(raw))
			}
			return 200, out, nil
		case "POST":
			var in MailRule
			if e := decode(r, &in); e != nil {
				return 0, nil, e
			}
			if in.ID != "" {
				return 0, nil, bad(400, "id must be omitted")
			}
			in.Address = strings.ToLower(in.Address)
			if e := s.mailAddress(in.Address, c); e != nil {
				return 0, nil, e
			}
			var action map[string]any
			switch in.Action {
			case "drop":
				if in.Destination != "" {
					return 0, nil, bad(400, "drop does not take a destination")
				}
				action = map[string]any{"type": "drop"}
			case "forward":
				if len(in.Destination) > 254 || strings.Count(in.Destination, "@") != 1 || strings.ContainsAny(in.Destination, "\r\n ") {
					return 0, nil, bad(400, "invalid forwarding destination")
				}
				action = map[string]any{"type": "forward", "value": []string{in.Destination}}
			case "worker":
				if in.Destination == "" {
					return 0, nil, bad(400, "worker ID required")
				}
				if _, e := s.owned(c, "worker", in.Destination); e != nil {
					return 0, nil, bad(403, "destination Worker not owned by client")
				}
				action = map[string]any{"type": "worker", "value": []string{in.Destination}}
			default:
				return 0, nil, bad(400, "action must be drop, forward or worker")
			}
			existing, e := s.cf.allWithPageSize(r.Context(), base, 50)
			if e != nil {
				return 0, nil, e
			}
			for _, v := range existing {
				if matcherAddress(v) == in.Address {
					return 0, nil, bad(409, "mailbox already has a rule")
				}
			}
			body := map[string]any{"name": "cfb-" + c.Name + "-" + randomID(), "enabled": true, "matchers": []any{map[string]any{"type": "literal", "field": "to", "value": in.Address}}, "actions": []any{action}}
			raw, e := s.cf.json(r.Context(), "POST", base, body)
			if e != nil {
				return 0, nil, e
			}
			id, e := cfID(raw)
			if e != nil {
				return 0, nil, e
			}
			if e = s.store.Put(Resource{Owner: c.Name, Kind: "email_rule", ID: id, Name: in.Address, Details: in.Action + ":" + in.Destination}); e != nil {
				return 0, nil, e
			}
			return 201, json.RawMessage(raw), nil
		}
		return 0, nil, bad(405, "method not allowed")
	}
	if len(p) == 2 && r.Method == "DELETE" {
		item, e := s.owned(c, "email_rule", p[1])
		if e != nil {
			return 0, nil, e
		}
		raw, e := s.cf.json(r.Context(), "GET", base+"/"+enc(item.ID), nil)
		if e != nil {
			return 0, nil, e
		}
		if matcherAddress(raw) != item.Name {
			return 0, nil, bad(409, "Email rule has changed outside bridge; refusing deletion")
		}
		if !ruleMatchesDetails(raw, item.Details) {
			return 0, nil, bad(409, "Email rule has changed outside bridge; refusing deletion")
		}
		if e = s.mailAddress(item.Name, c); e != nil {
			return 0, nil, e
		}
		if _, e = s.cf.json(r.Context(), "DELETE", base+"/"+enc(item.ID), nil); e != nil {
			return 0, nil, e
		}
		if e = s.store.Delete(c.Name, "email_rule", item.ID); e != nil {
			return 0, nil, e
		}
		return 200, map[string]any{"deleted": true}, nil
	}
	return 0, nil, bad(405, "method not allowed")
}
