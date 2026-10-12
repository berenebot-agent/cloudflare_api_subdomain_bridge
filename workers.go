package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"
)

// workerNameAvailable checks both the global ownership ledger and the live
// account-wide Worker list *before* uploading. The upload also sends a
// conditional create-only header, closing the preflight-to-PUT race if the
// Cloudflare endpoint honours its If-None-Match contract.
func (s *Server) workerNameAvailable(ctx context.Context, name string) error {
	managed, e := s.store.ListAll()
	if e != nil {
		return e // Fail closed if ownership cannot be checked.
	}
	for _, item := range managed {
		if item.ID == name {
			return bad(409, "Worker name is already in use")
		}
	}
	live, e := s.cf.all(ctx, s.account("/workers/scripts"))
	if e != nil {
		return e // Never attempt an upload if account-wide discovery fails.
	}
	for _, raw := range live {
		var script struct {
			ID string `json:"id"`
		}
		if e := json.Unmarshal(raw, &script); e != nil || script.ID == "" {
			return fmt.Errorf("Cloudflare returned an invalid Worker listing")
		}
		if script.ID == name {
			return bad(409, "Worker name is already in use")
		}
	}
	return nil
}

func (s *Server) workers(r *http.Request, c Client, p []string) (int, any, error) {
	base := s.account("/workers/scripts")
	routes := s.zone("/workers/routes")
	if len(p) == 1 {
		switch r.Method {
		case "GET":
			items, e := s.store.List(c.Name, "worker")
			return 200, items, e
		case "POST":
			var input struct {
				Label  string `json:"label"`
				Script string `json:"script"`
			}
			if e := decode(r, &input); e != nil {
				return 0, nil, e
			}
			if !idPattern.MatchString(input.Label) || len(input.Script) == 0 || len(input.Script) > 512*1024 {
				return 0, nil, bad(400, "label must be an identifier and script must be 1..524288 bytes")
			}
			// Retain the exact human-readable name the caller picked, but NEVER
			// let POST behave as an upsert: it could replace another client's (or
			// an unrelated account owner's) Worker before SQLite detects it.
			cfName := input.Label
			if e := s.workerNameAvailable(r.Context(), cfName); e != nil {
				return 0, nil, e
			}
			path := base + "/" + enc(cfName)
			if _, e := s.cf.uploadWorker(r.Context(), path, input.Script, true); e != nil {
				var ue upstreamError
				if errors.As(e, &ue) && (ue.Status == http.StatusPreconditionFailed || ue.Status == http.StatusConflict) {
					return 0, nil, bad(409, "Worker name is already in use")
				}
				return 0, nil, e
			}
			if _, e := s.cf.json(r.Context(), "POST", path+"/subdomain", map[string]any{"enabled": false, "previews_enabled": false}); e != nil {
				_, cleanup := s.cf.json(r.Context(), "DELETE", path, nil)
				if cleanup != nil {
					return 0, nil, bad(502, "Worker uploaded but public URL disable and cleanup failed; inspect Cloudflare immediately")
				}
				return 0, nil, bad(502, "Worker upload rolled back because disabling public workers.dev URLs failed")
			}
			if e := s.store.Put(Resource{Owner: c.Name, Kind: "worker", ID: input.Label, Name: cfName}); e != nil {
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
				_, cleanup := s.cf.json(cleanupCtx, "DELETE", path, nil)
				cancel()
				if cleanup != nil {
					log.Printf("worker %s created but ownership persist failed (%v) and rollback failed (%v)", input.Label, e, cleanup)
					return 0, nil, bad(502, "Worker uploaded but ownership could not be recorded and cleanup failed; inspect Cloudflare immediately (Worker "+input.Label+")")
				}
				return 0, nil, bad(502, "Worker upload rolled back because ownership could not be recorded")
			}
			return 201, map[string]any{"id": input.Label, "label": input.Label}, nil
		}
		return 0, nil, bad(405, "method not allowed")
	}
	if len(p) >= 2 && p[1] == "routes" {
		if len(p) == 2 && r.Method == "GET" {
			items, e := s.store.List(c.Name, "worker_route")
			return 200, items, e
		}
		if len(p) == 3 && r.Method == "DELETE" {
			item, e := s.owned(c, "worker_route", p[2])
			if e != nil {
				return 0, nil, e
			}
			raw, e := s.cf.json(r.Context(), "GET", routes+"/"+enc(item.ID), nil)
			if e != nil {
				return 0, nil, e
			}
			var cfroute struct {
				Pattern string `json:"pattern"`
				Script  string `json:"script"`
			}
			if json.Unmarshal(raw, &cfroute) != nil || cfroute.Pattern != item.Name || cfroute.Script != item.Details {
				return 0, nil, bad(409, "Worker route drift detected")
			}
			if e = s.scope(hostFromPattern(item.Name), c); e != nil {
				return 0, nil, e
			}
			if _, e = s.cf.json(r.Context(), "DELETE", routes+"/"+enc(item.ID), nil); e != nil {
				return 0, nil, e
			}
			if e = s.store.Delete(c.Name, "worker_route", item.ID); e != nil {
				return 0, nil, e
			}
			return 200, map[string]any{"deleted": true}, nil
		}
		return 0, nil, bad(405, "method not allowed")
	}
	if len(p) < 2 {
		return 0, nil, bad(404, "not found")
	}
	worker, e := s.owned(c, "worker", p[1])
	if e != nil {
		return 0, nil, e
	}
	wpath := base + "/" + enc(worker.ID)
	if len(p) == 2 && r.Method == "DELETE" {
		mail, err := s.store.List(c.Name, "email_rule")
		if err != nil {
			return 0, nil, err
		}
		for _, rule := range mail {
			if rule.Details == "worker:"+worker.ID {
				return 0, nil, bad(409, "delete Email Routing rules referencing this Worker first")
			}
		}
		items, e := s.store.List(c.Name, "worker_route")
		if e != nil {
			return 0, nil, e
		}
		for _, item := range items {
			if item.Details == worker.ID {
				return 0, nil, bad(409, "delete Worker routes first")
			}
		}
		existing, e := s.cf.all(r.Context(), routes)
		if e != nil {
			return 0, nil, e
		}
		for _, v := range existing {
			var route struct {
				Script string `json:"script"`
			}
			_ = json.Unmarshal(v, &route)
			if route.Script == worker.ID {
				return 0, nil, bad(409, "Worker has unmanaged routes; refusing deletion")
			}
		}
		if e = s.workerRoutesInScope(r, c, worker.ID); e != nil {
			return 0, nil, e
		}
		if _, e = s.cf.json(r.Context(), "DELETE", wpath, nil); e != nil {
			return 0, nil, e
		}
		if e = s.store.Delete(c.Name, "worker", worker.ID); e != nil {
			return 0, nil, e
		}
		return 200, map[string]any{"deleted": true}, nil
	}
	if len(p) == 2 && r.Method == "PUT" {
		var input struct {
			Script string `json:"script"`
		}
		if e := decode(r, &input); e != nil {
			return 0, nil, e
		}
		if len(input.Script) == 0 || len(input.Script) > 512*1024 {
			return 0, nil, bad(400, "invalid script length")
		}
		if e = s.workerRoutesInScope(r, c, worker.ID); e != nil {
			return 0, nil, e
		}
		if _, e := s.cf.uploadWorker(r.Context(), wpath, input.Script, false); e != nil {
			return 0, nil, e
		}
		if _, e := s.cf.json(r.Context(), "POST", wpath+"/subdomain", map[string]any{"enabled": false, "previews_enabled": false}); e != nil {
			return 0, nil, bad(502, "Worker updated but disabling public workers.dev URLs failed")
		}
		return 200, map[string]any{"id": worker.ID, "updated": true}, nil
	}
	if len(p) == 3 && p[2] == "routes" && r.Method == "POST" {
		var input struct {
			Hostname string `json:"hostname"`
		}
		if e := decode(r, &input); e != nil {
			return 0, nil, e
		}
		if e = s.scope(input.Hostname, c); e != nil {
			return 0, nil, e
		}
		pattern := input.Hostname + "/*"
		existing, e := s.cf.all(r.Context(), routes)
		if e != nil {
			return 0, nil, e
		}
		for _, v := range existing {
			var x struct {
				Pattern string `json:"pattern"`
			}
			_ = json.Unmarshal(v, &x)
			if x.Pattern == pattern {
				return 0, nil, bad(409, "Worker route already exists")
			}
		}
		raw, e := s.cf.json(r.Context(), "POST", routes, map[string]string{"pattern": pattern, "script": worker.ID})
		if e != nil {
			return 0, nil, e
		}
		id, e := cfID(raw)
		if e != nil {
			return 0, nil, e
		}
		if e = s.store.Put(Resource{Owner: c.Name, Kind: "worker_route", ID: id, Name: pattern, Details: worker.ID}); e != nil {
			return 0, nil, e
		}
		return 201, map[string]any{"id": id, "pattern": pattern, "script": worker.ID}, nil
	}
	return 0, nil, bad(405, "method not allowed")
}
