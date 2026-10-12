package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Cloudflare struct {
	Base   string
	Token  string
	Client *http.Client
}
type cfEnvelope struct {
	Success bool            `json:"success"`
	Result  json.RawMessage `json:"result"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	ResultInfo struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

// upstreamError carries the HTTP status and Cloudflare error codes so callers
// can distinguish "the resource does not exist" (404) or an explicit conflict
// from a genuine upstream or network failure. Without it every rejection
// collapses into a generic error and surfaces to the client as 502.
type upstreamError struct {
	Status int
	Codes  []int
	Msg    string
}

func (e upstreamError) Error() string { return e.Msg }

// upstreamConflict reports whether an upstream rejection is an explicit
// duplicate/conflict rather than a generic fault. Cloudflare signals this with
// HTTP 409 or its "record already exists" codes; only those become a client
// 409, so other write failures are not mislabelled as collisions.
func upstreamConflict(e error) bool {
	var ue upstreamError
	if !errors.As(e, &ue) {
		return false
	}
	if ue.Status == 409 {
		return true
	}
	for _, c := range ue.Codes {
		switch c {
		case 81057, 81058:
			return true
		}
	}
	return false
}

func (cf *Cloudflare) call(ctx context.Context, method, path, ct string, body []byte) (json.RawMessage, error) {
	return cf.callWithHeaders(ctx, method, path, ct, body, nil)
}

// callWithHeaders is used for create-only Worker uploads. A conditional header
// prevents a script PUT from silently replacing an existing account-wide Worker.
func (cf *Cloudflare) callWithHeaders(ctx context.Context, method, path, ct string, body []byte, extra http.Header) (json.RawMessage, error) {
	if cf.Client == nil {
		cf.Client = &http.Client{Timeout: 25 * time.Second}
	}
	if len(body) > 2*1024*1024 {
		return nil, errors.New("request too large")
	}
	req, e := http.NewRequestWithContext(ctx, method, cf.Base+path, bytes.NewReader(body))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Authorization", "Bearer "+cf.Token)
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	for name, values := range extra {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	resp, e := cf.Client.Do(req)
	if e != nil {
		return nil, fmt.Errorf("upstream request failed: %w", e)
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024+1))
	if e != nil {
		return nil, e
	}
	if len(b) > 2*1024*1024 {
		return nil, errors.New("upstream response too large")
	}
	var v cfEnvelope
	if json.Unmarshal(b, &v) != nil {
		return nil, fmt.Errorf("Cloudflare returned invalid JSON (status %d)", resp.StatusCode)
	}
	if resp.StatusCode >= 300 || !v.Success {
		msgs := []string{}
		codes := []int{}
		for _, issue := range v.Errors {
			msgs = append(msgs, fmt.Sprintf("%d: %s", issue.Code, issue.Message))
			codes = append(codes, issue.Code)
		}
		return nil, upstreamError{Status: resp.StatusCode, Codes: codes, Msg: fmt.Sprintf("Cloudflare request rejected (status %d): %s", resp.StatusCode, strings.Join(msgs, "; "))}
	}
	return v.Result, nil
}
func (cf *Cloudflare) json(ctx context.Context, method, path string, body any) (json.RawMessage, error) {
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	return cf.call(ctx, method, path, "application/json", b)
}
func (cf *Cloudflare) all(ctx context.Context, path string) ([]json.RawMessage, error) {
	return cf.allWithPageSize(ctx, path, 100)
}

// allWithPageSize paginates an endpoint, requesting perPage items per page.
// Cloudflare caps some endpoints lower than others (for example Email Routing
// rules allow at most 50), so callers must not assume a single global maximum.
func (cf *Cloudflare) allWithPageSize(ctx context.Context, path string, perPage int) ([]json.RawMessage, error) {
	if perPage < 1 {
		perPage = 100
	}
	out := []json.RawMessage{}
	for page := 1; page <= 50; page++ {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		req, e := http.NewRequestWithContext(ctx, "GET", cf.Base+path+sep+fmt.Sprintf("per_page=%d&page=%d", perPage, page), nil)
		if e != nil {
			return nil, e
		}
		req.Header.Set("Authorization", "Bearer "+cf.Token)
		client := cf.Client
		if client == nil {
			client = &http.Client{Timeout: 25 * time.Second}
		}
		resp, e := client.Do(req)
		if e != nil {
			return nil, e
		}
		b, e := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024+1))
		resp.Body.Close()
		if e != nil {
			return nil, e
		}
		var v cfEnvelope
		if json.Unmarshal(b, &v) != nil || resp.StatusCode >= 300 || !v.Success {
			return nil, fmt.Errorf("Cloudflare list request failed (%d)", resp.StatusCode)
		}
		var items []json.RawMessage
		if err := json.Unmarshal(v.Result, &items); err != nil {
			return nil, err
		}
		out = append(out, items...)
		if v.ResultInfo.TotalPages == 0 || page >= v.ResultInfo.TotalPages {
			return out, nil
		}
	}
	return nil, errors.New("Cloudflare pagination cap exceeded")
}
func (cf *Cloudflare) uploadWorker(ctx context.Context, path, script string, createOnly bool) (json.RawMessage, error) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	meta, _ := json.Marshal(map[string]any{"main_module": "main.mjs", "bindings": []any{}, "compatibility_date": "2026-09-01"})
	partHeader := make(map[string][]string)
	partHeader["Content-Disposition"] = []string{`form-data; name="metadata"`}
	partHeader["Content-Type"] = []string{"application/json"}
	p, _ := w.CreatePart(partHeader)
	p.Write(meta)
	header := map[string][]string{"Content-Disposition": {`form-data; name="main.mjs"; filename="main.mjs"`}, "Content-Type": {"application/javascript+module"}}
	p, _ = w.CreatePart(header)
	p.Write([]byte(script))
	w.Close()
	if createOnly {
		h := make(http.Header)
		h.Set("If-None-Match", "*")
		return cf.callWithHeaders(ctx, "PUT", path, w.FormDataContentType(), b.Bytes(), h)
	}
	return cf.call(ctx, "PUT", path, w.FormDataContentType(), b.Bytes())
}
func enc(s string) string { return url.PathEscape(s) }
