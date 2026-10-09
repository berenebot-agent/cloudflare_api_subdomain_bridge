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

func (cf *Cloudflare) call(ctx context.Context, method, path, ct string, body []byte) (json.RawMessage, error) {
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
		for _, issue := range v.Errors {
			msgs = append(msgs, fmt.Sprintf("%d: %s", issue.Code, issue.Message))
		}
		return nil, fmt.Errorf("Cloudflare request rejected (status %d): %s", resp.StatusCode, strings.Join(msgs, "; "))
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
	out := []json.RawMessage{}
	for page := 1; page <= 50; page++ {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		req, e := http.NewRequestWithContext(ctx, "GET", cf.Base+path+sep+fmt.Sprintf("per_page=100&page=%d", page), nil)
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
func (cf *Cloudflare) uploadWorker(ctx context.Context, path, script string) (json.RawMessage, error) {
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
	return cf.call(ctx, "PUT", path, w.FormDataContentType(), b.Bytes())
}
func enc(s string) string { return url.PathEscape(s) }
