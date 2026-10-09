package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Client struct {
	Name        string   `json:"-"`
	Key         string   `json:"key"`
	Scope       string   `json:"scope"`
	Descendants bool     `json:"descendants"`
	Permissions []string `json:"permissions"`
}
type Config struct {
	AccountID, ZoneID, ZoneName, Token, Listen, DataDir string
	Clients                                             []Client
	RatePerMin                                          int
}

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,40}$`)
var labelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func validHost(s string) bool {
	if len(s) < 4 || len(s) > 253 || strings.TrimSpace(s) != s || s != strings.ToLower(s) || strings.HasSuffix(s, ".") {
		return false
	}
	a := strings.Split(s, ".")
	if len(a) < 2 {
		return false
	}
	for _, l := range a {
		if !labelPattern.MatchString(l) {
			return false
		}
	}
	return true
}
func inside(host string, c Client) bool {
	return host == c.Scope || (c.Descendants && strings.HasSuffix(host, "."+c.Scope))
}
func conflicts(a, b Client) bool { return inside(a.Scope, b) || inside(b.Scope, a) }

func isPlaceholder(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "replace_with") || strings.Contains(l, "changeme") || strings.Contains(l, "your_")
}
func LoadConfigFrom(environ []string) (Config, error) {
	env := map[string]string{}
	for _, v := range environ {
		parts := strings.SplitN(v, "=", 2)
		if len(parts) == 2 {
			env[parts[0]] = parts[1]
		}
	}
	c := Config{AccountID: env["CF_ACCOUNT_ID"], ZoneID: env["CF_ZONE_ID"], ZoneName: strings.ToLower(env["CF_ZONE_NAME"]), Token: env["CF_API_TOKEN"], DataDir: env["BRIDGE_DATA_DIR"]}
	c.RatePerMin = 120
	if env["BRIDGE_RATE_PER_MIN"] != "" {
		n, e := strconv.Atoi(env["BRIDGE_RATE_PER_MIN"])
		if e != nil || n < 1 || n > 10000 {
			return c, fmt.Errorf("BRIDGE_RATE_PER_MIN must be 1..10000")
		}
		c.RatePerMin = n
	}
	host := env["BRIDGE_LISTEN_ADDR"]
	if host == "" {
		host = "0.0.0.0"
	}
	port := env["BRIDGE_PORT"]
	if port == "" {
		port = "8080"
	}
	if n, e := strconv.Atoi(port); e != nil || n < 1 || n > 65535 {
		return c, fmt.Errorf("BRIDGE_PORT must be 1..65535")
	}
	c.Listen = net.JoinHostPort(host, port)
	if c.DataDir == "" {
		c.DataDir = "/data"
	}
	if c.Token == "" || c.AccountID == "" || c.ZoneID == "" || !validHost(c.ZoneName) {
		return c, errors.New("CF_API_TOKEN, CF_ACCOUNT_ID, CF_ZONE_ID and valid CF_ZONE_NAME are required")
	}
	if isPlaceholder(c.Token) || isPlaceholder(c.AccountID) || isPlaceholder(c.ZoneID) {
		return c, errors.New("config still contains example placeholder values; set real CF_API_TOKEN, CF_ACCOUNT_ID and CF_ZONE_ID")
	}
	keys := []string{}
	for k := range env {
		if strings.HasPrefix(k, "BRIDGE_CLIENT_") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return c, errors.New("at least one BRIDGE_CLIENT_* is required")
	}
	seenKeys := map[[32]byte]bool{}
	for _, k := range keys {
		name := strings.ToLower(strings.TrimPrefix(k, "BRIDGE_CLIENT_"))
		if !idPattern.MatchString(name) {
			return c, fmt.Errorf("invalid client variable: %s", k)
		}
		var cli Client
		dec := json.NewDecoder(strings.NewReader(env[k]))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cli); err != nil {
			return c, fmt.Errorf("%s: %w", k, err)
		}
		cli.Name = name
		if isPlaceholder(cli.Key) {
			return c, fmt.Errorf("%s: client key is still the example placeholder (%q); generate one with `openssl rand -hex 32`", k, cli.Key)
		}
		if len(cli.Key) < 24 {
			return c, fmt.Errorf("%s: key must be >=24 bytes", k)
		}
		digest := sha256.Sum256([]byte(cli.Key))
		if seenKeys[digest] {
			return c, errors.New("duplicate client key")
		}
		seenKeys[digest] = true
		cli.Scope = strings.ToLower(cli.Scope)
		if !validHost(cli.Scope) || cli.Scope == c.ZoneName || !strings.HasSuffix(cli.Scope, "."+c.ZoneName) {
			return c, fmt.Errorf("%s: scope must be a valid subdomain of CF_ZONE_NAME", k)
		}
		if len(cli.Permissions) == 0 {
			return c, fmt.Errorf("%s: permissions required", k)
		}
		seen := map[string]bool{}
		for _, p := range cli.Permissions {
			if p != "dns" && p != "workers" && p != "tunnels" && p != "email" {
				return c, fmt.Errorf("%s: unknown permission %s", k, p)
			}
			if seen[p] {
				return c, fmt.Errorf("%s: duplicate permission", k)
			}
			seen[p] = true
		}
		for _, prior := range c.Clients {
			if conflicts(prior, cli) {
				return c, fmt.Errorf("client scopes overlap: %s and %s", prior.Name, cli.Name)
			}
		}
		c.Clients = append(c.Clients, cli)
	}
	return c, nil
}
func LoadConfig() (Config, error) { return LoadConfigFrom(os.Environ()) }
func hasPermission(c Client, p string) bool {
	for _, v := range c.Permissions {
		if v == p {
			return true
		}
	}
	return false
}
