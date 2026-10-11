package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const defaultAPI = "https://config.doxx.net/v1/"

// Client talks to the doxx.net config API: every call is a form-encoded POST
// with endpoint_name=1 and token=<auth token>.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
	Debug   bool
}

func NewClient(token string, debug bool) *Client {
	base := os.Getenv("DOXX_API")
	if base == "" {
		base = defaultAPI
	}
	return &Client{BaseURL: base, Token: token, HTTP: &http.Client{Timeout: 30 * time.Second}, Debug: debug}
}

// loadToken reads the auth token from DOXX_TOKEN, DOXX_TOKEN_FILE or
// ~/.config/doxx/token. The token is never printed.
func loadToken() (string, error) {
	if t := strings.TrimSpace(os.Getenv("DOXX_TOKEN")); t != "" {
		return t, nil
	}
	path := os.Getenv("DOXX_TOKEN_FILE")
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(home, ".config", "doxx", "token")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("no doxx token: set DOXX_TOKEN or put a net-admin token in %s (chmod 600)", path)
	}
	t := strings.TrimSpace(string(b))
	if t == "" {
		return "", fmt.Errorf("token file %s is empty", path)
	}
	return t, nil
}

// APIError is a structured error returned by the API.
type APIError struct {
	Endpoint string
	Code     string
	Message  string
	Context  string
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("%s: %s", e.Endpoint, firstNonEmpty(e.Message, e.Code, "request failed"))
	if e.Code != "" && e.Message != "" {
		msg += " (" + e.Code + ")"
	}
	if e.Context != "" {
		msg += "\n  api says: " + e.Context
	}
	return msg
}

// Call invokes an endpoint and returns the decoded JSON body.
func (c *Client) Call(endpoint string, params map[string]string, auth bool) (any, error) {
	form := url.Values{}
	form.Set(endpoint, "1")
	for k, v := range params {
		form.Set(k, v)
	}
	if auth {
		form.Set("token", c.Token)
	}
	resp, err := c.HTTP.PostForm(c.BaseURL, form)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("%s: reading response: %w", endpoint, err)
	}
	var data any
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("%s: HTTP %d, response is not JSON: %.200s", endpoint, resp.StatusCode, string(body))
	}
	if c.Debug {
		pretty, _ := json.MarshalIndent(redact(data), "", "  ")
		fmt.Fprintf(os.Stderr, "--- %s (HTTP %d) ---\n%s\n", endpoint, resp.StatusCode, pretty)
	}
	if m, ok := data.(map[string]any); ok {
		status, _ := m["status"].(string)
		if status == "error" || resp.StatusCode >= 400 {
			return nil, &APIError{
				Endpoint: endpoint,
				Code:     firstNonEmpty(str(m["error_code"]), str(m["error"])),
				Message:  str(m["message"]),
				Context:  str(m["fix"]),
			}
		}
	} else if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%s: HTTP %d", endpoint, resp.StatusCode)
	}
	return data, nil
}

// ---- domain helpers -------------------------------------------------------

type Tunnel struct {
	Token  string
	Name   string
	Server string
	IP     string
	Raw    map[string]any
}

type Server struct {
	Name, Hostname, Location string
}

func (c *Client) Servers() ([]Server, error) {
	data, err := c.Call("servers", nil, false)
	if err != nil {
		return nil, err
	}
	var out []Server
	for _, m := range findObjects(data) {
		host := pick(m, "hostname", "server", "host")
		if host == "" {
			continue
		}
		out = append(out, Server{Name: pick(m, "server_name", "name"), Hostname: host, Location: pick(m, "location", "city", "country")})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return out, nil
}

func (c *Client) Tunnels() ([]Tunnel, error) {
	data, err := c.Call("list_tunnels", nil, true)
	if err != nil {
		return nil, err
	}
	var out []Tunnel
	for _, m := range findObjects(data) {
		tok := pick(m, "tunnel_token", "token")
		if tok == "" {
			continue
		}
		out = append(out, Tunnel{
			Token:  tok,
			Name:   pick(m, "name", "tunnel_name"),
			Server: pick(m, "server", "server_name", "hostname"),
			IP:     stripPrefix(pick(m, "assigned_ip", "assigned_ipv4", "ipv4", "ip_address", "address")),
			Raw:    m,
		})
	}
	return out, nil
}

func (c *Client) TunnelByName(name string) (*Tunnel, error) {
	ts, err := c.Tunnels()
	if err != nil {
		return nil, err
	}
	var hits []Tunnel
	for _, t := range ts {
		if t.Name == name {
			hits = append(hits, t)
		}
	}
	switch len(hits) {
	case 0:
		return nil, nil
	case 1:
		return &hits[0], nil
	default:
		return nil, fmt.Errorf("%d tunnels are named %q; rename or delete the extras in the portal first", len(hits), name)
	}
}

func (c *Client) CreateTunnel(server, name string) error {
	_, err := c.Call("create_tunnel", map[string]string{"server": server, "name": name, "type": "wireguard"}, true)
	return err
}

func (c *Client) DeleteTunnel(tunnelToken string) error {
	_, err := c.Call("delete_tunnel", map[string]string{"tunnel_token": tunnelToken}, true)
	return err
}

// WireGuard returns the raw response of the wireguard endpoint.
func (c *Client) WireGuard(tunnelToken string) (any, error) {
	return c.Call("wireguard", map[string]string{"tunnel_token": tunnelToken}, true)
}

type Rule struct {
	Protocol, SrcIP, DstIP, DstPort string
	TunnelToken                     string         // the tunnel the rule protects
	raw                             map[string]any // as listed; firewall_rule_delete wants every field back
}

// Rules lists the firewall rules of one tunnel, or of every tunnel if
// tunnelToken is empty.
func (c *Client) Rules(tunnelToken string) ([]Rule, error) {
	params := map[string]string{}
	if tunnelToken != "" {
		params["tunnel_token"] = tunnelToken
	}
	data, err := c.Call("firewall_rule_list", params, true)
	if err != nil {
		return nil, err
	}
	var out []Rule
	for _, m := range findObjects(data) {
		out = append(out, Rule{
			Protocol:    strings.ToUpper(pick(m, "protocol")),
			SrcIP:       stripPrefix(pick(m, "src_ip")),
			DstIP:       stripPrefix(pick(m, "dst_ip")),
			DstPort:     pick(m, "dst_port"),
			TunnelToken: pick(m, "tunnel_token"),
			raw:         m,
		})
	}
	return out, nil
}

func (c *Client) AddRule(tunnelToken string, r Rule) error {
	_, err := c.Call("firewall_rule_add", map[string]string{
		"tunnel_token": tunnelToken,
		"protocol":     r.Protocol,
		"src_ip":       r.SrcIP,
		"dst_ip":       r.DstIP,
		"dst_port":     r.DstPort,
	}, true)
	return err
}

func (c *Client) DeleteRule(tunnelToken string, r Rule) error {
	_, err := c.Call("firewall_rule_delete", map[string]string{
		"tunnel_token": tunnelToken,
		"protocol":     firstNonEmpty(pick(r.raw, "protocol"), r.Protocol),
		"src_ip":       firstNonEmpty(pick(r.raw, "src_ip"), r.SrcIP),
		"src_port":     firstNonEmpty(pick(r.raw, "src_port"), "ALL"),
		"dst_ip":       firstNonEmpty(pick(r.raw, "dst_ip"), r.DstIP),
		"dst_port":     firstNonEmpty(pick(r.raw, "dst_port"), r.DstPort),
	}, true)
	return err
}

// ---- JSON helpers ---------------------------------------------------------

// findObjects returns the first non-empty array of objects in the response,
// searching breadth-first. The API returns lists either at the top level or
// under a key like "tunnels" or "data".
func findObjects(data any) []map[string]any {
	queue := []any{data}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		switch v := cur.(type) {
		case []any:
			var objs []map[string]any
			for _, item := range v {
				if m, ok := item.(map[string]any); ok {
					objs = append(objs, m)
				}
			}
			if len(objs) > 0 {
				return objs
			}
		case map[string]any:
			keys := make([]string, 0, len(v))
			for k := range v {
				if k != "context" {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			for _, k := range keys {
				queue = append(queue, v[k])
			}
		}
	}
	return nil
}

// pick returns the first non-empty value among keys (case-insensitive),
// converted to a string.
func pick(m map[string]any, keys ...string) string {
	for _, k := range keys {
		for mk, mv := range m {
			if strings.EqualFold(mk, k) {
				if s := str(mv); s != "" {
					return s
				}
			}
		}
	}
	return ""
}

func str(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%g", t)
	case bool:
		if t {
			return "1"
		}
		return "0"
	case []any:
		parts := make([]string, 0, len(t))
		for _, x := range t {
			if s := str(x); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ", ")
	default:
		return ""
	}
}

func stripPrefix(ip string) string {
	ip = strings.TrimSpace(ip)
	if i := strings.IndexByte(ip, ','); i >= 0 {
		ip = strings.TrimSpace(ip[:i])
	}
	if i := strings.IndexByte(ip, '/'); i >= 0 {
		ip = ip[:i]
	}
	return ip
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// redact masks anything that looks like a credential before debug output.
func redact(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			lk := strings.ToLower(k)
			if lk == "context" {
				out[k] = "(omitted)"
				continue
			}
			if strings.Contains(lk, "private") || strings.Contains(lk, "token") || strings.Contains(lk, "secret") || lk == "key" {
				if s, ok := val.(string); ok && s != "" {
					out[k] = "***redacted***"
					continue
				}
			}
			out[k] = redact(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = redact(x)
		}
		return out
	case string:
		if strings.Contains(t, "PrivateKey") {
			return redactConf(t)
		}
		return t
	default:
		return v
	}
}

func redactConf(conf string) string {
	lines := strings.Split(conf, "\n")
	for i, l := range lines {
		k, _, ok := strings.Cut(l, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "PrivateKey") {
			lines[i] = "PrivateKey = ***redacted***"
		}
	}
	return strings.Join(lines, "\n")
}
