package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"
)

// meshRanges are the doxx.net mesh prefixes ("chat-only" scope in the doxx
// docs). Routing only these through the tunnel leaves the server's default
// route, public SSH and DNS resolver untouched.
var meshRanges = []string{"10.0.0.0/8", "2602:f5c1::/36"}

// RenderConfig turns the wireguard endpoint's response into a wg-quick config
// that is safe for a remote server:
//   - AllowedIPs limited to the doxx mesh (never the default route)
//   - DNS lines removed (wg-quick would otherwise replace the system resolver)
//   - PersistentKeepalive set so the outbound tunnel stays up behind NAT
func RenderConfig(resp any) (string, error) {
	if raw := findConfString(resp); raw != "" {
		return rewriteConf(raw)
	}
	m, ok := resp.(map[string]any)
	if !ok {
		return "", fmt.Errorf("unexpected wireguard response shape; run with --debug and check the fields")
	}
	// Some responses nest the config under a key such as "config" or "wireguard".
	for _, k := range []string{"config", "wireguard", "data", "tunnel"} {
		if sub, ok := m[k].(map[string]any); ok {
			m = mergeMaps(m, sub)
		}
	}
	priv := pick(m, "private_key", "privatekey", "client_private_key", "interface_private_key")
	addr4 := pick(m, "assigned_ipv4", "assigned_ip", "ipv4", "address", "interface_address", "ip")
	addr6 := pick(m, "assigned_ipv6", "ipv6", "ipv6_address")
	peer := pick(m, "server_public_key", "server_pubkey", "peer_public_key", "public_key_server")
	endpoint := pick(m, "endpoint", "server_endpoint", "peer_endpoint")
	// The live API splits the config like the file: {"interface": {...}, "peer": {...}}.
	// Both halves have a "public_key"/"address"-style key, so read each from its own half.
	if ifc, ok := m["interface"].(map[string]any); ok {
		priv = firstNonEmpty(pick(ifc, "private_key", "privatekey"), priv)
		addr4 = firstNonEmpty(pick(ifc, "address", "addresses"), addr4)
	}
	if p, ok := m["peer"].(map[string]any); ok {
		peer = firstNonEmpty(pick(p, "public_key", "publickey"), peer)
		endpoint = firstNonEmpty(pick(p, "endpoint"), endpoint)
	}

	var missing []string
	if priv == "" {
		missing = append(missing, "private key")
	}
	if addr4 == "" && addr6 == "" {
		missing = append(missing, "address")
	}
	if peer == "" {
		missing = append(missing, "server public key")
	}
	if endpoint == "" {
		missing = append(missing, "endpoint")
	}
	if len(missing) > 0 {
		return "", fmt.Errorf("wireguard response is missing %s; run with --debug to see the (redacted) fields", strings.Join(missing, ", "))
	}

	// Validate before interpolation: a JSON string must never add config lines.
	for _, value := range []string{priv, addr4, addr6, peer, endpoint} {
		if strings.ContainsAny(value, "\r\n\x00") {
			return "", fmt.Errorf("wireguard field contains a control character")
		}
	}

	var addrs []string
	for _, a := range []string{addr4, addr6} {
		for _, part := range strings.Split(a, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if !strings.Contains(part, "/") {
				if strings.Contains(part, ":") {
					part += "/128"
				} else {
					part += "/32"
				}
			}
			addrs = append(addrs, part)
		}
	}
	var b strings.Builder
	b.WriteString("# managed by dxx\n[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", priv)
	fmt.Fprintf(&b, "Address = %s\n", strings.Join(addrs, ", "))
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", peer)
	fmt.Fprintf(&b, "Endpoint = %s\n", endpoint)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(meshRanges, ", "))
	b.WriteString("PersistentKeepalive = 25\n")
	return rewriteConf(b.String())
}

// rewriteConf parses downloaded text and emits only validated, supported fields.
// Strip comments before recognizing sections, just as wg-quick does. Never
// retain arbitrary source lines: wg-quick extensions can execute root commands.
func rewriteConf(raw string) (string, error) {
	var out []string
	section := ""
	seen := map[string]bool{}
	sawInterface, sawPeer := false, false
	finish := func() error {
		switch section {
		case "interface":
			if !seen["privatekey"] || !seen["address"] {
				return fmt.Errorf("wireguard interface requires PrivateKey and Address")
			}
		case "peer":
			if !seen["publickey"] || !seen["endpoint"] {
				return fmt.Errorf("wireguard peer requires PublicKey and Endpoint")
			}
			out = append(out, "AllowedIPs = "+strings.Join(meshRanges, ", "), "PersistentKeepalive = 25")
		}
		return nil
	}
	out = append(out, "# managed by dxx")
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line, _, _ = strings.Cut(line, "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if err := finish(); err != nil {
				return "", err
			}
			seen = map[string]bool{}
			switch strings.ToLower(line) {
			case "[interface]":
				if sawInterface || sawPeer {
					return "", fmt.Errorf("wireguard config has a repeated or misplaced Interface section")
				}
				sawInterface, section = true, "interface"
				out = append(out, "[Interface]")
			case "[peer]":
				if !sawInterface {
					return "", fmt.Errorf("wireguard config must start with Interface")
				}
				sawPeer, section = true, "peer"
				out = append(out, "", "[Peer]")
			default:
				return "", fmt.Errorf("wireguard config has an unsupported section")
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || section == "" {
			return "", fmt.Errorf("malformed wireguard config field")
		}
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
		canonical := ""
		if section == "interface" {
			canonical = map[string]string{"privatekey": "PrivateKey", "address": "Address", "listenport": "ListenPort", "mtu": "MTU"}[key]
		} else {
			canonical = map[string]string{"publickey": "PublicKey", "presharedkey": "PresharedKey", "endpoint": "Endpoint"}[key]
		}
		if canonical == "" {
			continue // Discard hooks, DNS, routing overrides and unknown extensions.
		}
		if seen[key] && key != "address" {
			return "", fmt.Errorf("duplicate wireguard %s field", canonical)
		}
		if err := validateWGField(key, value); err != nil {
			return "", fmt.Errorf("invalid wireguard %s: %s", canonical, err)
		}
		seen[key] = true
		out = append(out, canonical+" = "+value)
	}
	if err := finish(); err != nil {
		return "", err
	}
	if !sawPeer {
		return "", fmt.Errorf("wireguard config has no [Peer] section")
	}
	return strings.Join(out, "\n") + "\n", nil
}

// Errors deliberately omit values, which may contain private keys.
func validateWGField(key, value string) error {
	if value == "" || strings.ContainsFunc(value, unicode.IsControl) {
		return fmt.Errorf("empty value or control character")
	}
	switch key {
	case "privatekey", "publickey", "presharedkey":
		b, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || len(b) != 32 {
			return fmt.Errorf("expected a base64-encoded 32-byte key")
		}
	case "address":
		for _, addr := range strings.Split(value, ",") {
			addr = strings.TrimSpace(addr)
			if net.ParseIP(addr) == nil {
				if _, _, err := net.ParseCIDR(addr); err != nil {
					return fmt.Errorf("expected IP addresses with optional prefixes")
				}
			}
		}
	case "endpoint":
		host, port, err := net.SplitHostPort(value)
		if err != nil || host == "" {
			return fmt.Errorf("expected host:port")
		}
		if net.ParseIP(host) == nil {
			for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
				if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
					return fmt.Errorf("invalid endpoint hostname")
				}
				for _, c := range label {
					if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
						return fmt.Errorf("invalid endpoint hostname")
					}
				}
			}
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("invalid endpoint port")
		}
	case "listenport", "mtu":
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 || n > 65535 || (key == "mtu" && n == 0) {
			return fmt.Errorf("invalid numeric value")
		}
	}
	return nil
}

// findConfString looks for a string value that already is a wg-quick config.
func findConfString(v any) string {
	switch t := v.(type) {
	case string:
		if strings.Contains(strings.ToLower(t), "[interface]") && strings.Contains(strings.ToLower(t), "[peer]") {
			return t
		}
	case map[string]any:
		for k, val := range t {
			if k == "context" {
				continue
			}
			if s := findConfString(val); s != "" {
				return s
			}
		}
	case []any:
		for _, val := range t {
			if s := findConfString(val); s != "" {
				return s
			}
		}
	}
	return ""
}

// ConfAddress returns the first IPv4 address from the [Interface] section.
func ConfAddress(conf string) string {
	section := ""
	for _, line := range strings.Split(conf, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			section = strings.ToLower(t)
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok || section != "[interface]" || !strings.EqualFold(strings.TrimSpace(k), "Address") {
			continue
		}
		for _, a := range strings.Split(v, ",") {
			a = stripPrefix(a)
			if a != "" && !strings.Contains(a, ":") {
				return a
			}
		}
	}
	return ""
}

func mergeMaps(base, over map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}

// PinEndpoint replaces a [Peer] Endpoint hostname with one of its addresses
// that lies outside the mesh ranges, preferring IPv4. The doxx servers' own
// IPv6 addresses are inside 2602:f5c1::/36, and wg-quick only keeps the
// endpoint off the tunnel for a default route, so a hostname that resolves to
// such an address sends the encrypted packets back into the tunnel: the first
// handshake succeeds and nothing passes afterwards.
func PinEndpoint(conf string, lookup func(host string) ([]net.IP, error)) (string, error) {
	lines := strings.Split(conf, "\n")
	section := ""
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			section = strings.ToLower(t)
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok || section != "[peer]" || !strings.EqualFold(strings.TrimSpace(k), "Endpoint") {
			continue
		}
		host, port, err := net.SplitHostPort(strings.TrimSpace(v))
		if err != nil {
			return "", fmt.Errorf("endpoint %q: %w", strings.TrimSpace(v), err)
		}
		if ip := net.ParseIP(host); ip != nil {
			if isMesh(ip) {
				return "", fmt.Errorf("endpoint %s is inside the doxx mesh range, so it cannot be reached outside the tunnel", host)
			}
			continue
		}
		ips, err := lookup(host)
		if err != nil {
			return "", fmt.Errorf("resolving endpoint %s: %w", host, err)
		}
		var pinned net.IP
		for _, ip := range ips {
			if isMesh(ip) {
				continue
			}
			if ip.To4() != nil {
				pinned = ip
				break
			}
			if pinned == nil {
				pinned = ip
			}
		}
		if pinned == nil {
			return "", fmt.Errorf("endpoint %s only resolves to addresses inside the doxx mesh range (%v)", host, ips)
		}
		lines[i] = "Endpoint = " + net.JoinHostPort(pinned.String(), port)
	}
	return strings.Join(lines, "\n"), nil
}

// pinEndpoint is PinEndpoint with the system resolver. A failed lookup keeps
// the hostname: wg-quick resolves it again on the machine that runs it.
func pinEndpoint(conf string) (string, error) {
	var lookupErr error
	out, err := PinEndpoint(conf, func(host string) ([]net.IP, error) {
		ips, err := net.LookupIP(host)
		lookupErr = err
		return ips, err
	})
	if lookupErr != nil {
		warn("could not resolve the doxx endpoint (%v); keeping the hostname in the config", lookupErr)
		return conf, nil
	}
	return out, err
}
