package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Remote runs commands on the server through the local ssh binary, so the
// user's ~/.ssh/config, keys and agent all apply.
//
// The Remote from NewRemote keeps one connection open (an ssh control master
// that closes itself a minute after its last use) and runs every call
// through it, so a password is asked for once per command, not once per
// call. Mesh and Fresh never share it: each of their calls is a real login.
type Remote struct {
	Host     string
	SSH      string // ssh binary, overridable via DXX_SSH for tests
	DryRun   bool
	Opts     []string // extra ssh options, placed before the host
	Password bool     // set by Connect: the server asks for a password
	prompts  bool     // calls may prompt on the terminal: no spinner, stderr stays attached
}

// Mesh returns a Remote that reaches the same server over its doxx mesh IP.
// It reuses the user's ssh config for host (user, keys, port) and the known
// host key via HostKeyAlias, and never shares a control socket with the
// public connection, so a successful call really proves the mesh path works.
func (r *Remote) Mesh(meshIP, keyAlias string) *Remote {
	opts := []string{
		"-o", "HostName=" + meshIP,
		"-o", "ConnectTimeout=10",
		"-o", "ServerAliveInterval=5",
		"-o", "ServerAliveCountMax=2",
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
	}
	if keyAlias != "" {
		opts = append(opts, "-o", "HostKeyAlias="+keyAlias)
	}
	return &Remote{Host: r.Host, SSH: r.SSH, DryRun: r.DryRun, Opts: opts, Password: r.Password, prompts: r.Password}
}

// Fresh returns a Remote that never reuses a control socket, so it reflects
// whether a fresh public connection is possible.
func (r *Remote) Fresh() *Remote {
	return &Remote{Host: r.Host, SSH: r.SSH, DryRun: r.DryRun, Opts: freshOpts, Password: r.Password, prompts: r.Password}
}

var freshOpts = []string{"-o", "ConnectTimeout=10", "-o", "ControlMaster=no", "-o", "ControlPath=none"}

// Connect opens the shared connection. Without a usable key or agent it
// falls back to an interactive login, which is where the one password prompt
// happens, and records that in Password.
func (r *Remote) Connect() error {
	batch := append([]string{"-o", "BatchMode=yes"}, r.Opts...)
	if exec.Command(r.SSH, append(batch, r.Host, "--", "true")...).Run() == nil {
		return nil
	}
	cmd := exec.Command(r.SSH, append(append([]string{}, r.Opts...), r.Host, "--", "true")...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh %s: %w", r.Host, err)
	}
	// The first try also fails on a host key question; only a fresh
	// non-interactive login tells whether a password was really needed.
	r.Password = !r.keyLoginWorks()
	return nil
}

func (r *Remote) keyLoginWorks() bool {
	args := append(append([]string{"-o", "BatchMode=yes"}, freshOpts...), r.Host, "--", "true")
	return exec.Command(r.SSH, args...).Run() == nil
}

// spin is spin for a step that talks to this server. Where ssh may ask for
// a password mid-step it prints a plain line, so the prompt stays readable.
func (r *Remote) spin(f string, a ...any) (stop func()) {
	if r.prompts {
		info(f, a...)
		return func() {}
	}
	return spin(f, a...)
}

// installKeyScript appends the public key on stdin to authorized_keys unless
// that exact line is already there.
const installKeyScript = `umask 077
mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys || exit 1
k=$(cat)
grep -qxF -- "$k" ~/.ssh/authorized_keys && exit 0
[ -z "$(tail -c1 ~/.ssh/authorized_keys)" ] || echo >> ~/.ssh/authorized_keys
printf '%s\n' "$k" >> ~/.ssh/authorized_keys`

func (r *Remote) InstallKey(pub string) error {
	_, err := r.Run(installKeyScript, []byte(pub+"\n"))
	return err
}

// localPublicKey finds the public key ssh would offer to this host: the
// .pub next to a configured identity file, or the first key in the agent.
func (r *Remote) localPublicKey() (key, from string) {
	home, _ := os.UserHomeDir()
	if out, err := exec.Command(r.SSH, "-G", r.Host).Output(); err == nil {
		for _, l := range strings.Split(string(out), "\n") {
			k, v, _ := strings.Cut(strings.TrimSpace(l), " ")
			if k != "identityfile" {
				continue
			}
			path := strings.TrimSpace(v) + ".pub"
			if strings.HasPrefix(path, "~/") {
				path = filepath.Join(home, path[2:])
			}
			if b, err := os.ReadFile(path); err == nil && isPublicKey(string(b)) {
				return strings.TrimSpace(string(b)), strings.Replace(path, home, "~", 1)
			}
		}
	}
	if out, err := exec.Command("ssh-add", "-L").Output(); err == nil {
		if first, _, _ := strings.Cut(string(out), "\n"); isPublicKey(first) {
			return strings.TrimSpace(first), "ssh-agent"
		}
	}
	return "", ""
}

func isPublicKey(s string) bool {
	f := strings.Fields(s)
	return len(f) >= 2 && !strings.Contains(strings.TrimSpace(s), "\n") &&
		(strings.HasPrefix(f[0], "ssh-") || strings.HasPrefix(f[0], "ecdsa-") || strings.HasPrefix(f[0], "sk-"))
}

// SSHConfig resolves host through `ssh -G`, returning keys such as hostname,
// port and user.
func (r *Remote) SSHConfig() (map[string]string, error) {
	out, err := exec.Command(r.SSH, "-G", r.Host).Output()
	if err != nil {
		return nil, fmt.Errorf("ssh -G %s: %w", r.Host, err)
	}
	cfg := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if ok {
			if _, seen := cfg[k]; !seen {
				cfg[k] = strings.TrimSpace(v)
			}
		}
	}
	return cfg, nil
}

func NewRemote(host string, dry bool) *Remote {
	bin := os.Getenv("DXX_SSH")
	if bin == "" {
		bin = "ssh"
	}
	// The socket path is kept short: unix socket paths end at ~104 bytes.
	dir := filepath.Join(filepath.Dir(statePath()), "cm")
	_ = os.MkdirAll(dir, 0o700)
	sock := filepath.Join(dir, fmt.Sprintf("%x", sha256.Sum256([]byte(host)))[:12])
	return &Remote{Host: host, SSH: bin, DryRun: dry, Opts: []string{
		"-o", "ControlMaster=auto", "-o", "ControlPath=" + sock, "-o", "ControlPersist=60",
	}}
}

// Run executes script on the server. stdin may be nil. Output is returned;
// stderr is kept out of the way and attached to the error if the call fails.
func (r *Remote) Run(script string, stdin []byte) (string, error) {
	args := append(append([]string{}, r.Opts...), r.Host, "--", script)
	cmd := exec.Command(r.SSH, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if r.prompts {
		cmd.Stderr = os.Stderr
	}
	err := cmd.Run()
	if err != nil {
		if msg := strings.TrimSpace(errb.String()); msg != "" {
			return out.String(), fmt.Errorf("ssh %s: %w\n%s", r.Host, err, indent(msg))
		}
		return out.String(), fmt.Errorf("ssh %s: %w", r.Host, err)
	}
	return out.String(), nil
}

// sudoPrelude makes every remote script work as root or via passwordless sudo.
const sudoPrelude = `S=""; if [ "$(id -u)" != 0 ]; then S="sudo -n"; fi; `

type Preflight struct {
	UID        string
	SudoOK     bool
	HasWG      bool
	WGIfaces   []string
	DoxxIfaces []string          // interfaces that already carry a doxx.net address
	Routes10   map[string]string // 10.x prefix -> device
	ConfExists bool
	OS         string
}

func (r *Remote) Preflight(iface string) (*Preflight, error) {
	script := sudoPrelude + `
echo "uid=$(id -u)"
if [ -n "$S" ]; then if sudo -n true 2>/dev/null; then echo sudo=ok; else echo sudo=no; fi; else echo sudo=ok; fi
if [ -r /etc/os-release ]; then . /etc/os-release; echo "os=$ID-$VERSION_ID"; fi
if command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1; then echo wg=yes; else echo wg=no; fi
ip -o link show type wireguard 2>/dev/null | awk -F': ' '{split($2,a,"@"); print "wgif=" a[1]}'
ip -o -6 addr show 2>/dev/null | awk '/2602:f5c1/ {print "doxxif=" $2}'
ip -o -4 addr show 2>/dev/null | awk '$4 ~ /^10\./ {print "addr10=" $2}'
ip -4 route show 2>/dev/null | awk '$1 ~ /^10\./ {d=""; for(i=1;i<=NF;i++) if($i=="dev") d=$(i+1); print "route10=" $1 "@" d}'
if $S test -e /etc/wireguard/` + shellQuote(iface) + `.conf 2>/dev/null; then echo conf=yes; fi
`
	out, err := r.Run(script, nil)
	if err != nil {
		return nil, err
	}
	p := &Preflight{Routes10: map[string]string{}}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		switch k {
		case "uid":
			p.UID = v
		case "sudo":
			p.SudoOK = v == "ok"
		case "os":
			p.OS = v
		case "wg":
			p.HasWG = v == "yes"
		case "wgif":
			p.WGIfaces = appendUniq(p.WGIfaces, v)
		case "doxxif":
			p.DoxxIfaces = appendUniq(p.DoxxIfaces, v)
		case "route10":
			prefix, dev, _ := strings.Cut(v, "@")
			p.Routes10[prefix] = dev
		case "conf":
			p.ConfExists = true
		}
	}
	if p.UID == "" {
		return nil, fmt.Errorf("preflight on %s returned no data; is it a Linux host with a POSIX shell?", r.Host)
	}
	return p, nil
}

func (r *Remote) InstallWireGuard() error {
	_, err := r.Run(sudoPrelude+`
if command -v apt-get >/dev/null 2>&1; then
  $S env DEBIAN_FRONTEND=noninteractive apt-get update -qq &&
  $S env DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 apt-get install -y -qq wireguard-tools
elif command -v dnf >/dev/null 2>&1; then
  $S dnf install -y wireguard-tools
else
  echo "no supported package manager; install wireguard-tools manually" >&2; exit 1
fi`, nil)
	return err
}

// WriteConf writes the config atomically with mode 600. The config travels
// over the ssh stdin, never on a command line.
func (r *Remote) WriteConf(iface, conf string) error {
	path := "/etc/wireguard/" + iface + ".conf"
	inner := "umask 077 && mkdir -p /etc/wireguard && cat > " + shellQuote(path+".tmp") + " && chmod 600 " + shellQuote(path+".tmp") + " && mv " + shellQuote(path+".tmp") + " " + shellQuote(path)
	_, err := r.Run(sudoPrelude+`$S sh -c `+shellQuote(inner), []byte(conf))
	return err
}

func (r *Remote) Enable(iface string) error {
	unit := shellQuote("wg-quick@" + iface)
	_, err := r.Run(sudoPrelude+`$S systemctl enable --quiet `+unit+` && $S systemctl restart `+unit+` || { $S journalctl -u `+unit+` -n 20 --no-pager >&2; exit 1; }`, nil)
	return err
}

// WaitHandshake polls for a WireGuard handshake for up to ~20 seconds.
func (r *Remote) WaitHandshake(iface string) (bool, error) {
	out, err := r.Run(sudoPrelude+`
i=0
while [ $i -lt 20 ]; do
  t=$($S wg show `+shellQuote(iface)+` latest-handshakes 2>/dev/null | awk '{print $2}' | sort -n | tail -1)
  if [ -n "$t" ] && [ "$t" != 0 ]; then echo handshake=ok; exit 0; fi
  i=$((i+1)); sleep 1
done
echo handshake=none`, nil)
	if err != nil {
		return false, err
	}
	return strings.Contains(out, "handshake=ok"), nil
}

var pingHostRe = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)

// FastestServer pings the doxx locations from the server, a few at a time,
// and returns the one closest to it. ok is false if nothing could be measured
// (no ping on the server, ICMP blocked).
func (r *Remote) FastestServer(servers []Server) (best Server, rtt time.Duration, ok bool) {
	byHost := map[string]Server{}
	var hosts []string
	for _, s := range servers {
		if pingHostRe.MatchString(s.Hostname) {
			byHost[s.Hostname] = s
			hosts = append(hosts, s.Hostname)
		}
	}
	if len(hosts) == 0 {
		return Server{}, 0, false
	}
	out, err := r.Run(`printf '%s\n' `+strings.Join(hosts, " ")+` | xargs -P 4 -I{} sh -c 'echo "rtt {} $(ping -c 2 -W 2 {} 2>/dev/null | tail -1)"'`, nil)
	if err != nil {
		return Server{}, 0, false
	}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 3 || f[0] != "rtt" {
			continue
		}
		s, known := byHost[f[1]]
		if d := parsePingMin([]byte(l)); known && d > 0 && (!ok || d < rtt) {
			best, rtt, ok = s, d, true
		}
	}
	return best, rtt, ok
}

func (r *Remote) Teardown(iface string) error {
	unit := shellQuote("wg-quick@" + iface)
	path := shellQuote("/etc/wireguard/" + iface + ".conf")
	out, err := r.Run(sudoPrelude+`if $S systemctl is-active --quiet dxx-lock.service 2>/dev/null; then echo locked; exit 0; fi; $S systemctl disable --now --quiet `+unit+` 2>/dev/null; $S rm -f `+path+`; echo removed`, nil)
	if err != nil {
		return err
	}
	if strings.Contains(out, "locked") {
		return fmt.Errorf("server is locked to doxx: removing the tunnel would lock you out. Run `dxx unlock` first")
	}
	return nil
}

func (r *Remote) InstallTerminfo(term string) error {
	desc, err := exec.Command("infocmp", "-x", term).Output()
	if err != nil {
		return fmt.Errorf("infocmp -x %s failed locally (is that terminal installed here?): %w", term, err)
	}
	_, err = r.Run(sudoPrelude+`$S tic -x -`, desc)
	return err
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func appendUniq(xs []string, v string) []string {
	for _, x := range xs {
		if x == v {
			return xs
		}
	}
	return append(xs, v)
}
