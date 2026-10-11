package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Lock model
//
// lock installs a small nftables table (inet dxx) that runs before
// UFW/iptables and, on every interface except lo and the doxx interface,
// drops new SSH connections (or, with --all, every new inbound connection).
// Established connections are kept, so the session doing the lock is never
// cut mid-command. The table is loaded at boot by dxx-lock.service.
//
// Safety net: before locking, a transient systemd timer is armed on the
// server that removes the lock after --confirm seconds. dxx disarms it
// only after a fresh SSH login over the mesh succeeds. If anything goes wrong
// you are back to public SSH within minutes, without touching the console.

const (
	lockUnit     = "dxx-lock.service"
	rollbackUnit = "dxx-rollback"
	nftTable     = "inet dxx"
)

func nftRuleset(iface string, ports []int, all bool) string {
	var b strings.Builder
	b.WriteString("# managed by dxx: inbound only via the doxx mesh\n")
	b.WriteString("table inet dxx {}\ndelete table inet dxx\n")
	b.WriteString("table inet dxx {\n\tchain input {\n")
	b.WriteString("\t\ttype filter hook input priority -10; policy accept;\n")
	b.WriteString("\t\tiifname \"lo\" accept\n")
	fmt.Fprintf(&b, "\t\tiifname %q accept\n", iface)
	b.WriteString("\t\tct state established,related accept\n")
	if all {
		b.WriteString("\t\tmeta l4proto { icmp, ipv6-icmp } accept\n")
		b.WriteString("\t\tudp dport { 68, 546 } accept comment \"dhcp replies\"\n")
		b.WriteString("\t\tcounter drop\n")
	} else {
		ps := make([]string, len(ports))
		for i, p := range ports {
			ps[i] = strconv.Itoa(p)
		}
		fmt.Fprintf(&b, "\t\ttcp dport { %s } counter drop\n", strings.Join(ps, ", "))
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}

// lockScript runs as root on the server (fed to `sh -s`). It arms the
// rollback timer first, then installs and starts the lock.
func lockScript(iface string, ports []int, all bool, confirm int) string {
	rollback := fmt.Sprintf("systemctl disable --now %s 2>/dev/null; nft delete table %s 2>/dev/null; true", lockUnit, nftTable)
	ufwPorts := ""
	for _, p := range ports {
		ufwPorts += fmt.Sprintf("  ufw allow in on %s to any port %d proto tcp >/dev/null\n", shellQuote(iface), p)
	}
	return `set -e
if ! command -v nft >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables
fi
NFT=$(command -v nft)
ip link show dev ` + shellQuote(iface) + ` >/dev/null 2>&1 || { echo "interface ` + iface + ` is not up; run dxx up first" >&2; exit 1; }

# 1. safety net first
systemctl stop ` + rollbackUnit + `.timer 2>/dev/null || true
systemctl reset-failed ` + rollbackUnit + `.timer ` + rollbackUnit + `.service 2>/dev/null || true
systemd-run --quiet --unit=` + rollbackUnit + ` --on-active=` + strconv.Itoa(confirm) + ` /bin/sh -c ` + shellQuote(rollback) + `
echo armed

# 2. if UFW is active, make sure it lets SSH in over the mesh
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
` + ufwPorts + `  echo ufw=allowed
fi

# 3. the lock
mkdir -p /etc/dxx
cat > /etc/dxx/lock.nft <<'DOXXEOF'
` + nftRuleset(iface, ports, all) + `DOXXEOF
"$NFT" -c -f /etc/dxx/lock.nft
cat > /etc/systemd/system/` + lockUnit + ` <<DOXXEOF
[Unit]
Description=dxx: accept inbound only via the doxx mesh
DefaultDependencies=no
After=local-fs.target
Wants=network-pre.target
Before=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$NFT -f /etc/dxx/lock.nft
ExecStop=$NFT delete table ` + nftTable + `

[Install]
WantedBy=multi-user.target
DOXXEOF
systemctl daemon-reload
systemctl enable --quiet ` + lockUnit + `
systemctl restart ` + lockUnit + `
echo locked
`
}

const unlockScript = `set +e
systemctl stop ` + rollbackUnit + `.timer 2>/dev/null
systemctl disable --now --quiet ` + lockUnit + ` 2>/dev/null
nft delete table ` + nftTable + ` 2>/dev/null
rm -f /etc/systemd/system/` + lockUnit + ` /etc/dxx/lock.nft
systemctl daemon-reload
rmdir /etc/dxx 2>/dev/null
echo unlocked
`

// ---- commands -------------------------------------------------------------

func cmdLock(args []string) error {
	fs := flag.NewFlagSet("lock", flag.ExitOnError)
	iface := fs.String("iface", "doxx0", "doxx WireGuard interface on the server")
	portsFlag := fs.String("ports", "", "TCP ports to close publicly (default: the server's SSH port)")
	all := fs.Bool("all", false, "drop ALL new public inbound traffic, not just SSH (web servers become mesh-only too)")
	confirm := fs.Int("confirm", 300, "seconds until the automatic rollback, unless the mesh login is confirmed")
	dry := fs.Bool("dry-run", false, "show the firewall rules without changing anything")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: dxx lock <name|ssh-host> [flags]")
		fs.PrintDefaults()
	}
	tgt, err := parseTarget(fs, args)
	if err != nil {
		return err
	}
	host, key := tgt.Dest, tgt.Key
	if !ifaceRe.MatchString(*iface) {
		return fmt.Errorf("invalid --iface %q", *iface)
	}
	if *confirm < 60 {
		return errors.New("--confirm must be at least 60 seconds")
	}

	pub := NewRemote(host, false)
	cfg, err := pub.SSHConfig()
	if err != nil {
		return err
	}
	pubHost, sshPort := cfg["hostname"], cfg["port"]
	if sshPort == "" {
		sshPort = "22"
	}
	ports, err := parsePorts(*portsFlag, sshPort)
	if err != nil {
		return err
	}

	if *dry {
		step("Dry run: rules that lock would install on %s", host)
		fmt.Print(indent(nftRuleset(*iface, ports, *all)))
		return nil
	}

	// 1. Read the mesh IP over the public path.
	step("Checking %s", host)
	if err := pub.Connect(); err != nil {
		return err
	}
	if pub.Password {
		info("password login: the fresh logins below each ask again (dxx up %s offers to install your SSH key)", key)
	}
	stop := pub.spin("looking at the server")
	out, err := pub.Run(sudoPrelude+`ip -4 -o addr show dev `+shellQuote(*iface)+` 2>/dev/null | awk '{print "mesh=" $4}'
if $S systemctl is-active --quiet `+lockUnit+` 2>/dev/null; then echo state=locked; fi
t=$($S wg show `+shellQuote(*iface)+` latest-handshakes 2>/dev/null | awk '{print $2}' | sort -n | tail -1)
[ -n "$t" ] && [ "$t" != 0 ] && echo handshake=ok`, nil)
	stop()
	if err != nil {
		return err
	}
	kv := parseKV(out)
	meshIP := stripPrefix(kv["mesh"])
	if meshIP == "" {
		return fmt.Errorf("%s has no address on %s; run dxx up first", host, *iface)
	}
	if kv["handshake"] != "ok" {
		return fmt.Errorf("%s on the server has no handshake with doxx.net; fix that before locking", *iface)
	}
	ok("tunnel up, mesh IP %s", meshIP)
	if kv["state"] == "locked" {
		info("already locked, re-applying")
	}

	// 2. Prove the mesh path works BEFORE changing anything.
	step("Testing SSH over the mesh (%s)", meshIP)
	mesh := pub.Mesh(meshIP, pubHost)
	stop = mesh.spin("logging in over the mesh")
	_, err = mesh.Run("echo ok", nil)
	stop()
	if err != nil {
		return fmt.Errorf("SSH over the mesh failed, nothing was changed.\n" +
			"  Check: is this computer connected to doxx (dxx connect)? Did you run `up --allow-from <this-computer's-tunnel>`?")
	}
	ok("mesh login works")

	// 3. Arm the rollback and lock, in a single public session.
	step("Locking (automatic rollback in %s unless confirmed)", time.Duration(*confirm)*time.Second)
	fresh := pub.Fresh()
	stop = fresh.spin("installing the firewall")
	out, err = fresh.Run(sudoPrelude+`$S sh -s`, []byte(lockScript(*iface, ports, *all, *confirm)))
	stop()
	if err != nil {
		if strings.Contains(out, "armed") {
			return fmt.Errorf("locking failed after the rollback was armed: public SSH comes back within %ds either way", *confirm)
		}
		return fmt.Errorf("locking failed, nothing was changed: %w", err)
	}
	if strings.Contains(out, "ufw=allowed") {
		ok("UFW: SSH allowed on %s", *iface)
	}
	ok("firewall installed (survives reboots)")

	// 4. Confirm with a brand-new mesh session, then disarm.
	step("Confirming over the mesh")
	var cerr error
	stop = mesh.spin("logging in over the mesh again")
	for i := 0; i < 3; i++ {
		if _, cerr = mesh.Run(sudoPrelude+`$S systemctl stop `+rollbackUnit+`.timer && echo disarmed`, nil); cerr == nil {
			break
		}
		time.Sleep(3 * time.Second)
	}
	stop()
	if cerr != nil {
		return fmt.Errorf("could not log in over the mesh after locking.\n"+
			"  The rollback restores public SSH automatically in about %ds. Wait, then check what's wrong.", *confirm)
	}
	ok("mesh login confirmed, rollback disarmed")

	// 5. Check the public door from here.
	if pubHost != "" && contains(ports, sshPort) {
		if portOpen(pubHost, sshPort) {
			warn("public %s:%s still accepts connections. Is that address actually the server's public IP?", pubHost, sshPort)
		} else {
			ok("public %s:%s no longer reachable", pubHost, sshPort)
		}
	}

	_ = saveState(key, hostState{Dest: host, MeshIP: meshIP, Iface: *iface})
	step("Locked")
	alias := key
	if key == host {
		alias = strings.TrimPrefix(defaultName(host), "dxx-")
	}
	fmt.Printf("  Connect (doxx on):  dxx %s\n", key)
	fmt.Printf("  For scp/rsync/VS Code, add to ~/.ssh/config:\n\n    Host %s-doxx\n      HostName %s\n      HostKeyAlias %s\n      User %s\n\n",
		alias, meshIP, pubHost, firstNonEmpty(cfg["user"], "root"))
	fmt.Printf("  Undo:  dxx unlock %s\n", key)
	fmt.Println("  Emergency (Hetzner web console):  systemctl disable --now " + lockUnit + "; nft delete table " + nftTable)
	return nil
}

func cmdUnlock(args []string) error {
	fs := flag.NewFlagSet("unlock", flag.ExitOnError)
	meshFlag := fs.String("mesh-ip", "", "the server's doxx mesh IP (default: remembered from lock/up)")
	tgt, err := parseTarget(fs, args)
	if err != nil {
		return err
	}
	host := tgt.Dest
	pub := NewRemote(host, false)
	cfg, err := pub.SSHConfig()
	if err != nil {
		return err
	}
	// Public SSH may be closed, so there is no shared connection to open and
	// no way to know up front whether a login will ask for a password.
	pub.Password = true
	meshIP := firstNonEmpty(*meshFlag, tgt.State.MeshIP)

	step("Unlocking %s", host)
	if err := unlockServer(pub, cfg["hostname"], meshIP); err != nil {
		return err
	}
	ok("lock removed")
	port := firstNonEmpty(cfg["port"], "22")
	if h := cfg["hostname"]; h != "" {
		if portOpen(h, port) {
			ok("public %s:%s reachable again", h, port)
		} else {
			warn("public %s:%s still not reachable from here; check the Hetzner cloud firewall", h, port)
		}
	}
	return nil
}

// unlockServer removes the lock over the mesh, or over public SSH if the
// mesh path does not work. It is safe to run on a server that is not locked.
func unlockServer(pub *Remote, pubHost, meshIP string) error {
	var out string
	var runErr error = errors.New("no mesh IP known")
	if meshIP != "" {
		info("via mesh %s", meshIP)
		out, runErr = pub.Mesh(meshIP, pubHost).Run(sudoPrelude+`$S sh -s`, []byte(unlockScript))
	}
	if runErr != nil {
		info("mesh not available, trying public SSH")
		out, runErr = pub.Fresh().Run(sudoPrelude+`$S sh -s`, []byte(unlockScript))
	}
	if runErr != nil || !strings.Contains(out, "unlocked") {
		return fmt.Errorf("could not reach the server over the mesh or publicly.\n" +
			"  Use the Hetzner web console and run:\n    systemctl disable --now " + lockUnit + "; nft delete table " + nftTable)
	}
	return nil
}

// ---- helpers --------------------------------------------------------------

func parsePorts(flagVal, sshPort string) ([]int, error) {
	src := flagVal
	if src == "" {
		src = sshPort
	}
	var ports []int
	for _, p := range strings.Split(src, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port %q", p)
		}
		ports = append(ports, n)
	}
	return ports, nil
}

func contains(ports []int, p string) bool {
	n, _ := strconv.Atoi(p)
	for _, x := range ports {
		if x == n {
			return true
		}
	}
	return false
}

func portOpen(host, port string) bool {
	timeout := 5 * time.Second
	if v := os.Getenv("DXX_DIAL_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			timeout = d
		}
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func parseKV(out string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok {
			m[k] = v
		}
	}
	return m
}

func indent(s string) string {
	return "  " + strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n  ") + "\n"
}
