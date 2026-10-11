package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// connect puts this computer on the doxx mesh, the same way `up` does for a
// server: a tunnel in the doxx account, a mesh-only wg-quick config, and
// `wg-quick up`. Only the mesh ranges are routed, so normal internet traffic
// and DNS stay as they are.
//
// The config lives next to the saved servers as dxx.conf (so the interface
// is called "dxx") and only exists while connected. The tunnel name is
// remembered in dxx-local.json, which `up` uses as the default --allow-from.

const localIface = "dxx"

type localState struct {
	Tunnel string `json:"tunnel,omitempty"` // doxx tunnel name of this computer
	MeshIP string `json:"mesh_ip,omitempty"`
	Server string `json:"server,omitempty"`
}

func localPath() string     { return filepath.Join(filepath.Dir(statePath()), "dxx-local.json") }
func localConfPath() string { return filepath.Join(filepath.Dir(statePath()), localIface+".conf") }

func readLocal() localState {
	var s localState
	if b, err := os.ReadFile(localPath()); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func writeLocal(s localState) error {
	b, _ := json.MarshalIndent(s, "", "  ")
	return writeFile600(localPath(), b)
}

func writeFile600(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ---- commands -------------------------------------------------------------

func cmdConnect(args []string) error {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	server := fs.String("server", "", "doxx.net location hostname for a new tunnel (default: the fastest; see: dxx servers)")
	name := fs.String("name", "", "doxx tunnel name for this computer (default: dxx-<hostname>)")
	dry := fs.Bool("dry-run", false, "show what would happen without changing anything")
	debug := fs.Bool("debug", false, "print redacted API responses")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: dxx connect [flags]")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if fs.NArg() > 0 {
		return fmt.Errorf("connect takes no arguments (got %q); to ssh into a server: dxx <name>", fs.Arg(0))
	}

	wgQuick, toolErr := findWGQuick()
	if toolErr != nil && !*dry {
		return toolErr
	}
	local := readLocal()
	// A tunnel is one device. Bringing a server's tunnel up here as well
	// would make the two fight over it and break both.
	if owner := serverWithTunnel(*name); owner != "" {
		return fmt.Errorf("tunnel %q belongs to the server %s, it can't also be this computer's.\n"+
			"  Run dxx connect without --name; to log in to the server: dxx %s", *name, owner, owner)
	}
	if owner := serverWithTunnel(local.Tunnel); owner != "" {
		warn("this computer was connected with %q, the tunnel of the server %s; switching to its own tunnel", local.Tunnel, owner)
		local.Tunnel = ""
	}
	if *name == "" {
		host, _ := os.Hostname()
		*name = firstNonEmpty(local.Tunnel, defaultName(host))
	}
	tok, err := loadToken()
	if err != nil {
		return err
	}
	api := NewClient(tok, *debug)

	// 1. Tunnel: reuse by name, or create on the fastest location.
	step("Tunnel %q", *name)
	t, err := api.TunnelByName(*name)
	if err != nil {
		return err
	}
	if t == nil {
		if *server == "" {
			srv, err := api.Servers()
			if err != nil {
				return err
			}
			stop := spin("measuring %d locations", len(srv))
			best, rtt, err := fastestServer(srv)
			stop()
			if err != nil {
				return err
			}
			*server = best.Hostname
			info("fastest location: %s (%s, %d ms)", best.Hostname, firstNonEmpty(best.Location, "?"), rtt.Milliseconds())
		}
		if *dry {
			info("would create tunnel %q on %s", *name, *server)
		} else {
			if err := api.CreateTunnel(*server, *name); err != nil {
				return err
			}
			if t, err = api.TunnelByName(*name); err != nil {
				return err
			} else if t == nil {
				return errors.New("create_tunnel succeeded but the tunnel is not in list_tunnels; run with --debug")
			}
			ok("created on %s", *server)
		}
	} else {
		ok("exists on %s, reusing it", firstNonEmpty(t.Server, "?"))
		if *server != "" && t.Server != "" && !strings.EqualFold(t.Server, *server) {
			warn("--server %s ignored: the existing tunnel lives on %s", *server, t.Server)
		}
	}

	// 2. WireGuard config, rewritten to mesh-only.
	var conf, meshIP string
	if t != nil {
		resp, err := api.WireGuard(t.Token)
		if err != nil {
			return err
		}
		if conf, err = RenderConfig(resp); err != nil {
			return err
		}
		if conf, err = pinEndpoint(conf); err != nil {
			return err
		}
		if meshIP = firstNonEmpty(ConfAddress(conf), t.IP); meshIP == "" {
			return errors.New("the tunnel has no IPv4 mesh address; run with --debug")
		}
		info("mesh IP %s, routes only %s through the tunnel", meshIP, strings.Join(meshRanges, " + "))
		local = localState{Tunnel: *name, MeshIP: meshIP, Server: firstNonEmpty(t.Server, *server)}

		// An interface that is up on a config other than the one just rendered
		// (written by an older dxx, say) is reconnected, not reused.
		onDisk, _ := os.ReadFile(localConfPath())
		if ifc := ifaceWithIP(meshIP); ifc != "" && len(onDisk) > 0 && string(onDisk) != conf {
			info("%s is up on an outdated config, reconnecting", ifc)
		} else if ifc != "" {
			if !*dry {
				if err := writeLocal(local); err != nil {
					warn("could not save %s: %v", localPath(), err)
				}
			}
			step("Already connected")
			info("%s carries %s", ifc, meshIP)
			return nil
		}
	}
	for _, n := range localNets10(meshIP) {
		warn("this computer is on %s; doxx mesh peers inside that range will not be reachable (the more specific route wins)", n)
	}

	if *dry {
		step("Dry run, nothing changed. Would:")
		if toolErr != nil {
			info("need wireguard-tools first: brew install wireguard-tools")
		}
		info("write %s (mode 600)", localConfPath())
		info("run sudo wg-quick up %s", localConfPath())
		return nil
	}

	// 3. Bring it up.
	step("Connecting")
	if err := sudoAuth("creating the interface needs root"); err != nil {
		return err
	}
	stop := spin("bringing the interface up")
	if _, err := os.Stat(localConfPath()); err == nil {
		_, _ = runWGQuick(wgQuick, "down") // leftover from an earlier connect
	}
	err = writeFile600(localConfPath(), []byte(conf))
	var out string
	if err == nil {
		if out, err = runWGQuick(wgQuick, "up"); err != nil {
			os.Remove(localConfPath())
			err = fmt.Errorf("wg-quick up failed: %w\n%s", err, indent(out))
		}
	}
	stop()
	if err != nil {
		return err
	}
	ok("wrote %s", localConfPath())
	ok("interface up")
	if err := writeLocal(local); err != nil {
		warn("could not save %s: %v", localPath(), err)
	}
	stop = spin("waiting for the handshake")
	hs := waitLocalHandshake(wgQuick, confPeerKey(conf))
	stop()
	if hs {
		ok("handshake with doxx.net")
	} else {
		warn("no handshake within 10s. Check that outbound UDP is allowed on this network")
	}

	step("Connected")
	fmt.Printf("  This computer is %s on the doxx mesh (tunnel %s).\n", meshIP, *name)
	fmt.Println("  Put a server on the mesh:  dxx up <ssh-host> --as <name>")
	fmt.Println("  Disconnect:                dxx disconnect")
	return nil
}

func cmdDisconnect(args []string) error {
	fs := flag.NewFlagSet("disconnect", flag.ExitOnError)
	name := fs.String("name", "", "doxx tunnel name (default: the saved one)")
	del := fs.Bool("delete-tunnel", false, "also delete this computer's tunnel in your doxx.net account")
	debug := fs.Bool("debug", false, "print redacted API responses")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: dxx disconnect [flags]")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	step("Disconnecting")
	wasUp, err := disconnectLocal()
	if err != nil {
		return err
	}
	if wasUp {
		ok("interface down, config removed")
	} else {
		ok("not connected")
	}

	if *del {
		local := readLocal()
		if *name == "" {
			*name = local.Tunnel
		}
		if *name == "" {
			return errors.New("no saved tunnel for this computer; pass --name (see: dxx tunnels)")
		}
		tok, err := loadToken()
		if err != nil {
			return err
		}
		found, err := deleteTunnel(NewClient(tok, *debug), *name)
		if err != nil {
			return err
		}
		if found {
			ok("tunnel %q deleted", *name)
		} else {
			warn("no tunnel named %q in your account", *name)
		}
		if *name == local.Tunnel {
			os.Remove(localPath())
		}
	}
	return nil
}

// disconnectLocal takes the interface down and removes the config. wasUp is
// false if there was no config, i.e. dxx had not connected this computer.
func disconnectLocal() (wasUp bool, err error) {
	if _, err := os.Stat(localConfPath()); err != nil {
		return false, nil
	}
	wgQuick, err := findWGQuick()
	if err != nil {
		return false, err
	}
	if err := sudoAuth("removing the interface needs root"); err != nil {
		return false, err
	}
	stop := spin("bringing the interface down")
	out, err := runWGQuick(wgQuick, "down")
	stop()
	if err != nil && !strings.Contains(out, "is not a WireGuard interface") {
		return false, fmt.Errorf("wg-quick down failed: %w\n%s", err, indent(out))
	}
	return true, os.Remove(localConfPath())
}

// serverWithTunnel returns the saved server that uses the given tunnel.
func serverWithTunnel(tunnel string) string {
	if tunnel == "" {
		return ""
	}
	for k, s := range readStates() {
		if s.Tunnel == tunnel {
			return k
		}
	}
	return ""
}

// ---- wg-quick -------------------------------------------------------------

func findWGQuick() (string, error) {
	bin := os.Getenv("DXX_WG_QUICK")
	if bin == "" {
		bin = "wg-quick"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return "", errors.New("wg-quick not found. Install WireGuard first:  brew install wireguard-tools")
	}
	return filepath.Abs(path)
}

// asRoot builds a command that runs as root. sudo resets PATH, so the
// directory of wg-quick (which also holds wg, wireguard-go and a modern bash
// under Homebrew) is passed explicitly. DXX_SUDO overrides sudo for tests;
// empty means run directly.
func asRoot(wgQuick string, argv ...string) *exec.Cmd {
	path := filepath.Dir(wgQuick) + ":/usr/bin:/bin:/usr/sbin:/sbin"
	full := append([]string{"env", "PATH=" + path}, argv...)
	sudo, set := os.LookupEnv("DXX_SUDO")
	if !set {
		sudo = "sudo"
	}
	if sudo == "" || os.Geteuid() == 0 {
		return exec.Command(full[0], full[1:]...)
	}
	return exec.Command(sudo, full...)
}

// sudoAuth asks for the sudo password up front, while no spinner is on
// screen; the sudo calls that follow reuse it.
func sudoAuth(why string) error {
	sudo, set := os.LookupEnv("DXX_SUDO")
	if (set && sudo != "sudo") || os.Geteuid() == 0 {
		return nil
	}
	if exec.Command("sudo", "-n", "true").Run() == nil {
		return nil
	}
	info("%s: sudo asks for your password", why)
	cmd := exec.Command("sudo", "-v")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sudo: %w", err)
	}
	return nil
}

// runWGQuick runs `wg-quick up|down` on the local config. Its chatter is
// returned rather than printed; sudo prompts on the terminal itself.
func runWGQuick(wgQuick, action string) (string, error) {
	cmd := asRoot(wgQuick, wgQuick, action, localConfPath())
	cmd.Stdin = os.Stdin
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// waitLocalHandshake polls for a handshake with the given peer for ~10s. It
// matches on the peer key because macOS names the real interface utunN.
func waitLocalHandshake(wgQuick, peerKey string) bool {
	wg := filepath.Join(filepath.Dir(wgQuick), "wg")
	if peerKey == "" {
		return false
	}
	for i := 0; i < 10; i++ {
		out, _ := asRoot(wgQuick, wg, "show", "all", "latest-handshakes").Output()
		for _, l := range strings.Split(string(out), "\n") {
			f := strings.Fields(l)
			if len(f) == 3 && f[1] == peerKey && f[2] != "0" {
				return true
			}
		}
		time.Sleep(time.Second)
	}
	return false
}

// confPeerKey returns the PublicKey of the first [Peer] section.
func confPeerKey(conf string) string {
	section := ""
	for _, line := range strings.Split(conf, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			section = strings.ToLower(t)
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if ok && section == "[peer]" && strings.EqualFold(strings.TrimSpace(k), "PublicKey") {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// ---- local network --------------------------------------------------------

// ifaceWithIP returns the name of the local interface that carries ip.
func ifaceWithIP(ip string) string {
	want := net.ParseIP(ip)
	if want == nil {
		return ""
	}
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(want) {
				return ifc.Name
			}
		}
	}
	return ""
}

// localNets10 lists local 10.x networks (other than the tunnel's own
// address) that shadow part of the mesh range.
func localNets10(meshIP string) []string {
	var out []string
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.To4() == nil || n.IP.To4()[0] != 10 || n.IP.String() == meshIP {
			continue
		}
		if ones, _ := n.Mask.Size(); ones < 32 {
			out = appendUniq(out, (&net.IPNet{IP: n.IP.Mask(n.Mask), Mask: n.Mask}).String())
		}
	}
	return out
}

// ---- fastest location -----------------------------------------------------

var pingMinRe = regexp.MustCompile(`= ([0-9.]+)/`)

// parsePingMin reads the minimum round trip from ping's summary line
// ("... min/avg/max/stddev = 16.1/16.3/16.5/0.2 ms"); 0 if there is none.
func parsePingMin(out []byte) time.Duration {
	if m := pingMinRe.FindSubmatch(out); m != nil {
		if ms, err := strconv.ParseFloat(string(m[1]), 64); err == nil {
			return time.Duration(ms * float64(time.Millisecond))
		}
	}
	return 0
}

// pickServer chooses a location for a new server tunnel when --server is not
// given: the one closest to the server itself, or failing that the one this
// computer's own tunnel lives on.
func pickServer(api *Client, rem *Remote) (string, error) {
	srv, err := api.Servers()
	if err != nil {
		return "", err
	}
	stop := rem.spin("no --server given: measuring %d locations from the server", len(srv))
	best, rtt, measured := rem.FastestServer(srv)
	stop()
	if measured {
		info("closest to the server: %s (%s, %d ms)", best.Hostname, firstNonEmpty(best.Location, "?"), rtt.Milliseconds())
		return best.Hostname, nil
	}
	if local := readLocal(); local.Server != "" {
		info("could not measure from the server; using this computer's location %s", local.Server)
		return local.Server, nil
	}
	return "", errors.New("could not measure the doxx.net locations from the server; pass --server (see: dxx servers)")
}

// fastestServer pings every location and returns the one with the lowest
// round trip. Only a few run at a time: a burst of ICMP to all of them gets
// throttled on the way and makes every location look equally slow.
func fastestServer(servers []Server) (Server, time.Duration, error) {
	ping := os.Getenv("DXX_PING")
	if ping == "" {
		ping = "ping"
	}
	rtts := make([]time.Duration, len(servers))
	var wg sync.WaitGroup
	slots := make(chan struct{}, 4)
	for i, s := range servers {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			out, _ := exec.CommandContext(ctx, ping, "-c", "2", host).Output()
			rtts[i] = parsePingMin(out)
		}(i, s.Hostname)
	}
	wg.Wait()
	best := -1
	for i, d := range rtts {
		if d > 0 && (best < 0 || d < rtts[best]) {
			best = i
		}
	}
	if best < 0 {
		return Server{}, 0, errors.New("could not measure any doxx.net location; pick one with --server (see: dxx servers)")
	}
	return servers[best], rtts[best], nil
}
