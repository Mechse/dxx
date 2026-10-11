// dxx: ssh over the doxx.net mesh, plus the tools to get a server there.
//
//	dxx up   root@my-server --server <loc> --allow-from <laptop-tunnel>
//	dxx lock root@my-server
//	dxx root@my-server          # = ssh, but only over doxx
//
// Known subcommands are handled by dxx; anything else is passed to ssh with
// the target's mesh IP swapped in.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"
)

var version = "dev"

const usage = `dxx - ssh over the doxx.net mesh

Connect (anything that isn't a subcommand goes to ssh):
  dxx [ssh options] <host> [command]   e.g. dxx hetzner, dxx -L 5432:localhost:5432 hetzner
  dxx ls                               your saved servers
  dxx name   <name> <ssh-host>         save/rename a server, e.g. dxx name hetzner root@203.0.113.10
  dxx forget <name>

This computer:
  dxx connect [--server LOC]           join the doxx mesh (creates/reuses a tunnel, wg-quick up)
  dxx disconnect [--delete-tunnel]
  dxx reset                            undo everything dxx set up: servers, tunnels, this computer

Set up a server:
  dxx up     <ssh-host> --as NAME [--server LOC] [--allow-from TUNNEL] put it on the doxx mesh
  dxx lock   <ssh-host> [--all]       accept SSH only via doxx (auto-rollback if it fails)
  dxx unlock <ssh-host>               reopen public SSH
  dxx down   <ssh-host> [--delete-tunnel]
  dxx servers                         doxx.net locations (no token needed)
  dxx tunnels                         your doxx tunnels and mesh IPs
  dxx tunnels rm <name>...            delete a tunnel and its firewall rules
  dxx rules [tunnel]                  doxx firewall rules: who may reach which tunnel
  dxx rules rm <tunnel> <from|all>    remove rules, e.g. dxx rules rm dxx-hetzner macbook

A host literally named like a subcommand: dxx -- up

Wherever a server is expected you can use its saved name, or anything ssh accepts.
Token: DOXX_TOKEN, DOXX_TOKEN_FILE, or ~/.config/doxx/token (net-admin, 7-30 day expiry)
Run "dxx up -h" (or lock/unlock/down) for flags.
`

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch args[0] {
	case "up":
		err = cmdUp(args[1:])
	case "lock":
		err = cmdLock(args[1:])
	case "unlock":
		err = cmdUnlock(args[1:])
	case "down":
		err = cmdDown(args[1:])
	case "connect":
		err = cmdConnect(args[1:])
	case "disconnect":
		err = cmdDisconnect(args[1:])
	case "reset":
		err = cmdReset(args[1:])
	case "servers":
		err = cmdServers(args[1:])
	case "tunnels":
		err = cmdTunnels(args[1:])
	case "rules":
		err = cmdRules(args[1:])
	case "ls":
		err = dxxList()
	case "name":
		err = cmdName(args[1:])
	case "forget":
		err = cmdForget(args[1:])
	case "version", "--version":
		fmt.Println(version)
		return
	case "help", "-h", "--help":
		fmt.Print(usage)
		return
	default:
		// Everything else is ssh over doxx. runDxx only returns on error;
		// on success the process becomes ssh.
		if err := runDxx(args); err != nil {
			fmt.Fprintln(os.Stderr, "dxx: "+err.Error())
			os.Exit(255)
		}
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "\n✗ "+err.Error())
		os.Exit(1)
	}
}

func cmdServers(args []string) error {
	fs := flag.NewFlagSet("servers", flag.ExitOnError)
	debug := fs.Bool("debug", false, "print redacted API responses")
	fs.Parse(args)
	srv, err := NewClient("", *debug).Servers()
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "HOSTNAME (use with --server)\tNAME\tLOCATION")
	for _, s := range srv {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", s.Hostname, s.Name, s.Location)
	}
	return tw.Flush()
}

func cmdTunnels(args []string) error {
	if len(args) > 0 && args[0] == "rm" {
		return cmdTunnelsRm(args[1:])
	}
	fs := flag.NewFlagSet("tunnels", flag.ExitOnError)
	debug := fs.Bool("debug", false, "print redacted API responses")
	fs.Parse(args)
	tok, err := loadToken()
	if err != nil {
		return err
	}
	ts, err := NewClient(tok, *debug).Tunnels()
	if err != nil {
		return err
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].Name < ts[j].Name })
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSERVER\tMESH IP")
	for _, t := range ts {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", firstNonEmpty(t.Name, "(unnamed)"), t.Server, firstNonEmpty(t.IP, "-"))
	}
	return tw.Flush()
}

var ifaceRe = regexp.MustCompile(`^[a-zA-Z0-9_=+.-]{1,15}$`)

func cmdUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	server := fs.String("server", "", "doxx.net location hostname for a new tunnel (default: the one closest to the server; see: dxx servers)")
	as := fs.String("as", "", "save this server under a short name, e.g. hetzner (then: dxx hetzner)")
	name := fs.String("name", "", "doxx tunnel name (default: dxx-<name>)")
	iface := fs.String("iface", "doxx0", "WireGuard interface name on the server")
	allowFrom := fs.String("allow-from", "", "name of YOUR tunnel (laptop/phone) allowed to SSH to the server's mesh IP (default: the one from dxx connect)")
	sshPort := fs.String("ssh-port", "22", "SSH port to open for --allow-from")
	terminfo := fs.String("terminfo", "", "also install this terminfo entry, e.g. xterm-ghostty")
	dry := fs.Bool("dry-run", false, "show what would happen without changing anything")
	noKey := fs.Bool("no-copy-key", false, "don't offer to install your SSH key when the server asks for a password")
	force := fs.Bool("force", false, "continue even if the server already has another doxx.net link")
	debug := fs.Bool("debug", false, "print redacted API responses")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: dxx up <ssh-host|name> --as NAME [--server LOC] [flags]")
		fs.PrintDefaults()
	}
	tgt, err := parseTarget(fs, args)
	if err != nil {
		return err
	}
	host, key := tgt.Dest, tgt.Key
	if *as != "" {
		if !nameRe.MatchString(*as) || strings.Contains(*as, "@") || isSubcommand(*as) {
			return fmt.Errorf("invalid --as %q: letters, digits, . _ - and not a dxx command", *as)
		}
		if other, taken := readStates()[*as]; taken && other.dest(*as) != host {
			return fmt.Errorf("the name %q is already used for %s", *as, other.dest(*as))
		}
		key = *as
	}
	if !ifaceRe.MatchString(*iface) {
		return fmt.Errorf("invalid --iface %q", *iface)
	}
	allowDefaulted := false
	if *allowFrom == "" {
		if local := readLocal(); local.Tunnel != "" && serverWithTunnel(local.Tunnel) == "" {
			*allowFrom, allowDefaulted = local.Tunnel, true
		}
	}
	if *name == "" {
		switch {
		case tgt.State.Tunnel != "":
			*name = tgt.State.Tunnel
		case key != host:
			*name = defaultName(key)
		default:
			*name = defaultName(host)
		}
	}

	tok, err := loadToken()
	if err != nil {
		return err
	}
	api := NewClient(tok, *debug)
	rem := NewRemote(host, *dry)

	// 1. Preflight: look before touching anything.
	step("Checking %s", host)
	if err := rem.Connect(); err != nil {
		return err
	}
	if rem.Password {
		offerKey(rem, *noKey || *dry)
	}
	stop := rem.spin("looking at the server")
	pf, err := rem.Preflight(*iface)
	stop()
	if err != nil {
		return err
	}
	if !pf.SudoOK {
		return errors.New("you are not root and sudo needs a password; connect as root@ or allow passwordless sudo")
	}
	info("os %s, uid %s, wireguard-tools %s", firstNonEmpty(pf.OS, "unknown"), pf.UID, yesNo(pf.HasWG))
	var foreign []string
	for _, i := range append(append([]string{}, pf.DoxxIfaces...), pf.WGIfaces...) {
		if i != *iface {
			foreign = appendUniq(foreign, i)
		}
	}
	if len(foreign) > 0 {
		msg := fmt.Sprintf("server already has other WireGuard/doxx interfaces: %s", strings.Join(foreign, ", "))
		if !*force {
			return errors.New(msg + "\n  A second interface claiming the mesh routes can cut an SSH session that rides doxx.\n  Re-run with --force only if you reach this server over its public IP and keep a console fallback.")
		}
		warn(msg + " (continuing: --force)")
	}
	for prefix, dev := range pf.Routes10 {
		if dev != *iface {
			warn("server already routes %s via %s; doxx mesh peers inside that range will not be reachable (the more specific route wins)", prefix, dev)
		}
	}

	// 2. Tunnel: reuse by name, or create.
	step("Tunnel %q", *name)
	t, err := api.TunnelByName(*name)
	if err != nil {
		return err
	}
	if t == nil {
		if *server == "" {
			if *server, err = pickServer(api, rem); err != nil {
				return err
			}
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

	// 3. WireGuard config, rewritten to mesh-only.
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
		meshIP = firstNonEmpty(ConfAddress(conf), t.IP)
		info("mesh IP %s, routes only %s through the tunnel", firstNonEmpty(meshIP, "?"), strings.Join(meshRanges, " + "))
	}

	// 4. Firewall: let your own device reach SSH on the mesh IP.
	var srcIP string
	if *allowFrom != "" {
		step("Firewall: %s → %s:%s", *allowFrom, *name, *sshPort)
		src, err := api.TunnelByName(*allowFrom)
		switch {
		case err != nil:
			return err
		case src == nil && allowDefaulted:
			warn("this computer's tunnel %q no longer exists; run dxx connect, or pass --allow-from", *allowFrom)
		case src == nil:
			return fmt.Errorf("no tunnel named %q (see: dxx tunnels)", *allowFrom)
		case src.IP == "":
			return fmt.Errorf("tunnel %q has no mesh IP yet; connect that device once, then re-run", *allowFrom)
		default:
			srcIP = src.IP
			if allowDefaulted {
				info("allowing this computer (%s)", srcIP)
			}
		}
	}

	if *dry {
		step("Dry run, nothing changed. Would:")
		if !pf.HasWG {
			info("install wireguard-tools")
		}
		info("write /etc/wireguard/%s.conf (mode 600) and enable wg-quick@%s", *iface, *iface)
		if srcIP != "" {
			info("allow TCP %s from %s to %s", *sshPort, srcIP, firstNonEmpty(meshIP, "<server mesh IP>"))
		}
		if *terminfo != "" {
			info("install terminfo %s", *terminfo)
		}
		return nil
	}

	if srcIP != "" {
		if meshIP == "" {
			return errors.New("cannot add firewall rule: server mesh IP unknown")
		}
		rule := Rule{Protocol: "TCP", SrcIP: srcIP, DstIP: meshIP, DstPort: *sshPort}
		existing, err := api.Rules(t.Token)
		if err != nil {
			return err
		}
		if hasRule(existing, rule) {
			ok("rule already present")
		} else if err := api.AddRule(t.Token, rule); err != nil {
			return err
		} else {
			ok("TCP %s from %s allowed", *sshPort, srcIP)
		}
	}

	// 5. Server side.
	step("Configuring %s", host)
	if !pf.HasWG {
		stop := rem.spin("installing wireguard-tools")
		err := rem.InstallWireGuard()
		stop()
		if err != nil {
			return err
		}
		ok("wireguard-tools installed")
	}
	stop = rem.spin("writing the config")
	err = rem.WriteConf(*iface, conf)
	stop()
	if err != nil {
		return err
	}
	ok("wrote /etc/wireguard/%s.conf", *iface)
	stop = rem.spin("starting wg-quick@%s", *iface)
	err = rem.Enable(*iface)
	stop()
	if err != nil {
		return err
	}
	ok("wg-quick@%s enabled (survives reboots)", *iface)
	stop = rem.spin("waiting for the handshake")
	hs, err := rem.WaitHandshake(*iface)
	stop()
	if err != nil {
		return err
	}
	if hs {
		ok("handshake with doxx.net")
	} else {
		warn("no handshake within 20s. Check outbound UDP on the server and `wg show %s`", *iface)
	}

	if *terminfo != "" {
		stop := rem.spin("installing terminfo %s", *terminfo)
		err := rem.InstallTerminfo(*terminfo)
		stop()
		if err != nil {
			warn("terminfo: %v", err)
		} else {
			ok("terminfo %s installed", *terminfo)
		}
	}

	if err := saveState(key, hostState{Dest: host, MeshIP: meshIP, Tunnel: *name, Iface: *iface}); err != nil {
		warn("could not save %s: %v", key, err)
	}
	if tgt.Saved && tgt.Key != key { // --as renamed an existing entry
		m := readStates()
		delete(m, tgt.Key)
		_ = writeStates(m)
	}

	// 6. Next steps.
	step("Done")
	if meshIP != "" {
		if srcIP != "" {
			fmt.Printf("  From %s (connected to doxx):  dxx %s\n", *allowFrom, key)
		} else {
			fmt.Printf("  Mesh IP: %s. Nothing can reach it yet: run dxx connect here and re-run, or pass --allow-from <your-tunnel>.\n", meshIP)
		}
	}
	if key == host {
		fmt.Printf("  Tip: give it a name so you can type less:  dxx name <name> %s\n", host)
	}
	fmt.Printf("  Public SSH is still open. Once mesh SSH works:  dxx lock %s\n", key)
	return nil
}

func cmdDown(args []string) error {
	fs := flag.NewFlagSet("down", flag.ExitOnError)
	name := fs.String("name", "", "doxx tunnel name (default: the saved one)")
	iface := fs.String("iface", "doxx0", "WireGuard interface name on the server")
	del := fs.Bool("delete-tunnel", false, "also delete the tunnel in your doxx.net account")
	debug := fs.Bool("debug", false, "print redacted API responses")
	tgt, err := parseTarget(fs, args)
	if err != nil {
		return err
	}
	host := tgt.Dest
	if !ifaceRe.MatchString(*iface) {
		return fmt.Errorf("invalid --iface %q", *iface)
	}
	if *name == "" {
		*name = firstNonEmpty(tgt.State.Tunnel, defaultName(host))
	}
	step("Removing %s from %s", *iface, host)
	rem := NewRemote(host, false)
	if err := rem.Connect(); err != nil {
		return err
	}
	stop := rem.spin("stopping the interface")
	err = rem.Teardown(*iface)
	stop()
	if err != nil {
		return err
	}
	ok("interface stopped, config removed")
	if *del {
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
	}
	return nil
}

// offerKey is called when the server asked for a password: it offers to
// install the local SSH public key so that no later login has to ask.
func offerKey(rem *Remote, skip bool) {
	pub, from := rem.localPublicKey()
	switch {
	case pub == "":
		info("password login, and no SSH key found on this computer: every dxx command will ask again (ssh-keygen -t ed25519 creates a key)")
		return
	case skip || !isTerminal(os.Stdin):
		info("password login: every dxx command will ask again (ssh-copy-id %s puts your key on the server)", rem.Host)
		return
	}
	if !askYesNo("This server asked for a password. Install your SSH key (%s) so it won't ask again?", from) {
		return
	}
	if err := rem.InstallKey(pub); err != nil {
		warn("could not install the key: %v", err)
		return
	}
	if !rem.keyLoginWorks() {
		warn("key installed, but the server still wants a password (is PubkeyAuthentication off in its sshd_config?)")
		return
	}
	rem.Password = false
	ok("key installed, no more password prompts")
}

func hasRule(rules []Rule, r Rule) bool {
	for _, x := range rules {
		if x.Protocol == r.Protocol && x.SrcIP == r.SrcIP && x.DstIP == r.DstIP && x.DstPort == r.DstPort {
			return true
		}
	}
	return false
}

// defaultName turns "root@my-box.example.com" into "my-box".
func defaultName(host string) string {
	if at := strings.LastIndexByte(host, '@'); at >= 0 {
		host = host[at+1:]
	}
	if !regexp.MustCompile(`^[0-9.:\[\]]+$`).MatchString(host) {
		host, _, _ = strings.Cut(host, ".")
	}
	host = regexp.MustCompile(`[^a-zA-Z0-9-]+`).ReplaceAllString(host, "-")
	host = strings.Trim(host, "-")
	if host == "" {
		host = "server"
	}
	name := "dxx-" + host
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}
