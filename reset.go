package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// reset undoes everything dxx has set up, in the order that cannot lock you
// out: servers first (a locked one is only reachable while this computer is
// still on the mesh), then this computer, then the local files.
//
// Only what dxx recorded is touched: the tunnels named in its state files,
// never others in the doxx account. A server that cannot be cleaned is kept,
// together with this computer's tunnel, so it stays reachable.

func cmdReset(args []string) error {
	fs := flag.NewFlagSet("reset", flag.ExitOnError)
	yes := fs.Bool("yes", false, "don't ask for confirmation")
	dry := fs.Bool("dry-run", false, "show what would be removed without changing anything")
	debug := fs.Bool("debug", false, "print redacted API responses")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: dxx reset [flags]")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	states, local := readStates(), readLocal()
	keys := make([]string, 0, len(states))
	for k := range states {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	cmDir := filepath.Join(filepath.Dir(statePath()), "cm")
	var files []string
	for _, p := range []string{statePath(), localPath(), localConfPath()} {
		if _, err := os.Stat(p); err == nil {
			files = append(files, p)
		}
	}
	if len(keys) == 0 && local.Tunnel == "" && len(files) == 0 {
		os.RemoveAll(cmDir)
		ok("nothing to reset")
		return nil
	}

	// 1. Say exactly what goes, then ask.
	step("Reset removes")
	needToken := local.Tunnel != ""
	for _, k := range keys {
		s := states[k]
		if !s.wasSetUp() {
			info("saved name %s (%s)", k, s.dest(k))
			continue
		}
		line := fmt.Sprintf("server %s (%s): unlock, remove interface %s", k, s.dest(k), firstNonEmpty(s.Iface, "doxx0"))
		if s.Tunnel != "" {
			line += fmt.Sprintf(", delete tunnel %q", s.Tunnel)
			needToken = true
		}
		info("%s", line)
	}
	if local.Tunnel != "" {
		info("this computer: disconnect, delete tunnel %q", local.Tunnel)
	}
	for _, p := range files {
		info("file %s", p)
	}
	info("kept: your doxx token, other tunnels in your account, your SSH key and installed packages on the servers")
	if *dry {
		step("Dry run, nothing changed.")
		return nil
	}
	var api *Client
	if needToken {
		tok, err := loadToken()
		if err != nil {
			return err
		}
		api = NewClient(tok, *debug)
	}
	if !*yes {
		if !isTerminal(os.Stdin) {
			return errors.New("not asking for confirmation without a terminal: pass --yes")
		}
		if !askTyped("reset") {
			return errors.New("cancelled, nothing changed")
		}
	}

	// 2. Servers.
	var kept []string
	for _, k := range keys {
		s := states[k]
		if s.wasSetUp() {
			step("Server %s (%s)", k, s.dest(k))
			if err := resetServer(api, k, s); err != nil {
				warn("skipped, left as it is: %v", err)
				kept = append(kept, k)
				continue
			}
		}
		m := readStates()
		delete(m, k)
		if err := writeStates(m); err != nil {
			return err
		}
	}
	if len(kept) > 0 {
		return fmt.Errorf("reset is incomplete: could not clean %s.\n"+
			"  This computer's tunnel and connection were left in place, in case a kept server is locked\n"+
			"  and only reachable over the mesh. Fix the problem above, then run dxx reset again", strings.Join(kept, ", "))
	}

	// 3. This computer.
	step("This computer")
	wasUp, err := disconnectLocal()
	if err != nil {
		return err
	}
	if wasUp {
		ok("interface down, config removed")
	}
	if local.Tunnel != "" {
		found, err := deleteTunnel(api, local.Tunnel)
		if err != nil {
			return err
		}
		if found {
			ok("tunnel %q deleted", local.Tunnel)
		}
	}

	// 4. Files.
	for _, p := range []string{statePath(), localPath(), localConfPath()} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	os.RemoveAll(cmDir)
	ok("local state removed")

	step("Reset complete")
	info("Start again with:  dxx connect")
	return nil
}

// wasSetUp is false for entries that only give a name to an ssh host.
func (s hostState) wasSetUp() bool { return s.MeshIP != "" || s.Tunnel != "" }

// resetServer unlocks the server, removes its doxx interface and deletes
// its tunnel. Any error leaves the rest of that server untouched.
func resetServer(api *Client, key string, s hostState) error {
	host, iface := s.dest(key), firstNonEmpty(s.Iface, "doxx0")
	if !ifaceRe.MatchString(iface) {
		return fmt.Errorf("invalid interface name %q in the saved state", iface)
	}
	pub := NewRemote(host, false)
	cfg, err := pub.SSHConfig()
	if err != nil {
		return err
	}
	pub.Password = true // public SSH may be closed: see cmdUnlock
	if err := unlockServer(pub, cfg["hostname"], s.MeshIP); err != nil {
		return err
	}
	ok("public SSH open")

	// Over public SSH from here on: the next step removes the mesh interface.
	rem := NewRemote(host, false)
	if err := rem.Connect(); err != nil {
		return err
	}
	stop := rem.spin("stopping the interface")
	err = rem.Teardown(iface)
	stop()
	if err != nil {
		return err
	}
	ok("interface stopped, config removed")

	if s.Tunnel != "" {
		found, err := deleteTunnel(api, s.Tunnel)
		if err != nil {
			return err
		}
		if found {
			ok("tunnel %q deleted", s.Tunnel)
		} else {
			info("tunnel %q is already gone", s.Tunnel)
		}
	}
	return nil
}

// deleteTunnel deletes a tunnel by name together with its firewall rules.
func deleteTunnel(api *Client, name string) (found bool, err error) {
	t, err := api.TunnelByName(name)
	if err != nil || t == nil {
		return false, err
	}
	// The API does not say whether rules go with their tunnel, so remove
	// them first. A leftover rule is not worth failing the deletion for.
	if rules, err := api.Rules(t.Token); err == nil {
		failed := 0
		for _, r := range rules {
			if api.DeleteRule(t.Token, r) != nil {
				failed++
			}
		}
		if failed > 0 {
			warn("could not remove %d firewall rule(s) of %q; check the portal", failed, name)
		}
	}
	return true, api.DeleteTunnel(t.Token)
}
