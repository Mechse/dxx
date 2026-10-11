package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
)

// Removing single resources in the doxx account:
//
//	dxx tunnels rm <name>...           a tunnel, with its firewall rules
//	dxx rules                          list firewall rules
//	dxx rules rm <tunnel> <from|all>   rules on a tunnel, by who they let in
//
// (Saved server names are removed with `dxx forget`.)

// splitArgs separates leading positional arguments from the flags after them.
func splitArgs(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		pos, args = append(pos, args[0]), args[1:]
	}
	fs.Parse(args)
	return append(pos, fs.Args()...)
}

func cmdTunnelsRm(args []string) error {
	fs := flag.NewFlagSet("tunnels rm", flag.ExitOnError)
	yes := fs.Bool("yes", false, "don't ask for confirmation")
	force := fs.Bool("force", false, "also delete a tunnel that a saved server or this computer is using")
	debug := fs.Bool("debug", false, "print redacted API responses")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: dxx tunnels rm <name>... [flags]")
		fs.PrintDefaults()
	}
	names := splitArgs(fs, args)
	if len(names) == 0 {
		return errors.New("which tunnel? dxx tunnels rm <name>  (see: dxx tunnels)")
	}
	tok, err := loadToken()
	if err != nil {
		return err
	}
	api := NewClient(tok, *debug)
	local := readLocal()
	_, connErr := os.Stat(localConfPath())

	// Check everything before deleting anything.
	step("Delete from your doxx account")
	for _, name := range names {
		if !*force {
			if owner := serverWithTunnel(name); owner != "" {
				return fmt.Errorf("%q is the tunnel of the saved server %s. Deleting only the tunnel leaves the server\n"+
					"  configured, and unreachable if it is locked. Use:  dxx down %s --delete-tunnel   (or --force)", name, owner, owner)
			}
			if name == local.Tunnel && connErr == nil {
				return fmt.Errorf("%q is the tunnel this computer is connected with. Use:  dxx disconnect --delete-tunnel   (or --force)", name)
			}
		}
		t, err := api.TunnelByName(name)
		if err != nil {
			return err
		}
		if t == nil {
			return fmt.Errorf("no tunnel named %q (see: dxx tunnels)", name)
		}
		info("tunnel %s on %s, mesh IP %s, with its firewall rules", name, firstNonEmpty(t.Server, "?"), firstNonEmpty(t.IP, "-"))
	}
	if !*yes {
		if !isTerminal(os.Stdin) {
			return errors.New("not asking for confirmation without a terminal: pass --yes")
		}
		if !askNoYes("This cannot be undone. Delete?") {
			return errors.New("cancelled, nothing changed")
		}
	}
	for _, name := range names {
		if _, err := deleteTunnel(api, name); err != nil {
			return err
		}
		ok("tunnel %q deleted", name)
		// Don't leave state pointing at a tunnel that is gone.
		if name == local.Tunnel {
			os.Remove(localPath())
		}
		if owner := serverWithTunnel(name); owner != "" {
			m := readStates()
			s := m[owner]
			s.Tunnel, s.MeshIP = "", ""
			m[owner] = s
			if err := writeStates(m); err != nil {
				return err
			}
			warn("%s is no longer on the mesh; its interface is still configured on the server (dxx up %s sets it up again)", owner, owner)
		}
	}
	return nil
}

func cmdRules(args []string) error {
	if len(args) > 0 && args[0] == "rm" {
		return cmdRulesRm(args[1:])
	}
	fs := flag.NewFlagSet("rules", flag.ExitOnError)
	debug := fs.Bool("debug", false, "print redacted API responses")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: dxx rules [tunnel]\n       dxx rules rm <tunnel> <from|all> [--port N]")
		fs.PrintDefaults()
	}
	only := splitArgs(fs, args)
	tok, err := loadToken()
	if err != nil {
		return err
	}
	api := NewClient(tok, *debug)
	ts, err := api.Tunnels()
	if err != nil {
		return err
	}
	byToken, byIP := map[string]string{}, map[string]string{}
	filter := ""
	for _, t := range ts {
		byToken[t.Token] = firstNonEmpty(t.Name, "(unnamed)")
		if t.IP != "" {
			byIP[t.IP] = t.Name
		}
		if len(only) > 0 && t.Name == only[0] {
			filter = t.Token
		}
	}
	if len(only) > 0 && filter == "" {
		return fmt.Errorf("no tunnel named %q (see: dxx tunnels)", only[0])
	}
	rules, err := api.Rules(filter)
	if err != nil {
		return err
	}
	if len(rules) == 0 {
		fmt.Println("no firewall rules")
		return nil
	}
	sort.SliceStable(rules, func(i, j int) bool { return byToken[rules[i].TunnelToken] < byToken[rules[j].TunnelToken] })
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "TUNNEL\tALLOWS FROM\tPROTO\tPORT")
	for _, r := range rules {
		from := r.SrcIP
		if n := byIP[r.SrcIP]; n != "" {
			from += " (" + n + ")"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", firstNonEmpty(byToken[r.TunnelToken], "?"), firstNonEmpty(from, "any"), r.Protocol, firstNonEmpty(r.DstPort, "all"))
	}
	return tw.Flush()
}

func cmdRulesRm(args []string) error {
	fs := flag.NewFlagSet("rules rm", flag.ExitOnError)
	port := fs.String("port", "", "only rules for this destination port")
	debug := fs.Bool("debug", false, "print redacted API responses")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: dxx rules rm <tunnel> <from|all> [--port N]\n"+
			"  <tunnel> is the tunnel the rules protect; <from> is a tunnel name or IP they let in.")
		fs.PrintDefaults()
	}
	pos := splitArgs(fs, args)
	if len(pos) != 2 {
		return errors.New("usage: dxx rules rm <tunnel> <from|all> [--port N]  (see: dxx rules)")
	}
	tok, err := loadToken()
	if err != nil {
		return err
	}
	api := NewClient(tok, *debug)
	t, err := api.TunnelByName(pos[0])
	if err != nil {
		return err
	}
	if t == nil {
		return fmt.Errorf("no tunnel named %q (see: dxx tunnels)", pos[0])
	}
	from := pos[1]
	if from != "all" {
		if src, err := api.TunnelByName(from); err != nil {
			return err
		} else if src != nil {
			from = src.IP
		}
	}
	rules, err := api.Rules(t.Token)
	if err != nil {
		return err
	}
	removed := 0
	for _, r := range rules {
		if (from != "all" && r.SrcIP != stripPrefix(from)) || (*port != "" && r.DstPort != *port) {
			continue
		}
		if err := api.DeleteRule(t.Token, r); err != nil {
			return err
		}
		ok("removed: %s %s from %s to %s", r.Protocol, firstNonEmpty(r.DstPort, "all ports"), firstNonEmpty(r.SrcIP, "any"), pos[0])
		removed++
	}
	if removed == 0 {
		return fmt.Errorf("no matching rule on %q (see: dxx rules %s)", pos[0], pos[0])
	}
	return nil
}
