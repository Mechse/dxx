package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"
)

// Saved servers live in ~/.config/doxx/dxx-hosts.json, keyed by name:
//
//	{"hetzner": {"dest": "root@203.0.113.10", "mesh_ip": "10.10.0.9", "tunnel": "dxx-hetzner", "iface": "doxx0"}}
//
// A name works everywhere a host does: dxx hetzner, dxx lock hetzner, ...
// Entries without "dest" (from older versions) use their key as the ssh host.

type hostState struct {
	Dest   string `json:"dest,omitempty"` // ssh destination, e.g. root@203.0.113.10
	MeshIP string `json:"mesh_ip,omitempty"`
	Tunnel string `json:"tunnel,omitempty"` // doxx tunnel name
	Iface  string `json:"iface,omitempty"`
}

func (s hostState) dest(key string) string { return firstNonEmpty(s.Dest, key) }

var nameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

func statePath() string {
	if p := os.Getenv("DXX_STATE"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "doxx", "dxx-hosts.json")
}

func readStates() map[string]hostState {
	m := map[string]hostState{}
	if b, err := os.ReadFile(statePath()); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func writeStates(m map[string]hostState) error {
	b, _ := json.MarshalIndent(m, "", "  ")
	if err := os.MkdirAll(filepath.Dir(statePath()), 0o700); err != nil {
		return err
	}
	tmp := statePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, statePath())
}

func loadState(key string) hostState { return readStates()[key] }

// saveState merges non-empty fields into the entry for key.
func saveState(key string, upd hostState) error {
	m := readStates()
	cur := m[key]
	if upd.Dest != "" && upd.Dest != key {
		cur.Dest = upd.Dest
	}
	if upd.MeshIP != "" {
		cur.MeshIP = upd.MeshIP
	}
	if upd.Tunnel != "" {
		cur.Tunnel = upd.Tunnel
	}
	if upd.Iface != "" {
		cur.Iface = upd.Iface
	}
	m[key] = cur
	return writeStates(m)
}

// Target is a server as the user named it on the command line.
type Target struct {
	Key   string    // saved name, or the ssh host as typed
	Dest  string    // what ssh connects to
	State hostState // saved data, if any
	Saved bool
}

func resolveTarget(arg string) Target {
	states := readStates()
	if s, ok := states[arg]; ok {
		return Target{Key: arg, Dest: s.dest(arg), State: s, Saved: true}
	}
	// An ssh host that was saved under a name: use that entry.
	for k, s := range states {
		if s.Dest == arg {
			return Target{Key: k, Dest: arg, State: s, Saved: true}
		}
	}
	return Target{Key: arg, Dest: arg}
}

// parseTarget parses flags and resolves the host argument, which may appear
// before or after the flags.
func parseTarget(fs *flag.FlagSet, args []string) (Target, error) {
	host := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		host, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return Target{}, err
	}
	if host == "" && fs.NArg() > 0 {
		host = fs.Arg(0)
	}
	if host == "" {
		return Target{}, errors.New("missing server: a saved name (dxx ls) or an ssh host like root@203.0.113.10")
	}
	return resolveTarget(host), nil
}

// ---- dxx name / ls / forget ----------------------------------------------

func cmdName(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: dxx name <name> <ssh-host|old-name>\n  e.g. dxx name hetzner root@203.0.113.10")
	}
	name, what := args[0], args[1]
	if !nameRe.MatchString(name) || strings.Contains(name, "@") {
		return fmt.Errorf("invalid name %q: letters, digits, . _ - only", name)
	}
	if isSubcommand(name) {
		return fmt.Errorf("%q is a dxx command; pick another name", name)
	}
	m := readStates()
	if _, taken := m[name]; taken && name != what {
		return fmt.Errorf("%q already exists (dxx forget %s first)", name, name)
	}
	src := resolveTarget(what)
	entry := src.State
	entry.Dest = src.Dest
	if src.Saved && src.Key != name {
		delete(m, src.Key) // rename: move the entry
	}
	m[name] = entry
	if err := writeStates(m); err != nil {
		return err
	}
	fmt.Printf("✓ %s → %s", name, entry.Dest)
	if entry.MeshIP != "" {
		fmt.Printf(" (mesh %s)", entry.MeshIP)
	}
	fmt.Println()
	if entry.MeshIP == "" {
		fmt.Printf("  not on doxx yet: dxx up %s\n", name)
	}
	return nil
}

func cmdForget(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: dxx forget <name>")
	}
	m := readStates()
	if _, ok := m[args[0]]; !ok {
		return fmt.Errorf("no saved server %q (see: dxx ls)", args[0])
	}
	delete(m, args[0])
	if err := writeStates(m); err != nil {
		return err
	}
	fmt.Printf("✓ forgot %s (the server and its doxx tunnel are untouched)\n", args[0])
	return nil
}

func dxxList() error {
	states := readStates()
	if len(states) == 0 {
		fmt.Println("no servers yet: dxx up <ssh-host> --as <name>")
		return nil
	}
	keys := make([]string, 0, len(states))
	for k := range states {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSSH HOST\tMESH IP")
	for _, k := range keys {
		s := states[k]
		fmt.Fprintf(tw, "%s\t%s\t%s\n", k, s.dest(k), firstNonEmpty(s.MeshIP, "-"))
	}
	return tw.Flush()
}

func isSubcommand(s string) bool {
	switch s {
	case "up", "lock", "unlock", "down", "connect", "disconnect", "reset", "servers", "tunnels", "rules", "ls", "name", "forget", "help", "version":
		return true
	}
	return false
}
