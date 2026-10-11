package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"time"
)

// dxx is ssh over the doxx mesh. It takes exactly the arguments ssh takes,
// finds the target's mesh IP, and execs ssh with
//
//	-o HostName=<mesh IP> -o HostKeyAlias=<public hostname>
//
// so your ~/.ssh/config (user, keys, port, forwards) and the already-known
// host key keep working, but the packets only travel over doxx.
//
// Mesh IPs come from the state dxx writes on `up`/`lock`, or from your
// doxx account (tunnel name) when a token is available.

// ssh options that take a value (from ssh(1)).
const sshValueFlags = "BbcDEeFIiJLlmOoPpQRSWw"

func runDxx(args []string) error {
	idx := findTarget(args)
	if idx < 0 {
		return fmt.Errorf("no host given")
	}
	target := args[idx]
	dest, meshIP, err := resolveMesh(target)
	if err != nil {
		return err
	}

	sshBin := os.Getenv("DXX_SSH")
	if sshBin == "" {
		sshBin = "ssh"
	}
	sshPath, err := exec.LookPath(sshBin)
	if err != nil {
		return fmt.Errorf("ssh not found: %w", err)
	}

	// The public hostname is what known_hosts knows this server by.
	alias, port := "", "22"
	if out, err := exec.Command(sshPath, "-G", dest).Output(); err == nil {
		for _, l := range strings.Split(string(out), "\n") {
			k, v, _ := strings.Cut(strings.TrimSpace(l), " ")
			switch k {
			case "hostname":
				if alias == "" {
					alias = v
				}
			case "port":
				port = v
			}
		}
	}

	if os.Getenv("DXX_NO_CHECK") == "" {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(meshIP, port), 4*time.Second)
		if err != nil {
			return fmt.Errorf("%s (%s:%s) is not reachable over doxx.\n"+
				"  Is doxx connected on this computer (dxx connect)? Does the server's doxx firewall allow this device?\n"+
				"  (dxx up %s --allow-from <this-computer's-tunnel>)", target, meshIP, port, dest)
		}
		c.Close()
	}

	pre := args[:idx]
	if len(pre) > 0 && pre[len(pre)-1] == "--" {
		pre = pre[:len(pre)-1] // our options must stay before the host
	}
	argv := []string{sshBin}
	argv = append(argv, pre...)
	argv = append(argv, "-o", "HostName="+meshIP)
	if alias != "" && alias != meshIP {
		argv = append(argv, "-o", "HostKeyAlias="+alias)
	}
	argv = append(argv, dest)
	argv = append(argv, args[idx+1:]...)
	return syscall.Exec(sshPath, argv, os.Environ())
}

// findTarget returns the index of the first positional argument (the host).
func findTarget(args []string) int {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			if i+1 < len(args) {
				return i + 1
			}
			return -1
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			return i
		}
		// -L8080:x:80 carries its value inline; -L 8080:x:80 does not.
		flags := a[1:]
		for j, f := range flags {
			if strings.ContainsRune(sshValueFlags, f) {
				if j == len(flags)-1 {
					i++ // value is the next argument
				}
				break
			}
		}
	}
	return -1
}

// resolveMesh maps what the user typed to an ssh destination and a mesh IP.
func resolveMesh(target string) (dest, meshIP string, err error) {
	user, bare := "", target
	if at := strings.LastIndexByte(target, '@'); at >= 0 {
		user, bare = target[:at+1], target[at+1:]
	}

	// 1. A mesh IP typed directly.
	if ip := net.ParseIP(bare); ip != nil && isMesh(ip) {
		return target, bare, nil
	}

	// 2. Saved servers: by name, by ssh host, or by host without the user.
	states := readStates()
	withUser := func(dest string) string {
		if user == "" {
			return dest
		}
		_, h, _ := cutUser(dest)
		return user + h
	}
	if s, ok := states[bare]; ok && s.MeshIP != "" {
		return withUser(s.dest(bare)), s.MeshIP, nil
	}
	if s, ok := states[target]; ok && s.MeshIP != "" {
		return s.dest(target), s.MeshIP, nil
	}
	var hits []string
	for key, s := range states {
		_, destBare, _ := cutUser(s.dest(key))
		if s.MeshIP != "" && destBare == bare {
			hits = append(hits, key)
		}
	}
	sort.Strings(hits)
	if len(hits) == 1 {
		s := states[hits[0]]
		return withUser(s.dest(hits[0])), s.MeshIP, nil
	}
	if len(hits) > 1 {
		return "", "", fmt.Errorf("%q matches several servers (%s); use the name", target, strings.Join(hits, ", "))
	}

	// 3. A tunnel name in the doxx account.
	if tok, terr := loadToken(); terr == nil {
		ts, aerr := NewClient(tok, false).Tunnels()
		if aerr == nil {
			for _, t := range ts {
				if (t.Name == bare || t.Name == "dxx-"+bare) && t.IP != "" {
					return target, t.IP, nil
				}
			}
		}
	}
	return "", "", fmt.Errorf("don't know a doxx mesh IP for %q.\n  Set it up with `dxx up <ssh-host> --as %s`, or see `dxx ls`", target, bare)
}

func cutUser(s string) (user, host string, hasUser bool) {
	if at := strings.LastIndexByte(s, '@'); at >= 0 {
		return s[:at], s[at+1:], true
	}
	return "", s, false
}

func isMesh(ip net.IP) bool {
	for _, c := range meshRanges {
		if _, n, err := net.ParseCIDR(c); err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}
