package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Opt in on Linux as root: DXX_NFT_TEST=1 go test -run TestFirewallPublishedPorts -v .
// All routing and firewall changes stay in temporary network namespaces.
func TestFirewallPublishedPorts(t *testing.T) {
	if os.Getenv("DXX_NFT_TEST") != "1" {
		t.Skip("set DXX_NFT_TEST=1 on Linux with root, ip, nft, sysctl and python3")
	}
	if os.Geteuid() != 0 {
		t.Fatal("network namespace test needs root")
	}
	for _, tool := range []string{"ip", "nft", "sysctl", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal(err)
		}
	}
	prefix := fmt.Sprintf("dxx-%d-%d-", os.Getpid(), time.Now().UnixNano()%1000000)
	host, public, container, mesh := prefix+"h", prefix+"p", prefix+"c", prefix+"m"
	run := func(ns string, args ...string) {
		t.Helper()
		cmd := exec.Command(args[0], args[1:]...)
		if ns != "" {
			cmd = exec.Command("ip", append([]string{"netns", "exec", ns}, args...)...)
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	for _, ns := range []string{host, public, container, mesh} {
		run("", "ip", "netns", "add", ns)
		ns := ns
		t.Cleanup(func() { exec.Command("ip", "netns", "del", ns).Run() })
		run(ns, "ip", "link", "set", "lo", "up")
	}
	for _, link := range []struct{ ns, name, hostIP, peerIP string }{
		{public, "public0", "192.0.2.1/24", "192.0.2.2/24"},
		{container, "bridge0", "172.20.0.1/24", "172.20.0.2/24"},
		{mesh, "doxx0", "10.0.0.1/24", "10.0.0.2/24"},
	} {
		run(host, "ip", "link", "add", link.name, "type", "veth", "peer", "name", "eth0", "netns", link.ns)
		run(host, "ip", "addr", "add", link.hostIP, "dev", link.name)
		run(host, "ip", "link", "set", link.name, "up")
		run(link.ns, "ip", "addr", "add", link.peerIP, "dev", "eth0")
		run(link.ns, "ip", "link", "set", "eth0", "up")
		run(link.ns, "ip", "route", "add", "default", "via", strings.Split(link.hostIP, "/")[0])
	}
	run(host, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	apply := func(rules string) {
		t.Helper()
		cmd := exec.Command("ip", "netns", "exec", host, "nft", "-f", "-")
		cmd.Stdin = strings.NewReader(rules)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("nft: %v\n%s", err, out)
		}
	}
	// Model Docker publishing two host ports to the same container port.
	apply(`table ip publish {
  chain prerouting {
   type nat hook prerouting priority -100; policy accept;
   ip daddr { 192.0.2.1, 10.0.0.1 } tcp dport { 18080, 18081 } dnat to 172.20.0.2:8080
  }
 }`)
	for _, ns := range []string{host, container, public} {
		cmd := exec.Command("ip", "netns", "exec", ns, "python3", "-u", "-c", `import socket
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('0.0.0.0',8080))
s.listen()
while True:
 c,_=s.accept()
 c.sendall(b'OK')
 c.close()
`)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	}
	probe := func(ns, addr string, port int) bool {
		cmd := exec.Command("ip", "netns", "exec", ns, "python3", "-c", `import socket,sys
try:
 s=socket.create_connection((sys.argv[1],int(sys.argv[2])),0.5)
 assert s.recv(2)==b'OK'
except Exception:
 sys.exit(1)
`, addr, strconv.Itoa(port))
		return cmd.Run() == nil
	}
	// Wait for the servers and validate the topology before testing the lock.
	for _, target := range []struct {
		ns, addr string
		port     int
	}{{public, "192.0.2.1", 18080}, {mesh, "10.0.0.1", 18080}, {container, "192.0.2.2", 8080}, {public, "192.0.2.1", 8080}} {
		ready := false
		for i := 0; i < 20; i++ {
			if probe(target.ns, target.addr, target.port) {
				ready = true
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !ready {
			t.Fatalf("baseline connection failed: %+v", target)
		}
	}
	check := func(ns, addr string, port int, want bool) {
		t.Helper()
		if got := probe(ns, addr, port); got != want {
			t.Errorf("%s -> %s:%d reachable=%v; want %v", ns, addr, port, got, want)
		}
	}
	apply(nftRuleset("doxx0", []int{22}, true))
	check(public, "192.0.2.1", 18080, false)
	check(public, "192.0.2.1", 8080, false)
	check(mesh, "10.0.0.1", 18080, true)
	check(mesh, "10.0.0.1", 8080, true)
	check(container, "192.0.2.2", 8080, true)
	apply(nftRuleset("doxx0", []int{18080}, false))
	check(public, "192.0.2.1", 18080, false)
	check(public, "192.0.2.1", 18081, true)
	check(public, "192.0.2.1", 8080, true)
	check(mesh, "10.0.0.1", 18080, true)
	apply("delete table inet dxx")
	check(public, "192.0.2.1", 18080, true)
}
