package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestConfigRejectsStructuredInjection(t *testing.T) {
	for _, field := range []string{"private_key", "assigned_ipv4", "assigned_ipv6", "server_public_key", "endpoint"} {
		for _, separator := range []string{"\n", "\r", "\x00"} {
			t.Run(field+separator, func(t *testing.T) {
				fields := map[string]any{"private_key": testPrivateKey, "assigned_ipv4": "10.0.0.9", "assigned_ipv6": "2602:f5c1::9", "server_public_key": testPublicKey, "endpoint": "example.com:51820"}
				fields[field] = fields[field].(string) + separator + "PreUp = echo INJECTED"
				conf, err := RenderConfig(fields)
				if err == nil || conf != "" {
					t.Fatalf("accepted injected %s", field)
				}
				if strings.Contains(err.Error(), testPrivateKey) {
					t.Fatal("error disclosed private key")
				}
			})
		}
	}
}

func TestConfigCanonicalizesUntrustedText(t *testing.T) {
	raw := strings.ReplaceAll(sampleConf, "[Interface]", "[iNtErFaCe] # comment")
	raw = strings.ReplaceAll(raw, "[Peer]", "[pEeR] # comment")
	raw = strings.Replace(raw, "DNS =", "PreUp = echo INJECTED\nSaveConfig = true\nTable = 123\nUnknown = ignored\nDNS =", 1)
	raw = strings.Replace(raw, "PublicKey =", "PresharedKey = "+testPrivateKey+"\nPublicKey =", 1)
	raw = strings.ReplaceAll(raw, "\n", "\r\n")
	conf, err := RenderConfig(map[string]any{"config": raw})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"PreUp", "PostUp", "SaveConfig", "Table", "Unknown", "DNS", "0.0.0.0/0", "::/0", "INJECTED"} {
		if strings.Contains(conf, bad) {
			t.Errorf("unsafe directive survived: %s", bad)
		}
	}
	for _, want := range []string{"[Interface]", "[Peer]", "PresharedKey = " + testPrivateKey, "AllowedIPs = 10.0.0.0/8, 2602:f5c1::/36", "PersistentKeepalive = 25"} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %s", want)
		}
	}
	if ConfAddress(conf) != "10.10.0.9" {
		t.Fatal("commented interface address was lost")
	}
	again, err := RenderConfig(conf)
	if err != nil || again != conf {
		t.Fatal("rendering is not idempotent")
	}
}

func TestConfigRejectsInvalidFields(t *testing.T) {
	for _, replacement := range []struct{ old, value string }{
		{testPrivateKey, "not-a-key"},
		{"10.10.0.9/32", "not-an-ip"},
		{"vie.doxx.net:51820", "example.com:0"},
		{"vie.doxx.net:51820", "bad$host:51820"},
		{"[Peer]", "[Unexpected]"},
		{"[Peer]", "[Interface]\n[Peer]"},
		{"PrivateKey = ", "MTU = $(echo INJECTED)\nPrivateKey = "},
		{"PrivateKey = ", "PrivateKey = " + testPrivateKey + "\nPrivateKey = "},
	} {
		conf, err := RenderConfig(strings.Replace(sampleConf, replacement.old, replacement.value, 1))
		if err == nil || conf != "" {
			t.Errorf("accepted invalid field replacing %q", replacement.old)
		}
	}
}

type reviewTransport func(*http.Request) (*http.Response, error)

func (f reviewTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAPIRejectsRedirects(t *testing.T) {
	for _, code := range []int{301, 302, 303, 307, 308} {
		for _, target := range []string{"https://api.example/other", "https://other.example/", "http://other.example/"} {
			t.Run(http.StatusText(code)+target, func(t *testing.T) {
				calls := 0
				client := NewClient("SYNTHETIC_TOKEN", false)
				client.BaseURL = "https://api.example/"
				client.HTTP.Transport = reviewTransport(func(r *http.Request) (*http.Response, error) {
					calls++
					if calls > 1 {
						t.Errorf("followed redirect to %s", r.URL)
					}
					body, _ := io.ReadAll(r.Body)
					if !strings.Contains(string(body), "token=SYNTHETIC_TOKEN") {
						t.Error("initial request missing token")
					}
					return &http.Response{StatusCode: code, Header: http.Header{"Location": []string{target}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
				})
				_, err := client.Call("list_tunnels", nil, true)
				if err == nil || !strings.Contains(err.Error(), "redirect refused") || calls != 1 {
					t.Fatalf("calls=%d err=%v", calls, err)
				}
			})
		}
	}
}

func TestAPIRequiresHTTPSBeforeSending(t *testing.T) {
	for _, target := range []string{"http://api.example/", "http://127.0.0.1/", "https:///missing-host", "https://user:password@api.example/", "https://api.example/#fragment"} {
		client := NewClient("SYNTHETIC_TOKEN", false)
		client.BaseURL = target
		client.HTTP.Transport = reviewTransport(func(*http.Request) (*http.Response, error) {
			t.Fatal("unsafe API URL reached transport")
			return nil, nil
		})
		if _, err := client.Call("list_tunnels", nil, true); err == nil {
			t.Errorf("accepted %s", target)
		}
	}
}

func TestRedactConfigKeyVariants(t *testing.T) {
	for _, key := range []string{"privatekey", "PRIVATEKEY", "PresharedKey", "presharedkey"} {
		conf := "[Interface]\n" + key + " = SYNTHETIC_SECRET\n[Peer]\n"
		if strings.Contains(redact(conf).(string), "SYNTHETIC_SECRET") {
			t.Errorf("leaked %s", key)
		}
	}
	data := redact(map[string]any{"preshared_key": "SYNTHETIC_SECRET"}).(map[string]any)
	if data["preshared_key"] == "SYNTHETIC_SECRET" {
		t.Fatal("leaked structured preshared key")
	}
}
