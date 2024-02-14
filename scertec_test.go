// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package scertec

import (
	"context"
	"crypto/tls"
	"flag"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/tailscale/setec/client/setec"
)

var (
	testServer = flag.String("server", "", "setec server URL for testing")
	testDomain = flag.String("domain", "", "domain name to test")
	testPrefix = flag.String("prefix", "dev/scertec/", "setec key prefix for testing")
)

func TestDev(t *testing.T) {
	if *testServer == "" || *testDomain == "" {
		t.Skip("skipping test; set --server flag to run (e.g. https://secrets.your-tailnet.ts.net) as well as --domain")
	}

	ctx := context.Background()
	c, err := NewClient(ctx, setec.Client{
		Server: *testServer,
		DoHTTP: http.DefaultClient.Do,
	}, nil, *testPrefix, *testDomain)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const msg = "hello from scertec client"
	s := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, msg)
		}),
		TLSConfig: &tls.Config{
			GetCertificate: c.GetCertificate,
		},
	}
	go s.ServeTLS(ln, "", "")

	checkRes := func(t *testing.T, res *http.Response) {
		t.Helper()
		defer res.Body.Close()
		if res.StatusCode != 200 {
			t.Fatalf("got status %d; want 200", res.StatusCode)
		}
		all, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(all) != msg {
			t.Fatalf("got %q; want %q", all, msg)
		}
	}

	hc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", ln.Addr().String())
			},
			DisableKeepAlives: true,
		},
	}

	const numRequests = 3
	for i := 0; i < numRequests; i++ {
		res, err := hc.Get("https://" + *testDomain)
		if err != nil {
			t.Fatal(err)
		}
		checkRes(t, res)
	}

	// Verify we hit the fast path numRequests - 1 times
	secName := *testPrefix + "domains/" + *testDomain + "/ecdsa"
	pci, ok := c.parsed.Load(secName)
	if !ok {
		t.Fatalf("no parsedCert for %q", secName)
	}
	pc := pci.(*parsedCert)
	pp := pc.latest.Load()
	if pp == nil {
		t.Fatalf("no latest parsedCert for %q", secName)
	}
	if got, want := pp.hits.Load(), int64(numRequests-1); got != want {
		t.Fatalf("got %d hits; want %d", got, want)
	}

	// Test RSA mode
	secName = *testPrefix + "domains/" + *testDomain + "/rsa"
	if _, ok := c.parsed.Load(secName); ok {
		t.Fatalf("unexpected RSA already parsed before requested")
	}
	c.forceRSA.Store(true)
	res, err := hc.Get("https://" + *testDomain)
	if err != nil {
		t.Fatalf("with RSA: %v", err)
	}
	checkRes(t, res)
	if _, ok := c.parsed.Load(secName); !ok {
		t.Fatalf("no parsedCert for %q", secName)
	}
}

func TestSupportsECDSA(t *testing.T) {
	tests := []struct {
		name string
		h    *tls.ClientHelloInfo
		want bool
	}{
		{
			name: "ecdsa",
			h: &tls.ClientHelloInfo{
				ServerName:      "foo.com",
				SupportedCurves: []tls.CurveID{tls.CurveP256},
				CipherSuites:    []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			},
			want: true,
		},
		{
			name: "rsa",
			h:    &tls.ClientHelloInfo{ServerName: "foo.com"},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := supportsECDSA(tt.h); err != nil {
				t.Fatal(err)
			} else if got != tt.want {
				t.Errorf("supportsECDSA() = %v, want %v", got, tt.want)
			}
		})
	}
}
