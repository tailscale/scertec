// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The scertecd command updates HTTPS certs in setec using Let's Encrypt
// with AWS Route53 DNS challenges.
//
// It can run either as a long-running HTTP server that keeps the certs
// refreshed or as a one-shot CLI command via the foreground mode.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/tailscale/scertec/scertecd"
	"github.com/tailscale/setec/client/setec"
)

var (
	setecURL      = flag.String("setec-url", "", "URL of setec secrets server")
	acmeContact   = flag.String("acme-contact", "", "ACME contact email address (optional)")
	prefix        = flag.String("prefix", "dev/scertec/", "setec secret prefix to put certs under (with suffixes DOMAIN/rsa and DOMAIN/ecdsa); must end in a slash")
	domains       = flag.String("domain-names", "", "Comma-separated list of domain names to get certs for")
	foreground    = flag.Bool("foreground", false, "run in the foreground and update all the --domains if needed and exit but don't run an HTTP server")
	listen        = flag.String("listen", ":8081", "address to listen on (if not in foreground mode)")
	dynDomainsKey = flag.String("dynamic-domains-secret", "", "setec key to fetch comma-separated list of additional domains from (optional)")
)

func main() {
	flag.Parse()

	if *domains == "" {
		log.Fatalf("missing required --domains")
	}
	if *setecURL == "" {
		log.Fatalf("missing required --setec-url")
	}
	if !strings.HasSuffix(*prefix, "/") {
		log.Fatalf("--prefix must end in a slash")
	}

	s := &scertecd.Server{
		SetecClient:       setec.Client{Server: *setecURL},
		Domains:           strings.Split(*domains, ","),
		DynamicDomainsKey: *dynDomainsKey,
		ACMEContact:       *acmeContact,
		Prefix:            *prefix,
	}
	if *foreground {
		if err := s.UpdateAll(); err != nil {
			log.Fatal(err)
		}
		return
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	log.Printf("listening on %s ...", *listen)

	if err := s.Start(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Fatal(http.Serve(ln, s))
}
