// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package scertec provides a client for the TLS certs stored in setec as
// placed there by the scertecd service.
//
// Think of it as a replacement for x/crypto/acme/autocert in that it provides
// the tls.Config.GetCertificate hook that provides the cert.
package scertec

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/tailscale/setec/client/setec"
	"golang.org/x/crypto/acme/autocert"
)

// Client looks up TLS certs stored in setec by scertecd as a function of a tls.ClientHelloInfo.
//
// It does not connect to scertecd directly. (in fact, scertecd provides no
// cert fetching service; scertecd only updates TLS cert secrets in setec.)
type Client struct {
	sc       setec.Client
	st       *setec.Store
	prefix   string
	forceRSA atomic.Bool // for testing

	parsed sync.Map // secret name [string] => *parsedCert
}

// parsedCert is a cache of a previously used certificate.
// It's used to avoid parsing the same certificate multiple times.
// There is one parsedCert per secret name but its latest
// pointer gets updated whenever the PEM from the secret changes.
type parsedCert struct {
	latest atomic.Pointer[pemAndParsed]
}

// pemAndParsed are the PEM and parsed certificate for a particular
// version of the secret. (We don't know the secret version but
// we notice when the PEM bytes change). The pem and parsed values
// are immutable once set.
type pemAndParsed struct {
	pem    []byte
	parsed *tls.Certificate
	hits   atomic.Int64 // for tests
}

func secretName(prefix, domain, typ string) string {
	return prefix + "domains/" + domain + "/" + typ
}

// NewClient returns a new HTTPS cert client. It blocks until all the needed
// secrets are available for retrieval by the Secret method, or ctx ends.  The
// context passed to NewStore is only used for initializing the store.
func NewClient(ctx context.Context, c setec.Client, cache setec.Cache, prefix string, domains ...string) (*Client, error) {
	if len(domains) == 0 {
		return nil, errors.New("no domains provided")
	}
	var secretNames []string
	for _, d := range domains {
		secretNames = append(secretNames,
			secretName(prefix, d, "rsa"),
			secretName(prefix, d, "ecdsa"),
		)
	}
	st, err := setec.NewStore(ctx, setec.StoreConfig{
		Client:  c,
		Secrets: secretNames,
		Cache:   cache,
	})
	if err != nil {
		return nil, err
	}
	return &Client{
		sc:     c,
		st:     st,
		prefix: prefix,
	}, nil
}

// GetCertificate returns the RSA or ECDSA certificate for hello.ServerName.
//
// It is the signature needed by tls.Config.GetCertificate.
func (c *Client) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	typ := "rsa"
	canEC, err := supportsECDSA(hello)
	if err != nil {
		return nil, err
	}
	if canEC && !c.forceRSA.Load() {
		typ = "ecdsa"
	}
	secName := secretName(c.prefix, hello.ServerName, typ)
	sec := c.st.Secret(secName)
	if sec == nil {
		return nil, errors.New("invalid server name")
	}
	return c.parsedCert(secName, sec.Get())
}

func (c *Client) parsedCert(secName string, pems []byte) (*tls.Certificate, error) {
	pci, ok := c.parsed.Load(secName)
	if !ok {
		pci, _ = c.parsed.LoadOrStore(secName, &parsedCert{})
	}
	pc := pci.(*parsedCert)

	latest := pc.latest.Load()
	if latest != nil && bytes.Equal(latest.pem, pems) {
		// Common case; the cert hasn't changed.
		latest.hits.Add(1)
		return latest.parsed, nil
	}

	b, certPEMBlock := pem.Decode(pems)
	if b == nil {
		return nil, errors.New("invalid PEM")
	}
	keyPEMSize := len(pems) - len(certPEMBlock)
	keyPEMBlock := pems[:keyPEMSize]

	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return nil, err
	}
	pc.latest.Store(&pemAndParsed{
		pem:    pems,
		parsed: &cert,
	})
	return &cert, nil
}

// sniffKeyAutoCertCache is an x/crypto/acme/autocert.Cache implementation
// as used by the common on supportsECDSA.
type sniffKeyAutoCertCache chan<- string

// errStopAutoCert is a sentinel error message we pass through acme/autocert
// and expect to get back out to ourselves. It doesn't escape to scertec callers.
var errStopAutoCert = errors.New("stop autocert")

func (ch sniffKeyAutoCertCache) Get(ctx context.Context, key string) ([]byte, error) {
	select {
	case ch <- key:
	default:
	}
	return nil, errStopAutoCert
}

func (ch sniffKeyAutoCertCache) Put(ctx context.Context, key string, data []byte) error {
	panic("unreachable")
}
func (ch sniffKeyAutoCertCache) Delete(ctx context.Context, key string) error {
	panic("unreachable")
}

var autoCertManagerPool = &sync.Pool{
	New: func() any { return &autocert.Manager{Prompt: autocert.AcceptTOS} },
}

// supportsECDSA reports whether the given ClientHelloInfo supports ECDSA.
//
// Rather than copying acme/autocert's private implementation of this, we use
// acme/autocert's own implementation indirectly by giving it a fake
// autocert.Cache implementation and seeing which cache key autocert tries to
// grab. It assumes that autocert fetches cache keys ending in "+rsa" for RSA
// keys which in practice won't change (thanks, Hyrum!), but we also lock it
// down in tests so we'll catch it if that behavior changes. Meanwhile,
// discussions are underway in https://github.com/golang/go/issues/65727
// of exporting that logic from acme/autocert somewhere.
func supportsECDSA(hello *tls.ClientHelloInfo) (canEC bool, err error) {
	am := autoCertManagerPool.Get().(*autocert.Manager)
	defer autoCertManagerPool.Put(am)

	ch := make(chan string, 1)
	am.Cache = sniffKeyAutoCertCache(ch)
	_, err = am.GetCertificate(hello)
	if err == nil {
		return false, errors.New("unexpected success from autocert GetCertificate")
	} else if err != nil && !errors.Is(err, errStopAutoCert) {
		return false, err
	}
	var got string
	select {
	case got = <-ch:
	default:
		panic("unexpected lack of response from sniffKeyAutoCertCache.Get")
	}
	return !strings.HasSuffix(got, "+rsa"), nil
}
