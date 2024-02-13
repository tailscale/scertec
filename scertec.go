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
	"sync"
	"sync/atomic"

	"github.com/tailscale/setec/client/setec"
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
	if supportsECDSA(hello) && !c.forceRSA.Load() {
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

// supportsECDSA reports whether the given ClientHelloInfo supports ECDSA.
//
// This is copied from x/crypto/acme/autocert.
func supportsECDSA(hello *tls.ClientHelloInfo) bool {
	// The "signature_algorithms" extension, if present, limits the key exchange
	// algorithms allowed by the cipher suites. See RFC 5246, section 7.4.1.4.1.
	if hello.SignatureSchemes != nil {
		ecdsaOK := false
	schemeLoop:
		for _, scheme := range hello.SignatureSchemes {
			const tlsECDSAWithSHA1 tls.SignatureScheme = 0x0203 // constant added in Go 1.10
			switch scheme {
			case tlsECDSAWithSHA1, tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384, tls.ECDSAWithP521AndSHA512:
				ecdsaOK = true
				break schemeLoop
			}
		}
		if !ecdsaOK {
			return false
		}
	}
	if hello.SupportedCurves != nil {
		ecdsaOK := false
		for _, curve := range hello.SupportedCurves {
			if curve == tls.CurveP256 {
				ecdsaOK = true
				break
			}
		}
		if !ecdsaOK {
			return false
		}
	}
	for _, suite := range hello.CipherSuites {
		switch suite {
		case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
			return true
		}
	}
	return false
}
