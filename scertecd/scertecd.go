// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The scertecd package provides the code that fetches new TLS certs
// from LetsEncrypt as needed and puts them in setec before they
// expire. The code can run either in the foreground once, or most
// commonly as an HTTP server daemon.
//
// It populates the following setec keys:
//
//   - {prefix}acme-key: the private key for the ACME account, as a PEM-encoded ECDSA key
//   - {prefix}domains/{domain-name}/rsa: PEM of private key, domain cert, LetsEncrypt cert
//   - {prefix}domains/{domain-name}/ecdsa: PEM of private key, domain cert, LetsEncrypt cert
package scertecd

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/tailscale/setec/client/setec"
	"github.com/tailscale/setec/types/api"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/ocsp"
)

// Server is the scertec updater server.
//
// Despite the name "server", it can also be used in a single-shot
// foreground mode via its UpdateAll method.
//
// All exported fields must be initialized before calling an exported
// method on the Server: either UpdateAll or Start.
type Server struct {
	SetecClient setec.Client                     // required client for setec
	Domains     []string                         // domains to maintain certs for
	Now         func() time.Time                 // if nil, time.Now is used
	ACMEContact string                           // optional email address for ACME registration
	Prefix      string                           // setec secret prefix
	Logf        func(format string, args ...any) // alternate log function; if nil, log.Printf is used

	lazyInitOnce sync.Once // guards dts and optional fields above
	dts          []domainAndType

	mu       sync.Mutex
	acLazy   *acme.Client // nil until needed via getACMEClient
	last     map[domainAndType]*certUpdateCheck
	secCache map[string]*api.SecretValue
}

func (s *Server) lazyInit() {
	s.lazyInitOnce.Do(func() {
		for _, d := range s.Domains {
			for _, typ := range []CertType{RSACert, ECDSACert} {
				s.dts = append(s.dts, domainAndType{d, typ})
			}
		}
		if s.Logf == nil {
			s.Logf = log.Printf
		}
		if s.Now == nil {
			s.Now = time.Now
		}
	})
}

// UpdateAll checks or updates all certs once and returns.
//
// If all certs are either fine or successfully updated, it returns nil.
//
// It is not necessary to call Start before UpdateAll.
func (s *Server) UpdateAll() error {
	s.lazyInit()
	for _, dt := range s.dts {
		cu := s.newCertUpdateCheck(dt)
		st, err := cu.updateIfNeeded(context.Background(), nil)
		if err != nil {
			cu.lg.Printf("updateIfNeeded error: %v", err)
			return err
		}
		cu.lg.Printf("success; %+v", st)
	}
	return nil
}

// Start starts a background renewal goroutine for each cert domain and
// algorithm type. The context is used only for the initial ACME registration
// check and not used thereafter.
func (s *Server) Start(ctx context.Context) error {
	s.lazyInit()
	if _, err := s.getACMEClient(ctx); err != nil {
		return err
	}
	for _, dt := range s.dts {
		go s.renewCertLoop(dt)
	}
	return nil
}

func (s *Server) getACMEClient(ctx context.Context) (*acme.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.acLazy != nil {
		return s.acLazy, nil
	}

	ac, err := s.getOrMakeACMEClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("getOrMakeACMEClient: %w", err)
	}
	if err := s.initACMEReg(ctx, ac); err != nil {
		return nil, fmt.Errorf("initACMEReg: %w", err)
	}
	s.acLazy = ac
	return ac, nil
}

var tmpls = template.Must(template.New("root").Parse(`
<html><h1>scertecd</h1><table border=1 cellpadding=5>
{{range .Certs}}
   <tr>
       <td><b>{{.Name}}</b>
	   <td>{{.Status}}
	       {{if .Log}}<pre>{{.Log}}</pre>{{end}}
	   </td>
   </tr>
{{end}}
</table></html>
`))

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	type certData struct {
		Name   string
		Status string
		Log    string
	}
	var data struct {
		Certs []certData
	}
	now := s.now()
	addRow := func(cu *certUpdateCheck) {
		if cu == nil {
			return
		}
		cu.mu.Lock()
		defer cu.mu.Unlock()

		cd := certData{
			Name: cu.dt.SecretName(cu.s),
		}

		if cu.end.IsZero() {
			cd.Status = "in progress"
			cd.Log = cu.log.String()
		} else if cu.err != nil {
			cd.Status = "error: " + cu.err.Error()
		} else if cu.res == nil {
			cd.Status = "unexpected done with no error and no result"
		} else {
			cd.Status = fmt.Sprintf("success; version %d; checked %v ago, good for %v",
				cu.res.SecretVersion,
				now.Sub(cu.end).Round(time.Second),
				formatDuration(cu.res.ExpiresAt.Sub(now)))
		}
		data.Certs = append(data.Certs, cd)
	}

	for _, dt := range s.dts {
		s.mu.Lock()
		last := s.last[dt]
		s.mu.Unlock()
		addRow(last)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpls.ExecuteTemplate(w, "root", data)
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) newCertUpdateCheck(dt domainAndType) *certUpdateCheck {
	cu := &certUpdateCheck{
		s:     s,
		dt:    dt,
		start: s.now(),
	}
	cu.lg = log.New(io.MultiWriter(cu, os.Stderr), fmt.Sprintf("%s: ", dt), log.LstdFlags|log.Lmsgprefix)
	return cu
}

func (s *Server) renewCertLoop(dt domainAndType) {
	for {
		cu := s.newCertUpdateCheck(dt)

		s.mu.Lock()
		if s.last == nil {
			s.last = make(map[domainAndType]*certUpdateCheck)
		}
		prev := s.last[dt]
		s.last[dt] = cu
		s.mu.Unlock()

		var prevRes *certUpdateResult
		if prev != nil {
			prevRes = prev.res
		}

		st, err := cu.updateIfNeeded(context.Background(), prevRes)
		if err != nil {
			cu.lg.Printf("updateIfNeeded error: %v", err)
			time.Sleep(5 * time.Minute)
		} else {
			cu.lg.Printf("success; %+v", st)
			time.Sleep(1 * time.Minute)
		}
	}
}

// domainAndType is a domain name and a cert algorithm type for that domain
// name. It's a value type, for use as a map key.
type domainAndType struct {
	domain string
	typ    CertType
}

func (dt domainAndType) String() string {
	return dt.domain + "/" + string(dt.typ)
}

func (dt domainAndType) SecretName(s *Server) string {
	return s.Prefix + "domains/" + dt.domain + "/" + strings.ToLower(string(dt.typ))
}

// certUpdateCheck is a single run of a cert update.
// It might be in progress or finished.
type certUpdateCheck struct {
	s     *Server
	dt    domainAndType // domain ("foo.com") and cert type (RSA vs ECDSA)
	start time.Time
	lg    *log.Logger

	mu  sync.Mutex
	log bytes.Buffer
	end time.Time // time check ended; non-zero if done
	err error     // final error
	res *certUpdateResult
}

func (cu *certUpdateCheck) Logf(format string, args ...any) {
	cu.lg.Printf(format, args...)
}

func (c *certUpdateCheck) Write(p []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.log.Write(p)
}

// CertType is the algorithm type for the cert,
// either RSA or ECDSA.
type CertType string

const (
	RSACert   CertType = "RSA"
	ECDSACert CertType = "ECDSA"
)

// getOrMakeACMEClient returns an acme.Client, making a new private key if
// possible. It doesn't do an ACME register.
func (s *Server) getOrMakeACMEClient(ctx context.Context) (*acme.Client, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	secName := s.Prefix + "acme-key"

	sec, err := s.SetecClient.Get(ctx, secName)
	if err == nil {
		priv, rest := pem.Decode(sec.Value)
		if priv == nil {
			s.Logf("secret %q has non-PEM garbage; ignoring", secName)
		} else if len(bytes.TrimSpace(rest)) > 0 {
			s.Logf("secret %q has unexpected data after first PEM block; ignoring secret", secName)
		} else if !strings.Contains(priv.Type, "PRIVATE KEY") {
			s.Logf("secret %q has unexpected PEM type %q (not a PRIVATE KEY); ignoring secret", secName, priv.Type)
		} else {
			privKey, err := parsePrivateKey(priv.Bytes)
			if err != nil {
				s.Logf("secret %q has invalid private key; ignoring error: %v", secName, err)
			} else {
				s.Logf("using cached ACME key")
				return &acme.Client{
					Key:       privKey,
					UserAgent: "tailscale-scertec/1.0",
				}, nil
			}
		}
	}
	if err != nil && !errors.Is(err, api.ErrNotFound) {
		return nil, fmt.Errorf("could not get %q secret: %w", secName, err)
	}
	s.Logf("creating %q ...", secName)
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	var pemBuf bytes.Buffer
	if err := encodeECDSAKey(&pemBuf, privKey); err != nil {
		return nil, err
	}
	if _, err := s.putAndActivateSecret(ctx, s.Logf, secName, pemBuf.Bytes()); err != nil {
		return nil, err
	}
	return &acme.Client{
		Key:       privKey,
		UserAgent: "tailscale-scertec/1.0",
	}, nil
}

func (s *Server) initACMEReg(ctx context.Context, ac *acme.Client) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	a, err := ac.GetReg(ctx, "" /* pre-RFC param */)
	switch {
	case err == nil:
		// Great, already registered.
		s.Logf("already had ACME account")
	case err == acme.ErrNoAccount:
		acct := &acme.Account{}
		if s.ACMEContact != "" {
			acct.Contact = append(acct.Contact, "mailto:"+s.ACMEContact)
		}
		a, err = ac.Register(ctx, acct, acme.AcceptTOS)
		if err == acme.ErrAccountAlreadyExists {
			// Potential race. Double check.
			a, err = ac.GetReg(ctx, "" /* pre-RFC param */)
		}
		if err != nil {
			return fmt.Errorf("acme.Register: %w", err)
		}
		s.Logf("registered ACME account")
	default:
		return fmt.Errorf("acme.GetReg: %w", err)

	}
	if a.Status != acme.StatusValid {
		return fmt.Errorf("unexpected ACME account status %q", a.Status)
	}
	s.Logf("ACME account: %+v", a)
	return nil
}

// getSecret fetches a secret from setec, remembering any fetched value so
// most calls end up doing a GetIfChanged called to setec which results in
// fewer audit log entries.
func (s *Server) getSecret(ctx context.Context, secName string) (*api.SecretValue, error) {
	s.mu.Lock()
	have := s.secCache[secName]
	s.mu.Unlock()

	var v *api.SecretValue
	var err error

	if have != nil {
		v, err = s.SetecClient.GetIfChanged(ctx, secName, have.Version)
		if errors.Is(err, api.ErrValueNotChanged) {
			return have, nil
		}
	} else {
		v, err = s.SetecClient.Get(ctx, secName)
	}
	if v != nil {
		s.mu.Lock()
		if s.secCache == nil {
			s.secCache = make(map[string]*api.SecretValue)
		}
		s.secCache[secName] = v
		s.mu.Unlock()
	}
	return v, err
}

type logf = func(format string, args ...any)

func (s *Server) putAndActivateSecret(ctx context.Context, logf logf, secName string, secValue []byte) (api.SecretVersion, error) {
	v, err := s.SetecClient.Put(ctx, secName, secValue)
	if err != nil {
		return 0, fmt.Errorf("could not create %q secret: %w", secName, err)
	}
	logf("created secret %q version %v", secName, v)
	err = s.SetecClient.Activate(ctx, secName, v)
	if err != nil {
		return 0, fmt.Errorf("could not activate %q version %v: %w", secName, v, err)
	}
	logf("activated secret %q version %v", secName, v)
	return v, nil
}

type certUpdateResult struct {
	Updated       bool
	ExpiresAt     time.Time // time cert expires
	SecretName    string
	SecretVersion api.SecretVersion
	LastOCSPCheck time.Time
}

// updateIfNeeded checks if the cert for cu.dt needs updating and fetches a new
// one from LetsEncrypt using ACME if so.
//
// prev is the previous cert update check, if any. It will be nil on the first
// check.
func (cu *certUpdateCheck) updateIfNeeded(ctx context.Context, prev *certUpdateResult) (res *certUpdateResult, retErr error) {
	defer func() {
		cu.mu.Lock()
		defer cu.mu.Unlock()
		cu.end = cu.s.now()
		cu.res = res
		cu.err = retErr
	}()

	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute) // minute for Route 53 + minute for ACME exchanges
	defer cancel()

	secName := cu.dt.SecretName(cu.s)

	res = &certUpdateResult{
		SecretName: secName,
	}

	// See if we have an existing cert in setec that still has sufficient
	// remaining expiry time.
	if sec, err := cu.s.getSecret(ctx, secName); err == nil {
		m, err := cu.s.parseCertMeta(sec.Value)
		switch {
		case err == nil:
			// It still has enough time left. The common case.
			res.SecretVersion = sec.Version
			res.ExpiresAt = m.ValidEnd

			now := cu.s.Now()
			if prev == nil || now.Sub(prev.LastOCSPCheck) > 10*time.Minute {
				if ores, err := getOCSPResponse(ctx, m.Leaf, m.Issuer); err != nil {
					cu.Logf("error fetching OCSP result, ignoring maybe-transient network issue: %v", err)
				} else if ores.Status != ocsp.Good {
					cu.Logf("OCSP status: %v", ores.Status)
					return nil, fmt.Errorf("OCSP not good; got status=%v, reason=%v, at=%v", ores.Status, ores.RevocationReason, ores.RevokedAt)
				} else {
					cu.Logf("OCSP good")
					res.LastOCSPCheck = now
				}
			} else {
				res.LastOCSPCheck = prev.LastOCSPCheck
			}
			return res, nil
		case err == errNeedNewCert:
			cu.Logf("insufficient remaining time; fetching a new one")
		default:
			cu.Logf("failed to parse cached cert: %v", err)
		}
	} else if !errors.Is(err, api.ErrNotFound) {
		return nil, fmt.Errorf("could not get %q secret: %w", secName, err)
	}

	// We need a new cert. Start the ACME dns-01 dance and
	// get a challenge.
	chal, err := cu.getACMEChallenge(ctx)
	if err != nil {
		return nil, fmt.Errorf("getACMEChallenge: %w", err)
	}

	// Make the DNS record we were told to make to prove we control the DNS.
	err = cu.s.makeRecord(ctx, cu.Logf, chal.dnsRecordName, chal.dnsRecordValue)
	if err != nil {
		return nil, fmt.Errorf("makeRecord %q: %w", chal.dnsRecordName, err)
	}
	cu.Logf("made DNS record %q", chal.dnsRecordName)

	// Finish the ACME dance.
	allPEM, err := cu.finishACME(ctx, chal)
	if err != nil {
		return nil, fmt.Errorf("finishACME: %w", err)
	}
	m, err := cu.s.parseCertMeta(allPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse newly fetched cert: %w", err)
	}

	res.SecretVersion, err = cu.s.putAndActivateSecret(ctx, cu.Logf, secName, allPEM)
	if err != nil {
		return nil, err
	}
	res.Updated = true
	res.ExpiresAt = m.ValidEnd
	return res, nil
}

func (cu *certUpdateCheck) finishACME(ctx context.Context, ci *acmeChallengeInfo) (allPEM []byte, err error) {
	ac, err := cu.s.getACMEClient(ctx)
	if err != nil {
		return nil, err
	}

	chal, err := ac.Accept(ctx, ci.challenge)
	if err != nil {
		return nil, fmt.Errorf("acme Accept: %w", err)
	}
	cu.traceACME(chal)

	order, err := ac.WaitOrder(ctx, ci.order.URI)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if oe, ok := err.(*acme.OrderError); ok {
			cu.Logf("WaitOrder: OrderError status %q", oe.Status)
		} else {
			cu.Logf("WaitOrder error: %v", err)
		}
		return nil, err
	}
	cu.traceACME(order)

	certPrivKey, err := cu.genCertPrivateKey()
	if err != nil {
		return nil, err
	}

	var pemBuf bytes.Buffer
	if err := encodePrivateKeyPEM(&pemBuf, certPrivKey); err != nil {
		return nil, err
	}

	csr, err := certRequest(certPrivKey, cu.dt.domain, nil, cu.dt.domain)
	if err != nil {
		return nil, err
	}

	cu.Logf("requesting cert...")
	der, _, err := ac.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, fmt.Errorf("CreateOrder: %v", err)
	}
	cu.Logf("got cert")

	for _, b := range der {
		pb := &pem.Block{Type: "CERTIFICATE", Bytes: b}
		if err := pem.Encode(&pemBuf, pb); err != nil {
			return nil, err
		}
	}

	return pemBuf.Bytes(), nil
}

func (cu *certUpdateCheck) genCertPrivateKey() (crypto.Signer, error) {
	switch cu.dt.typ {
	case RSACert:
		return rsa.GenerateKey(rand.Reader, 2048)
	case ECDSACert:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		return nil, fmt.Errorf("invalid cert type %q", cu.dt.typ)
	}
}

var errNeedNewCert = errors.New("need new cert")

func (cu *certUpdateCheck) traceACME(v any) {
	cu.lg.Printf("acme: %T: %+v", v, v)
}

type acmeChallengeInfo struct {
	dnsRecordName  string // "_acme-challenge." + domain
	dnsRecordValue string // the value to put in the TXT record

	order     *acme.Order
	challenge *acme.Challenge
}

func (cu *certUpdateCheck) getACMEChallenge(ctx context.Context) (*acmeChallengeInfo, error) {
	ci := &acmeChallengeInfo{}

	ac, err := cu.s.getACMEClient(ctx)
	if err != nil {
		return nil, err
	}

	ci.order, err = ac.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: cu.dt.domain}})
	if err != nil {
		return nil, err
	}
	cu.traceACME(ci.order)

	for _, aurl := range ci.order.AuthzURLs {
		az, err := ac.GetAuthorization(ctx, aurl)
		if err != nil {
			return nil, fmt.Errorf("GetAuthorization: %w", err)
		}
		cu.traceACME(az)
		for _, ch := range az.Challenges {
			if ch.Type != "dns-01" {
				continue
			}
			dnsRecordValue, err := ac.DNS01ChallengeRecord(ch.Token)
			if err != nil {
				return nil, err
			}
			ci.dnsRecordName = "_acme-challenge." + cu.dt.domain
			ci.dnsRecordValue = dnsRecordValue
			ci.challenge = ch
			return ci, nil
		}
	}
	return nil, errors.New("no dns-01 challenge returned")
}

type certMeta struct {
	ValidStart time.Time // NotBefore of the latest cert (the domain cert)
	ValidEnd   time.Time // NotAfter of the soonest expiring cert (the domain cert)

	Leaf   *x509.Certificate // the domain cert
	Issuer *x509.Certificate // the Let's Encrypt cert
}

// parseCertMeta parses the PEM of a previously-stored key+cert(s) in setec
// and returns metadata about the validity window of the cert(s).
// If we're over 2/3rds of the way through its validity period, it returns
// it returns (non-nil, errNeedNewCert).
func (s *Server) parseCertMeta(p []byte) (*certMeta, error) {
	m := &certMeta{}
	var blocks []*pem.Block
	for {
		b, rest := pem.Decode(p)
		if b == nil {
			break
		}
		p = rest
		blocks = append(blocks, b)
	}
	if len(blocks) == 0 {
		return nil, errors.New("no PEM blocks found")
	}
	if len(blocks) < 3 {
		return nil, errors.New("not enough PEM blocks found")
	}
	if !strings.HasSuffix(blocks[0].Type, " PRIVATE KEY") {
		return nil, errors.New("first PEM block is not a private key")
	}
	certBlocks := blocks[1:]
	for i, cb := range certBlocks {
		if cb.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block of type %q", cb.Type)
		}
		c, err := x509.ParseCertificate(cb.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing cert: %w", err)
		}
		if i == 0 {
			m.Leaf = c
		} else {
			m.Issuer = c
		}
		if c.NotAfter.IsZero() {
			return nil, errors.New("cert has no NotAfter")
		}
		if c.NotBefore.IsZero() {
			return nil, errors.New("cert has no NotBefore")
		}
		if m.ValidEnd.IsZero() || c.NotAfter.Before(m.ValidEnd) {
			m.ValidEnd = c.NotAfter
		}
		if m.ValidStart.IsZero() || c.NotBefore.After(m.ValidStart) {
			m.ValidStart = c.NotBefore
		}
	}

	validDur := m.ValidEnd.Sub(m.ValidStart)
	leeway := validDur / 3
	const day = 24 * time.Hour
	if leeway < day {
		leeway = day
	}
	remain := m.ValidEnd.Sub(s.Now())
	if remain < leeway {
		return m, errNeedNewCert
	}
	return m, nil
}

// certRequest generates a CSR for the given common name cn and optional SANs.
func certRequest(key crypto.Signer, cn string, ext []pkix.Extension, san ...string) ([]byte, error) {
	req := &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: cn},
		DNSNames:        san,
		ExtraExtensions: ext,
	}
	return x509.CreateCertificateRequest(rand.Reader, req, key)
}

// parsePrivateKey is a copy of x/crypto/acme's parsePrivateKey.
//
// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS#1 private keys by default, while OpenSSL 1.0.0 generates PKCS#8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
//
// Inspired by parsePrivateKey in crypto/tls/tls.go.
func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey:
			return key, nil
		case *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("failed to parse private key")
}

func encodeECDSAKey(w io.Writer, key *ecdsa.PrivateKey) error {
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	pb := &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	return pem.Encode(w, pb)
}

func encodePrivateKeyPEM(w io.Writer, key crypto.Signer) error {
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		if err := encodeECDSAKey(w, key); err != nil {
			return err
		}
	case *rsa.PrivateKey:
		b := x509.MarshalPKCS1PrivateKey(key)
		pb := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}
		if err := pem.Encode(w, pb); err != nil {
			return err
		}
	default:
		return errors.New("unknown private key type")
	}
	return nil
}

// makeRecord upserts a Route 53 TXT record and waits for it to be globally
// synchronized.
func (s *Server) makeRecord(ctx context.Context, logf logf, recordName, txtVal string) error {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))
	svc := route53.New(sess)

	// Find the hosted zone for the recordName.
	//
	// TODO(bradfitz): cache these hosted zone lookups? they don't change often.
	// but we also don't get new cert often. But we could cache them and then
	// only reload on miss.
	var hostedZoneID string
	err := svc.ListHostedZonesPagesWithContext(ctx, &route53.ListHostedZonesInput{
		MaxItems: aws.String("100"),
	}, func(page *route53.ListHostedZonesOutput, lastPage bool) bool {
		for _, hz := range page.HostedZones {
			if hz.Name == nil || *hz.Name == "local." {
				continue
			}
			if strings.HasSuffix(recordName, "."+strings.TrimSuffix(*hz.Name, ".")) {
				hostedZoneID = path.Base(*hz.Id) // map "/hostedzone/ZFOO" to "ZFOO"
				logf("matched hosted zone %q (%s)", *hz.Name, hostedZoneID)
				return false // stop
			}
		}
		return true // continue
	})
	if err != nil {
		return err
	}
	if hostedZoneID == "" {
		return fmt.Errorf("unknown hosted zone for %q", recordName)
	}

	const recordType = "TXT"
	const ttlSec = 300

	// Look up the record first to see if it already exists and is of the
	// right type (TXT) and value. If so, don't do anything. But if it exists
	// with the wrong value, delete it first.
	lookup := &route53.ListResourceRecordSetsInput{
		HostedZoneId:    aws.String(hostedZoneID),
		StartRecordName: aws.String(recordName),
		MaxItems:        aws.String("1"),
	}
	rrsOut, err := svc.ListResourceRecordSetsWithContext(ctx, lookup)
	if err != nil {
		return err
	}
	wantVal := fmt.Sprintf("%q", txtVal)
	if len(rrsOut.ResourceRecordSets) > 0 {
		rrs := rrsOut.ResourceRecordSets[0]
		if strings.TrimSuffix(*rrs.Name, ".") == recordName && *rrs.Type == recordType &&
			len(rrs.ResourceRecords) == 1 &&
			*rrs.ResourceRecords[0].Value == wantVal {
			logf("record %q already has value %q; skipping", recordName, txtVal)
			return nil
		}
	}

	input := &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(hostedZoneID),
		ChangeBatch: &route53.ChangeBatch{
			Changes: []*route53.Change{
				{
					Action: aws.String("UPSERT"),
					ResourceRecordSet: &route53.ResourceRecordSet{
						Name: aws.String(recordName),
						Type: aws.String(recordType),
						TTL:  aws.Int64(ttlSec),
						ResourceRecords: []*route53.ResourceRecord{
							{
								Value: aws.String(wantVal),
							},
						},
					},
				},
			},
		},
	}

	crsOut, err := svc.ChangeResourceRecordSetsWithContext(ctx, input)
	if err != nil {
		logf("ChangeResourceRecordSets error: %T, %#v", err, err)
		return err
	}
	ci := crsOut.ChangeInfo

	// Wait for the change to be globally in sync. (there are only two states:
	// pending and insync)
	for ci.Status == nil || *ci.Status == route53.ChangeStatusPending {
		logf("ChangeInfo: %+v", ci)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
		crsOut, err := svc.GetChangeWithContext(ctx, &route53.GetChangeInput{
			Id: ci.Id,
		})
		if err != nil {
			return err
		}
		ci = crsOut.ChangeInfo
	}
	logf("ChangeInfo: %+v", ci)

	return ctx.Err()
}

// formatDuration is like time.Duration.String but
// omits seconds and adds days.
func formatDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	const day = 24 * time.Hour
	days := d / day
	var s string
	if days > 0 {
		s = fmt.Sprintf("%dd%s", days, (d - days*day).String())
	} else {
		s = d.String()
	}
	return strings.TrimSuffix(s, "0s")
}

func getOCSPResponse(ctx context.Context, leaf, issuer *x509.Certificate) (*ocsp.Response, error) {
	if leaf == nil {
		return nil, errors.New("nil leaf")
	}
	if issuer == nil {
		return nil, errors.New("nil issuer")
	}
	if len(leaf.OCSPServer) == 0 {
		return nil, errors.New("no OCSP server")
	}

	reqb, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return nil, fmt.Errorf("ocsp.CreateRequest: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	hreq, err := http.NewRequestWithContext(ctx, "POST", leaf.OCSPServer[0], bytes.NewReader(reqb))
	if err != nil {
		return nil, err
	}
	hreq.Header.Add("Content-Type", "application/ocsp-request")
	hreq.Header.Add("Accept", "application/ocsp-response")
	hres, err := http.DefaultClient.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer hres.Body.Close()
	if hres.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected HTTP status %v", hres.Status)
	}
	ocspRawRes, err := io.ReadAll(io.LimitReader(hres.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return ocsp.ParseResponse(ocspRawRes, issuer)
}
