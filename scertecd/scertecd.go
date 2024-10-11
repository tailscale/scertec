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
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"expvar"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
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
	Now         func() time.Time                 // if nil, initialized to time.Now
	ACMEContact string                           // optional email address for ACME registration
	Prefix      string                           // setec secret prefix ("prod/scertec/")
	Logf        func(format string, args ...any) // if nil, initialized to log.Printf

	lazyInitOnce sync.Once // guards dts and optional fields above
	dts          []domainAndType
	startTime    time.Time // time the server was started, for metrics

	metricOCSPGood         expvar.Int
	metricOCSPRevoked      expvar.Int
	metricErrorCount       expvar.Map // error type => count
	metricRenewalsStarted  expvar.Int // counter of renewal started
	metricCurRenewals      expvar.Int // gauge of in-flight renewals
	metricSetecGet         expvar.Int
	metricSetecGetNoChange expvar.Int
	metricMadeDNSRecords   expvar.Int
	lastMadeDNSRecord      atomic.Int64 // unix time of last successful DNS record made

	mu             sync.Mutex
	acLazy         *acme.Client // nil until needed via getACMEClient
	lastOrCurCheck map[domainAndType]*certUpdateCheck
	lastRes        map[domainAndType]*certUpdateResult
	secCache       map[string]*api.SecretValue // secret name => latest version
	domainLock     map[string]chan struct{}    // domain name => 1-buffered semaphore channel to limit concurrent renewals
}

func (s *Server) lazyInit() {
	s.lazyInitOnce.Do(func() {
		s.startTime = time.Now()
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
		s.lastOrCurCheck = make(map[domainAndType]*certUpdateCheck)
		s.lastRes = make(map[domainAndType]*certUpdateResult)
		s.addError0(errTypeSetecGet)
		s.addError0(errTypeSetecPut)
		s.addError0(errTypeSetecActivate)
		s.addError0(errTypeACMEGetChallenge)
		s.addError0(errTypeMakeRecord)
		s.addError0(errTypeACMEFinish)
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

	go s.checkAWSPermissionsLoop()
	for _, dt := range s.dts {
		go s.renewCertLoop(dt)
	}
	return nil
}

// acquireDomainRenewalLock acquires a lock for the given domain name,
// preventing RSA and ECDSA renewals from happening concurrently for the same
// domain and fighting over TXT records. See
// https://github.com/tailscale/scertec/issues/4. This isn't a perfect solution,
// but it's a simple one. We could make it possible for both to run at the same
// time later if we change how DNS records are managed.

func (s *Server) acquireDomainRenewalLock(ctx context.Context, logf logf, domain string) (release func(), err error) {
	s.mu.Lock()
	if s.domainLock == nil {
		s.domainLock = make(map[string]chan struct{})
	}
	sem, ok := s.domainLock[domain]
	if !ok {
		sem = make(chan struct{}, 1)
		s.domainLock[domain] = sem
	}
	s.mu.Unlock()

	release = func() {
		logf("release domain renewal lock for %q", domain)
		<-sem
	}

	select {
	case sem <- struct{}{}:
		logf("immediately acquired domain renewal lock for %q", domain)
		return release, nil
	default:
		logf("waiting for domain renewal lock for %q (currently held by other renewal)", domain)
	}
	t0 := s.Now()

	select {
	case sem <- struct{}{}:
		logf("acquired domain renewal lock for %q after waiting %v", domain, s.Now().Sub(t0).Round(time.Millisecond))
		return release, nil
	case <-ctx.Done():
		err := ctx.Err()
		logf("timeout waiting for domain renewal lock for %q: %v", domain, err)
		return nil, err
	}
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
<html><h1>scertecd</h1>
[<a href="/metrics">metrics</a>]
<table border=1 cellpadding=5>
{{range .Certs}}
   <tr>
       <td><b>{{.Name}}</b>
	   <td>{{.Status}}
	       {{if .Log}}<pre>{{.Log}}</pre>{{end}}
		   {{if .SHA256}}[<a href="https://search.censys.io/certificates/{{.SHA256}}">censys</a>]{{end}}
	   </td>
   </tr>
{{end}}
</table></html>
`))

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/":
		s.serveRoot(w, r)
	case "/metrics":
		s.serveMetrics(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (s *Server) serveRoot(w http.ResponseWriter, r *http.Request) {
	type certData struct {
		Name    string
		Status  string
		Log     string
		Version int
		SHA256  string
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
		} else if cu.res.CertMeta == nil {
			cd.Status = "unexpected done with no error and no cert meta"
		} else {
			cd.Status = fmt.Sprintf("success; version %d; checked %v ago, good for %v",
				cu.res.SecretVersion,
				now.Sub(cu.end).Round(time.Second),
				formatDuration(cu.res.CertMeta.ValidEnd.Sub(now)))
			cd.Version = int(cu.res.SecretVersion)
			cd.SHA256 = fmt.Sprintf("%x", sha256.Sum256(cu.res.CertMeta.Leaf.Raw))
		}
		data.Certs = append(data.Certs, cd)
	}

	for _, dt := range s.dts {
		s.mu.Lock()
		last := s.lastOrCurCheck[dt]
		s.mu.Unlock()
		addRow(last)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpls.ExecuteTemplate(w, "root", data)
}

// Consts for at least the broad error types, and anything referenced multiple
// times, but not necessarily every little unlikely error path. String literals
// in rare error cases are fine.
const (
	errTypeMakeRecord       = "aws-make-record"
	errTypeSetecGet         = "setec-get"
	errTypeSetecPut         = "setec-put"
	errTypeSetecActivate    = "setec-activate"
	errTypeACMEGetChallenge = "acme-get-challenge"
	errTypeACMEFinish       = "acme-finish"
	errTypeCheckCertSetec   = "check-cert-setec"
)

func (s *Server) serveMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.Now()
	uptime := now.Sub(s.startTime)

	good := 0
	bad := 0

	fmt.Fprintf(w, "uptime %d\n", int64(uptime.Seconds()))
	add := func(s string, v int64) {
		fmt.Fprintf(w, "scertecd_%s %d\n", s, v)
	}
	add("managed_certs", int64(len(s.dts)))

	for _, dt := range s.dts {
		res := s.lastRes[dt]
		if res == nil || res.CertMeta == nil || res.CertMeta.ValidEnd.Before(now) {
			bad++
		} else {
			renewalTime := res.CertMeta.RenewalTime()
			secRemain := int64(res.CertMeta.ValidEnd.Sub(now).Seconds())
			secUntilRenew := int64(renewalTime.Sub(now).Seconds())
			fmt.Fprintf(w, "scertecd_cert_seconds_remain{domain=%q} %v\n", dt, secRemain)
			fmt.Fprintf(w, "scertecd_cert_seconds_until_renewal{domain=%q} %v\n", dt, max(secUntilRenew, 0))
			if now.After(renewalTime.Add(15*time.Minute)) || now.Sub(res.LastOCSPCheck) > 30*time.Minute {
				bad++
			} else {
				good++
			}
		}
	}
	add("certs_cur_good", int64(good))
	add("certs_cur_bad", int64(bad))
	add("ocsp_checks_good", s.metricOCSPGood.Value())
	add("ocsp_checks_revoked", s.metricOCSPRevoked.Value())
	add("certs_renewals_started", s.metricRenewalsStarted.Value())
	add("certs_cur_renewals", s.metricCurRenewals.Value())
	add("setec_get", s.metricSetecGet.Value())
	add("setec_get_no_change", s.metricSetecGetNoChange.Value())
	add("made_dns_records", s.metricMadeDNSRecords.Value()) // including tests

	var dnsErrors int64
	if e, ok := s.metricErrorCount.Get(errTypeMakeRecord).(*expvar.Int); ok {
		dnsErrors = e.Value()
	}
	if uptime < 5*time.Minute && dnsErrors == 0 && s.metricMadeDNSRecords.Value() == 0 {
		// At startup, don't emit metrics related to DNS errors while the first
		// test is ongoing,
	} else {
		lastTime := s.lastMadeDNSRecord.Load()
		if lastTime == 0 {
			add("alert_dns_permission_problem_likely", 1)
		} else {
			add("last_dns_record_seconds_ago", now.Unix()-lastTime)
		}
	}

	s.metricErrorCount.Do(func(kv expvar.KeyValue) {
		fmt.Fprintf(w, "scertecd_error{type=%q} %d\n", kv.Key, kv.Value.(*expvar.Int).Value())
	})
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
		prev := s.lastOrCurCheck[dt]
		s.lastOrCurCheck[dt] = cu
		s.mu.Unlock()

		var prevRes *certUpdateResult
		if prev != nil {
			prevRes = prev.res
		}

		res, err := cu.updateIfNeeded(context.Background(), prevRes)
		if err != nil {
			cu.lg.Printf("updateIfNeeded error: %v", err)
			// In case we violated some rate limit, sleep a bit. We should be
			// looking at acme response headers/errors more but in the meantime,
			// just conservatively sleep more than hopefully necessary.
			time.Sleep(5 * time.Minute)
		} else {
			s.mu.Lock()
			s.lastRes[dt] = res
			s.mu.Unlock()

			// In the happy path, we just keep checking regularly. The checks
			// are cheap: just an if-modified-since call to setec. The OCSP checks
			// will be skipped if it was done recently enough (per prevRes).
			cu.lg.Printf("success; %+v", res)
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

func (s *Server) addError(errType string) {
	s.metricErrorCount.Add(errType, 1)
}

func (s *Server) addError0(errType string) {
	s.metricErrorCount.Add(errType, 0)
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
			s.metricSetecGetNoChange.Add(1)
			return have, nil
		}
	} else {
		v, err = s.SetecClient.Get(ctx, secName)
	}
	if v != nil {
		s.metricSetecGet.Add(1)

		s.mu.Lock()
		if s.secCache == nil {
			s.secCache = make(map[string]*api.SecretValue)
		}
		s.secCache[secName] = v
		s.mu.Unlock()
	}
	if err != nil {
		s.addError(errTypeSetecGet)
	}
	return v, err
}

type logf = func(format string, args ...any)

func (s *Server) putAndActivateSecret(ctx context.Context, logf logf, secName string, secValue []byte) (api.SecretVersion, error) {
	v, err := s.SetecClient.Put(ctx, secName, secValue)
	if err != nil {
		s.addError(errTypeSetecPut)
		return 0, fmt.Errorf("could not create %q secret: %w", secName, err)
	}
	logf("created secret %q version %v", secName, v)
	err = s.SetecClient.Activate(ctx, secName, v)
	if err != nil {
		s.addError(errTypeSetecActivate)
		return 0, fmt.Errorf("could not activate %q version %v: %w", secName, v, err)
	}
	logf("activated secret %q version %v", secName, v)
	return v, nil
}

type certUpdateResult struct {
	Updated       bool
	CheckedAt     time.Time
	CertMeta      *certMeta
	SecretName    string
	SecretVersion api.SecretVersion
	LastOCSPCheck time.Time
}

// updateIfNeeded checks if the cert for cu.dt needs updating and fetches a new
// one from LetsEncrypt using ACME if so.
//
// prev is the previous cert update check, if any. It will be nil on the first
// check.
func (cu *certUpdateCheck) updateIfNeeded(ctx context.Context, prev *certUpdateResult) (_ *certUpdateResult, retErr error) {
	defer func() {
		cu.mu.Lock()
		defer cu.mu.Unlock()
		cu.end = cu.s.now()
		cu.err = retErr
	}()

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute) // minute for Route 53 + plenty of slack for ACME exchanges + RSA/ECDSA being serialized
	defer cancel()

	secName := cu.dt.SecretName(cu.s)

	res := &certUpdateResult{
		SecretName: secName,
		CheckedAt:  cu.s.Now(),
	}
	cu.res = res

	// See if we have an existing cert in setec that still has sufficient
	// remaining expiry time.
	if sec, err := cu.s.getSecret(ctx, secName); err == nil {
		m, err := cu.s.parseCertMeta(sec.Value)
		switch {
		case err == nil:
			// It still has enough time left. The common case.
			res.SecretVersion = sec.Version
			res.CertMeta = m

			now := cu.s.Now()
			if prev == nil || now.Sub(prev.LastOCSPCheck) > 10*time.Minute {
				if ores, err := cu.s.getOCSPResponse(ctx, m.Leaf, m.Issuer); err != nil {
					cu.Logf("error fetching OCSP result, ignoring maybe-transient network issue: %v", err)
				} else if ores.Status != ocsp.Good {
					cu.Logf("OCSP status: %v", ores.Status)
					cu.s.metricOCSPRevoked.Add(1)
					return nil, fmt.Errorf("OCSP not good; got status=%v, reason=%v, at=%v", ores.Status, ores.RevocationReason, ores.RevokedAt)
				} else {
					cu.Logf("OCSP good")
					cu.s.metricOCSPGood.Add(1)
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
		cu.s.addError(errTypeCheckCertSetec)
		return nil, fmt.Errorf("could not get %q secret: %w", secName, err)
	}

	// We need a new cert. Start the ACME dns-01 dance and get a challenge. But
	// only permit one renewal per DNS name at a time, so our TXT records don't
	// fight (https://github.com/tailscale/scertec/issues/4).
	release, err := cu.s.acquireDomainRenewalLock(ctx, cu.Logf, cu.dt.domain)
	if err != nil {
		return nil, fmt.Errorf("acquireDomainRenewalLock: %w", err)
	}
	defer release()

	cu.s.metricCurRenewals.Add(1)
	defer cu.s.metricCurRenewals.Add(-1)
	cu.s.metricRenewalsStarted.Add(1)

	chal, err := cu.getACMEChallenge(ctx)
	if err != nil {
		cu.s.addError(errTypeACMEGetChallenge)
		return nil, fmt.Errorf("getACMEChallenge: %w", err)
	}

	// Make the DNS record we were told to make to prove we control the DNS.
	err = cu.s.makeRecord(ctx, cu.Logf, chal.dnsRecordName, chal.dnsRecordValue)
	if err != nil {
		cu.s.addError(errTypeMakeRecord)
		return nil, fmt.Errorf("makeRecord %q: %w", chal.dnsRecordName, err)
	}
	cu.Logf("made DNS record %q", chal.dnsRecordName)

	// Finish the ACME dance.
	allPEM, err := cu.finishACME(ctx, chal)
	if err != nil {
		cu.s.addError(errTypeACMEFinish)
		return nil, fmt.Errorf("finishACME: %w", err)
	}

	m, err := cu.s.parseCertMeta(allPEM)
	if err != nil {
		cu.s.addError("renewal-parse-new-cert")
		return nil, fmt.Errorf("failed to parse newly fetched cert: %w", err)
	}

	res.SecretVersion, err = cu.s.putAndActivateSecret(ctx, cu.Logf, secName, allPEM)
	if err != nil {
		return nil, err
	}
	res.Updated = true
	res.CertMeta = m
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
			cu.Logf("WaitOrder: OrderError status %q; err=%s", oe.Status, oe.Error())
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

// RenewalTime returns the time two thirds of the way between ValidStart and ValidEnd.
func (m *certMeta) RenewalTime() time.Time {
	return m.ValidEnd.Add(-(m.ValidEnd.Sub(m.ValidStart) / 3))
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

	if s.Now().After(m.RenewalTime()) {
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

	if err := ctx.Err(); err != nil {
		return err
	}

	s.lastMadeDNSRecord.Store(time.Now().Unix())
	s.metricMadeDNSRecords.Add(1)
	return nil
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

func (s *Server) getOCSPResponse(ctx context.Context, leaf, issuer *x509.Certificate) (*ocsp.Response, error) {
	if leaf == nil {
		s.addError("ocsp-nil-leaf")
		return nil, errors.New("nil leaf")
	}
	if issuer == nil {
		s.addError("ocsp-nil-issuer")
		return nil, errors.New("nil issuer")
	}
	if len(leaf.OCSPServer) == 0 {
		s.addError("ocsp-no-ocsp-server")
		return nil, errors.New("no OCSP server")
	}

	reqb, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		s.addError("ocsp-create-request")
		return nil, fmt.Errorf("ocsp.CreateRequest: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	hreq, err := http.NewRequestWithContext(ctx, "POST", leaf.OCSPServer[0], bytes.NewReader(reqb))
	if err != nil {
		s.addError("ocsp-new-http-request")
		return nil, err
	}
	hreq.Header.Add("Content-Type", "application/ocsp-request")
	hreq.Header.Add("Accept", "application/ocsp-response")
	hres, err := http.DefaultClient.Do(hreq)
	if err != nil {
		s.addError("ocsp-http-do")
		return nil, err
	}
	defer hres.Body.Close()
	if hres.StatusCode != 200 {
		s.addError("ocsp-http-status")
		return nil, fmt.Errorf("unexpected HTTP status %v", hres.Status)
	}
	ocspRawRes, err := io.ReadAll(io.LimitReader(hres.Body, 1<<20))
	if err != nil {
		s.addError("ocsp-read-body")
		return nil, err
	}
	res, err := ocsp.ParseResponse(ocspRawRes, issuer)
	if err != nil {
		s.addError("ocsp-parse-response")
		return nil, err
	}
	return res, nil
}

// checkAWSPermissionsLoop is a background goroutine that periodically checks
// whether our Route53 IAM permissions are still valid. This is meant to protect
// us from moving the certd server between VMs and not having the right roles on
// the new VM and then not noticing until certs fail to expire.
//
// On failure, this sets a metric on the server that we can then alert.
func (s *Server) checkAWSPermissionsLoop() {
	for {
		if err := s.checkAWSPermissions(); err != nil {
			s.Logf("checkAWSPermissions error: %v", err)
			s.addError(errTypeMakeRecord)

			// If we failed to make a record, try again in a few minutes.
			// This lets us distinguish between a transient error and a more
			// persistent issue in alerting.
			time.Sleep(10 * time.Minute)
		} else {
			time.Sleep(1 * time.Hour)
		}
	}
}

// checkAWSPermissions makes a test Route53 record to see if we have
// suitable permissions.
func (s *Server) checkAWSPermissions() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var buf bytes.Buffer
	lg := log.New(&buf, "", log.LstdFlags|log.Lmsgprefix)
	logf := lg.Printf

	domain := s.dts[0].domain // TODO(bradfitz): random? check each unique domain?
	release, err := s.acquireDomainRenewalLock(ctx, logf, domain)
	if err != nil {
		return err
	}
	defer release()

	t0 := time.Now()
	if err := s.makeRecord(ctx, logf, "_acme-challenge."+domain, fmt.Sprintf("permtest-%v", time.Now().Unix())); err != nil {
		s.Logf("checkAWSPermissions makeRecord error: %v, %s", err, buf.Bytes())
		return err
	}
	s.Logf("checkAWSPermissions success; took %v", time.Since(t0).Round(time.Millisecond))
	return nil
}
