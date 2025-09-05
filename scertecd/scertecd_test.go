package scertecd

import (
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math"
	"math/big"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/setec/client/setec"
	"github.com/tailscale/setec/setectest"
)

func rootCA(t *testing.T, orgName string) (privKey ed25519.PrivateKey, cert *x509.Certificate) {
	t.Helper()

	// create the test CA
	caPub, caPriv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := x509.Certificate{
		SerialNumber: randSerial(t),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		Subject: pkix.Name{
			CommonName:   "Test Root CA",
			Organization: []string{orgName},
		},
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(crand.Reader, &root, &root, caPub, caPriv)
	if err != nil {
		t.Fatal(err)
	}

	selfSigned, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	return caPriv, selfSigned
}

func randSerial(t *testing.T) *big.Int {
	t.Helper()
	n, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPrivateCARenewal(t *testing.T) {
	rootPrivKey, rootCert := rootCA(t, "Tailscale Root CA")

	pkb, err := x509.MarshalPKCS8PrivateKey(rootPrivKey)
	if err != nil {
		t.Fatalf("error marshaling root private key: %v", err)
	}
	privKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: pkb})
	rootCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})

	// create setec test server with the root CA populated in the DB
	db := setectest.NewDB(t, nil)
	db.MustPut(db.Superuser, "test/scertec/roots/private-key", string(privKeyPEM))
	db.MustPut(db.Superuser, "test/scertec/roots/certificate-latest", string(rootCertPEM))
	ss := setectest.NewServer(t, db, nil)
	hs := httptest.NewServer(ss.Mux)
	defer hs.Close()
	st := setec.Client{Server: hs.URL, DoHTTP: hs.Client().Do}

	// create the certUpdateCheck for the private domain
	secName := "test/scertec/domains/foobar.tailscale.com/ECDSA"
	cu := certUpdateCheck{
		s: &Server{
			SetecClient: st,
			Prefix:      "test/scertec/",
			Now:         time.Now,
		},
		dt: domainAndType{
			domain:    "foobar.tailscale.com",
			typ:       "ECDSA",
			privateCA: true,
		},
		mu: sync.Mutex{},
		lg: log.New(io.Discard, "", 0),
		res: &certUpdateResult{
			SecretName: secName,
			CheckedAt:  time.Now(),
		},
	}

	// perform a private CA renewal
	if err := cu.privateCARenewal(t.Context(), secName); err != nil {
		t.Fatalf("privateCARenewal error: %v", err)
	}

	// retrieve the key & certificate from setec
	sec, err := st.Get(t.Context(), secName)
	if err != nil {
		t.Fatalf("error retrieving secret after renewal: %v", err)
	}
	if sec == nil || sec.Value == nil {
		t.Fatal("got nil secret after renewal")
	}

	// validate the retrieved key/certificate
	t.Logf("renewed secret value:\n%s", sec.Value)
	meta, err := cu.s.parseCertMeta(sec.Value, true)
	if err != nil {
		t.Fatalf("error parsing renewed cert: %v", err)
	}
	if meta == nil {
		t.Fatal("got nil cert meta after renewal")
	}
	if meta.Leaf == nil {
		t.Fatal("got nil Leaf after renewal")
	}

	// verify the leaf certificate is signed by the test root CA
	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM(rootCertPEM); !ok {
		t.Fatal("failed to append root certificate to pool")
	}
	opts := x509.VerifyOptions{
		DNSName: "foobar.tailscale.com",
		Roots:   roots,
	}
	if _, err := meta.Leaf.Verify(opts); err != nil {
		t.Fatalf("failed to verify leaf certificate against root: %v", err)
	}
}
