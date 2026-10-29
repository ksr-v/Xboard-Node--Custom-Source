package cert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"

	"github.com/cedar2025/xboard-node/internal/config"
)

func TestCanonicalACMEDomainPreservesSubjectSyntax(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{" \tJP-Tokyo-H-2.Example.TEST\n", "jp-tokyo-h-2.example.test"},
		{" *.Mixed.Example.TEST ", "*.mixed.example.test"},
		{" Mixed.Example.TEST. ", "mixed.example.test."},
		{" 192.0.2.7 ", "192.0.2.7"},
		{" 2001:DB8::ABCD ", "2001:db8::abcd"},
		{" [2001:DB8::ABCD] ", "[2001:db8::abcd]"},
		{"Bad..Example.TEST", "bad..example.test"},
		{" \t\n", ""},
	} {
		t.Run(tc.input, func(t *testing.T) {
			if got := canonicalACMEDomain(tc.input); got != tc.want {
				t.Fatalf("canonical domain = %q, want %q", got, tc.want)
			}
		})
	}
}

// Exercise the pinned ACME library's real CSR encoding and identifier
// extraction without contacting any CA. An order returned with lowercase DNS
// identifiers must match the CSR's literal DNS SAN, not merely its DNS meaning.
func TestCanonicalACMEDomainMatchesActualCSRAndOrderIdentifiers(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := "JP-Tokyo-H-2.Example.TEST"
	original, err := acmez.NewCSR(key, []string{raw})
	if err != nil {
		t.Fatal(err)
	}
	originalOrder, err := acmez.OrderParametersFromCSR(acme.Account{}, original)
	if err != nil {
		t.Fatal(err)
	}
	want := []acme.Identifier{{Type: "dns", Value: "jp-tokyo-h-2.example.test"}}
	if reflect.DeepEqual(originalOrder.Identifiers, want) {
		t.Fatal("regression fixture no longer reproduces literal CSR/order casing difference")
	}
	for _, input := range []string{raw, " \t" + raw + "\n", "*.Mixed.Example.TEST"} {
		domain := canonicalACMEDomain(input)
		csr, err := acmez.NewCSR(key, []string{domain})
		if err != nil {
			t.Fatal(err)
		}
		order, err := acmez.OrderParametersFromCSR(acme.Account{}, csr)
		if err != nil {
			t.Fatal(err)
		}
		want := []acme.Identifier{{Type: "dns", Value: domain}}
		if !reflect.DeepEqual(order.Identifiers, want) || !reflect.DeepEqual(csr.DNSNames, []string{domain}) {
			t.Fatal("canonical DNS name diverged between real CSR and order parameters")
		}
	}
	for _, input := range []string{"192.0.2.7", "2001:DB8::ABCD"} {
		domain := canonicalACMEDomain(input)
		csr, err := acmez.NewCSR(key, []string{domain})
		if err != nil {
			t.Fatal(err)
		}
		order, err := acmez.OrderParametersFromCSR(acme.Account{}, csr)
		if err != nil {
			t.Fatal(err)
		}
		want := []acme.Identifier{{Type: "ip", Value: net.ParseIP(input).String()}}
		if len(csr.DNSNames) != 0 || len(csr.IPAddresses) != 1 || !reflect.DeepEqual(order.Identifiers, want) {
			t.Fatal("IP subject was converted to a DNS identifier")
		}
	}
}

func TestACMECaseOnlyReconfigureKeepsRunningManagerAndMaterial(t *testing.T) {
	for _, mode := range []string{"http", "dns", ""} {
		t.Run(mode, func(t *testing.T) {
			cfg := config.CertConfig{CertMode: mode, AutoTLS: mode == "", Domain: "mixed.example.test",
				CertDir: t.TempDir(), DNSProvider: "cloudflare",
				DNSEnv: map[string]string{"CF_API_TOKEN": "synthetic-no-network-token"}}
			m := NewManager(cfg)
			cert, key := generateSelfSignedPair(t, cfg.Domain)
			m.storePEM(cert, key)
			magic := &certmagic.Config{}
			m.magic, m.acmeStarted, m.acmeFingerprint = magic, true, acmeFingerprint(cfg)
			cancelled := false
			m.acmeCancel = func() { cancelled = true }
			next := cfg
			next.Domain = " \tMiXeD.Example.TEST\n"
			changed, err := m.Reconfigure(context.Background(), next)
			if err != nil {
				t.Fatal(err)
			}
			if changed || cancelled || m.magic != magic || !m.acmeStarted || m.cfg.Domain != cfg.Domain {
				t.Fatal("case-only update tore down/reissued a running ACME manager")
			}
			if !bytes.Equal(m.TLSCert().CertPEM, cert) || !bytes.Equal(m.TLSCert().KeyPEM, key) {
				t.Fatal("case-only update replaced cached certificate material")
			}
			for name, want := range map[string][]byte{"cert.pem": cert, "key.pem": key} {
				got, err := os.ReadFile(filepath.Join(cfg.CertDir, name))
				if err != nil || !bytes.Equal(got, want) {
					t.Fatal("case-only update changed persisted certificate material")
				}
			}
		})
	}
}

func TestACMEWhitespaceDomainRejectedBeforeStorageOrIssuance(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "must-not-be-created")
	m := NewManager(config.CertConfig{CertMode: "http", Domain: " \t\n", CertDir: directory})
	if err := m.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "cert.domain is required") {
		t.Fatal("empty canonical ACME subject was not rejected")
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) || m.magic != nil || m.HasCert() {
		t.Fatal("empty subject created storage or initialized issuance")
	}
}

func TestCanonicalACMEStorageLookupReusesExistingMixedCaseMaterial(t *testing.T) {
	ctx := context.Background()
	storage := &certmagic.FileStorage{Path: t.TempDir()}
	issuer, original := "test-issuer", "MiXeD.Example.TEST"
	cert, key := generateSelfSignedPair(t, original)
	entries := map[string][]byte{
		certmagic.StorageKeys.SiteCert(issuer, original):       cert,
		certmagic.StorageKeys.SitePrivateKey(issuer, original): key,
		certmagic.StorageKeys.SiteMeta(issuer, original):       []byte(`{"fixture":"preserve-existing-metadata"}`),
	}
	for path, data := range entries {
		if err := storage.Store(ctx, path, data); err != nil {
			t.Fatal(err)
		}
	}
	m := NewManager(config.CertConfig{})
	if err := m.loadPEMFromStorage(ctx, storage, issuer, " \tMIXED.example.test\n"); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.TLSCert().CertPEM, cert) || !bytes.Equal(m.TLSCert().KeyPEM, key) {
		t.Fatal("existing certificate was not reused verbatim")
	}
	for path, want := range entries {
		got, err := storage.Load(ctx, path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("canonical lookup deleted or replaced an existing storage resource")
		}
	}
}

func TestNonACMEModesKeepConfiguredDomainSpelling(t *testing.T) {
	for _, mode := range []string{"none", "self", "file", "content"} {
		t.Run(mode, func(t *testing.T) {
			cfg := config.CertConfig{CertMode: mode, Domain: "MiXeD.Example.TEST", CertDir: t.TempDir()}
			cert, key := generateSelfSignedPair(t, cfg.Domain)
			cfg.CertContent, cfg.KeyContent = string(cert), string(key)
			cfg.CertFile, cfg.KeyFile = filepath.Join(cfg.CertDir, "provided.crt"), filepath.Join(cfg.CertDir, "provided.key")
			if err := os.WriteFile(cfg.CertFile, cert, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(cfg.KeyFile, key, 0o600); err != nil {
				t.Fatal(err)
			}
			m := NewManager(cfg)
			if err := m.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			if m.cfg.Domain != cfg.Domain {
				t.Fatal("ACME normalization changed another certificate mode")
			}
		})
	}
}
