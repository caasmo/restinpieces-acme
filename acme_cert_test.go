package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"testing"
	"time"
)

// stubSecureStore is a config.SecureStore that returns one fixed TOML document.
type stubSecureStore struct {
	tomlData []byte
}

func (s stubSecureStore) Get(scope string, generation int) ([]byte, string, error) {
	return s.tomlData, "toml", nil
}

func (s stubSecureStore) Save(scope string, plaintextData []byte, format string, description string) error {
	return nil
}

func TestLoadAcmeConfig_RemainingLifetimeFraction(t *testing.T) {
	tests := []struct {
		name     string
		document string
		want     float64
	}{
		{
			name:     "absent key falls back to the default",
			document: "[acme]\n  domains = [\"example.com\"]\n",
			want:     0.25,
		},
		{
			name:     "stored value overrides the default",
			document: "[acme]\n  remaining_lifetime_fraction = 0.5\n",
			want:     0.5,
		},
		{
			name:     "missing acme section falls back to the default",
			document: "[server]\n  addr = \":8080\"\n",
			want:     0.25,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewCertHandler(stubSecureStore{tomlData: []byte(tt.document)}, slog.New(slog.NewTextHandler(io.Discard, nil)))

			acmeCfg, err := handler.loadAcmeConfig()
			if err != nil {
				t.Fatalf("loadAcmeConfig() returned an error: %v", err)
			}

			if acmeCfg.RemainingLifetimeFraction != tt.want {
				t.Errorf("RemainingLifetimeFraction: got %v, want %v", acmeCfg.RemainingLifetimeFraction, tt.want)
			}
		})
	}
}

func TestCoversDomains(t *testing.T) {
	tests := []struct {
		name    string
		leaf    *x509.Certificate
		domains []string
		want    bool
	}{
		{
			name:    "DNS names match ignoring case and order",
			leaf:    &x509.Certificate{DNSNames: []string{"example.com", "*.example.com"}},
			domains: []string{"*.EXAMPLE.com", "example.com"},
			want:    true,
		},
		{
			name:    "IP address matches however it is written",
			leaf:    &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("2001:db8::1")}},
			domains: []string{"2001:0db8:0000::1"},
			want:    true,
		},
		{
			name:    "different IP address does not match",
			leaf:    &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("2001:db8::1")}},
			domains: []string{"2001:db8::2"},
			want:    false,
		},
		{
			name:    "DNS name and address together",
			leaf:    &x509.Certificate{DNSNames: []string{"example.com"}, IPAddresses: []net.IP{net.ParseIP("192.0.2.1")}},
			domains: []string{"example.com", "192.0.2.1"},
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := coversDomains(tt.leaf, tt.domains)
			if err != nil {
				t.Fatalf("coversDomains() returned an error: %v", err)
			}

			if got != tt.want {
				t.Errorf("coversDomains() = %v, want %v", got, tt.want)
			}
		})
	}
}

// newTestCertificate generates a self-signed certificate and its private key.
// The serial distinguishes certificates created by separate calls.
func newTestCertificate(t *testing.T, serial int64, notBefore, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert, privateKey, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestStagedCertificate(t *testing.T) {
	now := time.Now()
	leaf, _, leafPEM := newTestCertificate(t, 1, now, now.Add(24*time.Hour))
	_, _, otherPEM := newTestCertificate(t, 2, now, now.Add(24*time.Hour))

	t.Run("returns the leaf of a chain", func(t *testing.T) {
		cert, err := stagedCertificate(leafPEM + otherPEM)
		if err != nil {
			t.Fatalf("stagedCertificate() returned an error: %v", err)
		}

		if cert.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
			t.Errorf("stagedCertificate() returned serial %v, want %v", cert.SerialNumber, leaf.SerialNumber)
		}
	})

	t.Run("rejects a value that is not PEM", func(t *testing.T) {
		_, err := stagedCertificate("not a pem block")
		if err == nil {
			t.Error("stagedCertificate() expected an error, got nil")
		}
	})

	t.Run("rejects a PEM block that is not a certificate", func(t *testing.T) {
		keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}))

		_, err := stagedCertificate(keyPEM)
		if err == nil {
			t.Error("stagedCertificate() expected an error, got nil")
		}
	})

	t.Run("rejects an empty value", func(t *testing.T) {
		_, err := stagedCertificate("")
		if err == nil {
			t.Error("stagedCertificate() expected an error, got nil")
		}
	})
}

func TestPrivateKeyMatchesCertificate(t *testing.T) {
	now := time.Now()
	cert, key, _ := newTestCertificate(t, 1, now, now.Add(24*time.Hour))
	_, otherKey, _ := newTestCertificate(t, 2, now, now.Add(24*time.Hour))

	t.Run("matching key", func(t *testing.T) {
		matches, err := privateKeyMatchesCertificate(cert, key)
		if err != nil {
			t.Fatalf("privateKeyMatchesCertificate() returned an error: %v", err)
		}

		if !matches {
			t.Error("privateKeyMatchesCertificate() = false, want true")
		}
	})

	t.Run("different key", func(t *testing.T) {
		matches, err := privateKeyMatchesCertificate(cert, otherKey)
		if err != nil {
			t.Fatalf("privateKeyMatchesCertificate() returned an error: %v", err)
		}

		if matches {
			t.Error("privateKeyMatchesCertificate() = true, want false")
		}
	})
}

func TestRemainingFractionReached(t *testing.T) {
	issued := time.Now()
	lifetime := 100 * 24 * time.Hour
	leaf := &x509.Certificate{NotBefore: issued, NotAfter: issued.Add(lifetime)}

	tests := []struct {
		name     string
		now      time.Time
		fraction float64
		want     bool
	}{
		{
			name:     "half the lifetime remains",
			now:      issued.Add(lifetime / 2),
			fraction: 0.25,
			want:     false,
		},
		{
			name:     "exactly the fraction remains",
			now:      issued.Add(lifetime * 3 / 4),
			fraction: 0.25,
			want:     true,
		},
		{
			name:     "less than the fraction remains",
			now:      issued.Add(lifetime * 4 / 5),
			fraction: 0.25,
			want:     true,
		},
		{
			name:     "just more than the fraction remains",
			now:      issued.Add(lifetime*3/4 - time.Hour),
			fraction: 0.25,
			want:     false,
		},
		{
			name:     "certificate is not valid yet",
			now:      issued.Add(-time.Hour),
			fraction: 0.25,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := remainingFractionReached(leaf, tt.fraction, tt.now); got != tt.want {
				t.Errorf("remainingFractionReached() = %v, want %v", got, tt.want)
			}
		})
	}
}
