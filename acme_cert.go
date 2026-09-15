// Package acme renews TLS certificates with Let's Encrypt and stores them in
// the application's encrypted configuration store.
//
// A TLS certificate proves to a browser that it is talking to the real
// example.com. Let's Encrypt issues such certificates for free, but only after
// you prove that you control the domain. That proof happens over ACME
// (Automatic Certificate Management Environment), the protocol this package
// speaks.
//
// The proof used here is the DNS-01 challenge. The package asks the DNS
// provider that hosts the domain to publish a temporary TXT record, Let's
// Encrypt reads that record from the public DNS, and only then issues the
// certificate. DNS-01 is the only challenge type that can issue a wildcard
// certificate such as "*.example.com".
//
// The renewal settings live in Config and are read from the encrypted store.
// The obtained certificate is written back to the encrypted store as Cert, so
// another command can install it into the web server.
package acme

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/caasmo/restinpieces/config"
	"github.com/caasmo/restinpieces/db"
	"github.com/pelletier/go-toml/v2"

	legoacme "github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/providers/dns/cloudflare"
	"github.com/go-acme/lego/v5/registration"
)

const (
	// ScopeConfig is the encrypted-store scope that holds the renewal settings
	// (Config): the account email, the domains, the DNS provider credentials
	// and the ACME account key.
	ScopeConfig = "acme_config"
	// ScopeAcmeCertificate is the encrypted-store scope that holds the most
	// recently obtained certificate (Cert): the certificate chain and the
	// private key that matches it.
	ScopeAcmeCertificate = "acme_certificate"
	// DNSProviderCloudflare is the provider name for Cloudflare in the
	// DNSProviders map of Config.
	DNSProviderCloudflare = "cloudflare"
)

// dnsQueryTimeout bounds one DNS lookup while lego checks the DNS-01 challenge
// record. It is applied to lego's shared DNS client.
const dnsQueryTimeout = 10 * time.Minute

// DNSProvider holds the credentials for one DNS provider. A DNS provider is
// the service that hosts the domain's DNS records, and can therefore publish
// the temporary record that the DNS-01 challenge needs.
type DNSProvider struct {
	// APIToken is the provider's API token, used to create and remove the
	// temporary DNS record. For Cloudflare it needs permission to edit DNS
	// records in the zone.
	APIToken string
}

// Config holds the settings for certificate renewal. It is stored encrypted
// under ScopeConfig and read back as TOML.
type Config struct {
	// Email is the contact address for the ACME account. Let's Encrypt uses it
	// to warn about certificates that are about to expire.
	Email string

	// Domains lists every name the certificate must cover. For a wildcard
	// certificate, include both the base domain and the wildcard, for example
	// ["example.com", "*.example.com"].
	Domains []string

	// DNSProviders maps a provider name (for example "cloudflare") to its
	// credentials.
	DNSProviders map[string]DNSProvider

	// CADirectoryURL is the address of the ACME server. Let's Encrypt runs two
	// independent servers, staging for testing and production for real
	// certificates:
	//
	//	https://acme-staging-v02.api.letsencrypt.org/directory
	//	https://acme-v02.api.letsencrypt.org/directory
	//
	// The two are separate: an account registered on one is unknown to the
	// other, so the account key must be registered on each server you use.
	CADirectoryURL string

	// ActiveDNSProvider names which entry of DNSProviders to use.
	ActiveDNSProvider string

	// AcmeAccountPrivateKey is the ACME account's private key in PEM form. It
	// identifies the account, so keep it secret and reuse it to reach the same
	// account on later runs. Generate one with:
	//
	//	openssl genpkey -algorithm Ed25519 -out acme_account_ed25519.key
	//
	// In TOML, paste it as a multi-line literal string ('''...''').
	AcmeAccountPrivateKey string
}

// Cert is the certificate we obtained, stored encrypted under
// ScopeAcmeCertificate as TOML.
//
// A certificate is not a single document. The server needs the certificate
// itself plus the intermediate certificate that signed it, so that clients can
// follow the chain up to a root they already trust; that pair is
// CertificateChain. The matching private key is stored in PrivateKey. Both are
// PEM text: a header, a block of base64, and a footer.
type Cert struct {
	// Identifier is a label for this certificate, taken from its main domain.
	Identifier string
	// Domains lists every name the certificate covers.
	Domains []string
	// CertificateChain is the PEM-encoded certificate followed by the
	// intermediate certificate that signed it.
	CertificateChain string
	// PrivateKey is the PEM-encoded private key matching the certificate. It is
	// sensitive: anyone who has it can impersonate the domain.
	PrivateKey string
	// IssuedAt is when the certificate became valid (its NotBefore time).
	IssuedAt time.Time
	// ExpiresAt is when the certificate stops being valid (its NotAfter time).
	ExpiresAt time.Time
}

// CertHandler obtains a certificate when the job queue runs an acme_cert job.
type CertHandler struct {
	config            *Config
	secureConfigStore config.SecureStore
	logger            *slog.Logger
}

// NewCertHandler builds a handler from the certificate settings, the encrypted
// store used to save the certificate, and a logger.
func NewCertHandler(cfg *Config, store config.SecureStore, logger *slog.Logger) *CertHandler {
	if cfg == nil || store == nil || logger == nil {
		panic("NewCertHandler: received nil config, store, or logger")
	}
	return &CertHandler{
		config:            cfg,
		secureConfigStore: store,
		logger:            logger.With("job_handler", "acme_cert"),
	}
}

// AcmeUser carries the ACME account details that lego needs: the contact
// email, the account private key, and the account registration once it is
// known. It implements lego's registration.User interface.
type AcmeUser struct {
	Email        string
	Registration *legoacme.ExtendedAccount
	PrivateKey   crypto.Signer
}

// GetEmail returns the account's contact email.
func (u *AcmeUser) GetEmail() string { return u.Email }

// GetRegistration returns the account registration, if the account has been
// registered.
func (u *AcmeUser) GetRegistration() *legoacme.ExtendedAccount { return u.Registration }

// GetPrivateKey returns the account's private key. lego uses it to sign the
// requests it sends to the ACME server.
func (u *AcmeUser) GetPrivateKey() crypto.Signer { return u.PrivateKey }

// Handle obtains a certificate. The job queue calls it for each acme_cert
// job; the job value itself is not used.
//
// The steps follow the ACME order of operations: parse the account key and
// build a client for the configured ACME server, select the DNS provider and
// register the DNS-01 solver, register the account (idempotent, so an existing
// account is looked up rather than created), obtain the certificate, and save
// it to the encrypted store.
func (h *CertHandler) Handle(ctx context.Context, job db.Job) error {
	cfg := h.config

	h.logger.Info("Attempting certificate renewal process", "domains", cfg.Domains)

	// --- ACME client ---
	// The account key is the account's identity, a private key in PEM form.
	// Parse it into a crypto.Signer that lego can use.
	acmePrivateKey, err := certcrypto.ParsePEMPrivateKey([]byte(cfg.AcmeAccountPrivateKey))
	if err != nil {
		h.logger.Error("Failed to parse ACME account private key from config", "error", err)
		return fmt.Errorf("failed to parse ACME account private key: %w", err)
	}

	acmeUser := AcmeUser{Email: cfg.Email, PrivateKey: acmePrivateKey}
	legoConfig := lego.NewConfig(&acmeUser)
	legoConfig.CADirURL = cfg.CADirectoryURL

	legoClient, err := lego.NewClient(legoConfig)
	if err != nil {
		h.logger.Error("Failed to create ACME client", "error", err)
		return fmt.Errorf("failed to create ACME client: %w", err)
	}

	// --- DNS provider ---
	providerName := cfg.ActiveDNSProvider
	if providerName == "" {
		err := fmt.Errorf("ActiveDNSProvider field is missing or empty in ACME configuration")
		h.logger.Error(err.Error())
		return err
	}
	h.logger.Debug("Using configured DNS provider", "provider_name", providerName)

	providerConfig, ok := cfg.DNSProviders[providerName]
	if !ok {
		err := fmt.Errorf("configured ActiveDNSProvider '%s' not found in DNSProviders map", providerName)
		h.logger.Error(err.Error())
		return err
	}

	dnsProvider, err := getDNSProvider(providerName, providerConfig, h.logger)
	if err != nil {
		return err
	}

	// lego looks up the challenge record through a shared DNS client. Set how
	// long one lookup may take, then register the DNS-01 solver. The client is
	// rebuilt on every run on purpose: the timeout belongs to the shared client,
	// not to the solver.
	dns01.SetDefaultClient(dns01.NewClient(&dns01.Options{Timeout: dnsQueryTimeout}))

	err = legoClient.Challenge.SetDNS01Provider(dnsProvider)
	if err != nil {
		h.logger.Error("Failed to set DNS01 provider", "provider", providerName, "error", err)
		return fmt.Errorf("failed to set DNS01 provider: %w", err)
	}

	// --- Account registration ---
	// Register is idempotent: a new key creates an account, an existing key
	// returns the existing account. TermsOfServiceAgreed must be true.
	reg, err := legoClient.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		h.logger.Error("ACME account registration/retrieval failed", "email", acmeUser.Email, "error", err)
		return fmt.Errorf("ACME registration/retrieval failed for %s: %w", acmeUser.Email, err)
	}
	acmeUser.Registration = reg
	h.logger.Info("ACME account registered/retrieved successfully", "email", acmeUser.Email, "account_location", reg.Location)

	// --- Obtain the certificate ---
	// Bundle asks for the full chain (the certificate plus its intermediate).
	// KeyType asks for an ECDSA P-256 key pair for the certificate.
	request := certificate.ObtainRequest{
		Domains: cfg.Domains,
		Bundle:  true,
		KeyType: certcrypto.EC256,
	}

	// This is the blocking call that runs the ACME flow: order, DNS-01
	// challenge, validation, and download.
	resource, err := legoClient.Certificate.Obtain(ctx, request)
	if err != nil {
		h.logger.Error("Failed to obtain certificate", "domains", request.Domains, "error", err)
		return fmt.Errorf("failed to obtain certificate for domains %v: %w", request.Domains, err)
	}
	h.logger.Info("Successfully obtained certificate", "domains", request.Domains, "certificate_url", resource.CertURL)

	err = h.saveCertificate(resource)
	if err != nil {
		return err
	}

	h.logger.Info("Successfully processed certificate renewal job.", "domains", request.Domains)
	return nil
}

// getDNSProvider builds the DNS provider that lego uses to publish the DNS-01
// challenge record.
func getDNSProvider(providerName string, providerConfig DNSProvider, logger *slog.Logger) (challenge.Provider, error) {
	switch providerName {
	case DNSProviderCloudflare:
		cfLegoConfig := cloudflare.NewDefaultConfig()
		cfLegoConfig.AuthToken = providerConfig.APIToken
		// Add other Cloudflare settings here if the authentication method needs
		// them, for example ZoneToken.

		cfProvider, err := cloudflare.NewDNSProviderConfig(cfLegoConfig)
		if err != nil {
			logger.Error("Failed to create Cloudflare DNS provider", "error", err)
			return nil, fmt.Errorf("failed to create Cloudflare provider: %w", err)
		}
		return cfProvider, nil
	default:
		err := fmt.Errorf("unsupported DNS provider configured: %q", providerName)
		logger.Error(err.Error())
		return nil, err
	}
}

// saveCertificate reads the validity dates from the obtained certificate and
// stores the certificate chain and its private key in the encrypted store.
func (h *CertHandler) saveCertificate(resource *certificate.Resource) error {
	// The chain starts with the certificate itself. Decode it to read when it
	// becomes valid and when it expires.
	block, _ := pem.Decode(resource.Certificate)
	if block == nil {
		err := fmt.Errorf("failed to decode PEM block from obtained certificate chain")
		h.logger.Error(err.Error(), "domain", resource.ID)
		return err
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		err = fmt.Errorf("failed to parse obtained leaf certificate: %w", err)
		h.logger.Error(err.Error(), "domain", resource.ID)
		return err
	}

	certData := Cert{
		Identifier:       resource.ID,
		Domains:          resource.Domains,
		CertificateChain: string(resource.Certificate),
		PrivateKey:       string(resource.PrivateKey),
		IssuedAt:         cert.NotBefore.UTC(),
		ExpiresAt:        cert.NotAfter.UTC(),
	}

	tomlBytes, err := toml.Marshal(certData)
	if err != nil {
		h.logger.Error("Failed to marshal certificate data to TOML", "error", err)
		return fmt.Errorf("failed to marshal certificate data to TOML: %w", err)
	}

	expiryStr := certData.ExpiresAt.Format(time.RFC3339)
	description := fmt.Sprintf("Obtained certificate for domains: %s (expires %s)", strings.Join(certData.Domains, ", "), expiryStr)

	h.logger.Info("Saving obtained certificate configuration", "scope", ScopeAcmeCertificate, "format", "toml", "identifier", certData.Identifier)
	err = h.secureConfigStore.Save(ScopeAcmeCertificate, tomlBytes, "toml", description)
	if err != nil {
		h.logger.Error("Failed to save certificate config via SecureConfigStore", "scope", ScopeAcmeCertificate, "error", err)
		return err
	}

	h.logger.Info("Successfully saved certificate configuration", "scope", ScopeAcmeCertificate, "identifier", certData.Identifier)
	return nil
}
