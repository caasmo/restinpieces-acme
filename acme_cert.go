// Package acme obtains TLS certificates with Let's Encrypt and stages them in
// the application's encrypted configuration store.
//
// A TLS certificate proves to a browser that it is talking to the real
// example.com. Let's Encrypt issues such certificates for free, but only after
// you prove that you control the domain. That proof happens over ACME
// (Automatic Certificate Management Environment), the protocol this package
// speaks.
//
// The proof used here is the dns-01 challenge. The package asks the DNS
// provider that hosts the domain to publish a temporary TXT record, Let's
// Encrypt reads that record from the public DNS, and only then issues the
// certificate. dns-01 is the only challenge type that can issue a wildcard
// certificate such as "*.example.com".
//
// The settings live in the Acme section of the application configuration. The
// obtained certificate is staged back into the same section as Certificate and
// PrivateKey, ready for the deploy step that moves them into the server's TLS
// settings.
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
	legolog "github.com/go-acme/lego/v5/log"
	"github.com/go-acme/lego/v5/providers/dns/cloudflare"
	"github.com/go-acme/lego/v5/registration"
)

// DNSProviderCloudflare is the provider name for Cloudflare in an acme.dns-01
// entry.
const DNSProviderCloudflare = "cloudflare"

// dnsQueryTimeout bounds one DNS lookup while lego checks the dns-01 challenge
// record. It is applied to lego's shared DNS client.
const dnsQueryTimeout = 10 * time.Minute

// CertHandler obtains a certificate when the job queue runs an acme_cert job.
type CertHandler struct {
	secureConfigStore config.SecureStore
	logger            *slog.Logger
}

// NewCertHandler builds a handler from the encrypted store that holds the
// application configuration, and a logger. The handler reads the configuration
// from the store at each request and stages the obtained certificate back into
// it. It also points lego's own logger at the handler's logger, so lego's step
// logs (dns-01 progress, order validation) share the same format and level as
// the handler's lines.
func NewCertHandler(store config.SecureStore, logger *slog.Logger) *CertHandler {
	if store == nil || logger == nil {
		panic("NewCertHandler: received nil store or logger")
	}
	handlerLogger := logger.With("job_handler", "acme_cert")
	legolog.SetDefault(handlerLogger)

	return &CertHandler{
		secureConfigStore: store,
		logger:            handlerLogger,
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

// Handle obtains a certificate and stages it in the Acme section of the
// application configuration. It reads the configuration from the encrypted
// store at the start, so it always sees the latest saved values. The job
// queue calls it for each acme_cert job; the job value itself is not used.
//
// The steps follow the ACME order of operations: load the application config,
// parse the account key and build a client for the configured ACME server,
// select the dns-01 entry and register its solver, register the account
// (idempotent, so an existing account is looked up rather than created),
// obtain the certificate, and stage it.
func (h *CertHandler) Handle(ctx context.Context, job db.Job) error {
	cfg, err := h.loadApplicationConfig()
	if err != nil {
		return err
	}
	acmeCfg := cfg.Acme

	h.logger.Info("Attempting certificate request", "domains", acmeCfg.Domains)

	// --- ACME client ---
	// The account key is the account's identity, a private key in PEM form.
	// Parse it into a crypto.Signer that lego can use.
	acmePrivateKey, err := certcrypto.ParsePEMPrivateKey([]byte(acmeCfg.Account.Key))
	if err != nil {
		h.logger.Error("Failed to parse ACME account private key from config", "error", err)
		return fmt.Errorf("failed to parse ACME account private key: %w", err)
	}

	acmeUser := AcmeUser{Email: acmeCfg.Account.Email, PrivateKey: acmePrivateKey}
	legoConfig := lego.NewConfig(&acmeUser)
	legoConfig.CADirURL = acmeCfg.CADirectoryURL

	legoClient, err := lego.NewClient(legoConfig)
	if err != nil {
		h.logger.Error("Failed to create ACME client", "error", err)
		return fmt.Errorf("failed to create ACME client: %w", err)
	}

	// --- DNS provider ---
	entryLabel, entry, err := dns01Entry(acmeCfg.DNS01)
	if err != nil {
		h.logger.Error(err.Error())
		return err
	}
	h.logger.Debug("Using dns-01 entry", "entry", entryLabel, "provider", entry.Provider)

	dnsProvider, err := getDNSProvider(entryLabel, entry, h.logger)
	if err != nil {
		return err
	}

	// lego looks up the challenge record through a shared DNS client. Set how
	// long one lookup may take, then register the DNS-01 solver. The client is
	// rebuilt on every run on purpose: the timeout belongs to the shared client,
	// not to the solver.
	dns01.SetDefaultClient(dns01.NewClient(&dns01.Options{Timeout: dnsQueryTimeout}))

	// Require the challenge record only on the domain's authoritative servers.
	// lego's default also requires it on the local recursive resolvers, but they
	// cache the NXDOMAIN from lego's zone lookup, which runs before the record
	// exists, for the zone's negative TTL (30 minutes on Cloudflare). The cached
	// answer outlives the propagation window, so that check can never pass.
	// Let's Encrypt validates against the authoritative servers, so that is the
	// check that matters.
	err = legoClient.Challenge.SetDNS01Provider(dnsProvider, dns01.DisableRecursiveNSsPropagationRequirement())
	if err != nil {
		h.logger.Error("Failed to set DNS01 provider", "provider", entry.Provider, "error", err)
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
		Domains: acmeCfg.Domains,
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

	err = h.saveCertificate(cfg, resource)
	if err != nil {
		return err
	}

	h.logger.Info("Successfully processed certificate request.", "domains", request.Domains)
	return nil
}

// loadApplicationConfig reads the application configuration from the encrypted
// store and merges it over the framework defaults, so the handler works with
// the same configuration the application runs with.
func (h *CertHandler) loadApplicationConfig() (*config.Config, error) {
	tomlData, format, err := h.secureConfigStore.Get(config.ScopeApplication, 0)
	if err != nil {
		h.logger.Error("Failed to load application config from secure store", "scope", config.ScopeApplication, "error", err)
		return nil, fmt.Errorf("failed to load application config: %w", err)
	}
	if len(tomlData) == 0 {
		err := fmt.Errorf("application config loaded from secure store is empty")
		h.logger.Error(err.Error(), "scope", config.ScopeApplication)
		return nil, err
	}
	if format != "toml" {
		err := fmt.Errorf("application config is not in TOML format, got %q", format)
		h.logger.Error(err.Error(), "scope", config.ScopeApplication)
		return nil, err
	}

	cfg := config.NewDefaultConfig()
	err = toml.Unmarshal(tomlData, cfg)
	if err != nil {
		h.logger.Error("Failed to unmarshal application config", "scope", config.ScopeApplication, "error", err)
		return nil, fmt.Errorf("failed to unmarshal application config: %w", err)
	}

	return cfg, nil
}

// dns01Entry returns the single dns-01 entry that has a provider set. An empty
// provider deactivates an entry, so exactly one entry must be active for a
// request to have a DNS provider.
func dns01Entry(entries config.AcmeDNS01) (string, config.AcmeDNS01Entry, error) {
	label := ""
	var entry config.AcmeDNS01Entry

	for key, candidate := range entries {
		if candidate.Provider == "" {
			continue
		}
		if label != "" {
			return "", config.AcmeDNS01Entry{}, fmt.Errorf("acme.dns-01 has more than one active entry: %q and %q", label, key)
		}
		label = key
		entry = candidate
	}

	if label == "" {
		return "", config.AcmeDNS01Entry{}, fmt.Errorf("acme.dns-01 has no active entry: set provider on exactly one entry")
	}

	return label, entry, nil
}

// getDNSProvider builds the DNS provider that lego uses to publish the dns-01
// challenge record. The entry's credentials are read by key, so each provider
// implementation documents the keys it needs.
func getDNSProvider(entryLabel string, entry config.AcmeDNS01Entry, logger *slog.Logger) (challenge.Provider, error) {
	switch entry.Provider {
	case DNSProviderCloudflare:
		apiToken := entry.Credentials["api_token"]
		if apiToken == "" {
			err := fmt.Errorf("acme.dns-01.%s.credentials.api_token is empty", entryLabel)
			logger.Error(err.Error())
			return nil, err
		}

		cfLegoConfig := cloudflare.NewDefaultConfig()
		cfLegoConfig.AuthToken = apiToken
		// Add other Cloudflare settings here if the authentication method needs
		// them, for example ZoneToken.

		cfProvider, err := cloudflare.NewDNSProviderConfig(cfLegoConfig)
		if err != nil {
			logger.Error("Failed to create Cloudflare DNS provider", "error", err)
			return nil, fmt.Errorf("failed to create Cloudflare provider: %w", err)
		}
		return cfProvider, nil
	default:
		err := fmt.Errorf("unsupported DNS provider configured: %q", entry.Provider)
		logger.Error(err.Error())
		return nil, err
	}
}

// saveCertificate stages the obtained certificate chain and its private key in
// the Acme section of the application configuration, so the deploy step can
// move them into the server's TLS settings.
func (h *CertHandler) saveCertificate(cfg *config.Config, resource *certificate.Resource) error {
	// The chain starts with the certificate itself. Decode it to read when it
	// expires for the stored version's description.
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

	cfg.Acme.Certificate = string(resource.Certificate)
	cfg.Acme.PrivateKey = string(resource.PrivateKey)

	tomlBytes, err := toml.Marshal(cfg)
	if err != nil {
		h.logger.Error("Failed to marshal application config to TOML", "error", err)
		return fmt.Errorf("failed to marshal application config to TOML: %w", err)
	}

	expiryStr := cert.NotAfter.UTC().Format(time.RFC3339)
	description := fmt.Sprintf("Staged certificate for domains: %s (expires %s)", strings.Join(resource.Domains, ", "), expiryStr)

	h.logger.Info("Staging obtained certificate", "scope", config.ScopeApplication, "format", "toml", "identifier", resource.ID)
	err = h.secureConfigStore.Save(config.ScopeApplication, tomlBytes, "toml", description)
	if err != nil {
		h.logger.Error("Failed to save application config via SecureConfigStore", "scope", config.ScopeApplication, "error", err)
		return err
	}

	h.logger.Info("Successfully staged certificate", "scope", config.ScopeApplication, "identifier", resource.ID)
	return nil
}
