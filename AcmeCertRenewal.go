package acme // Or root package of your module

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"time"

	rip_queue "github.com/caasmo/restinpieces/queue"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
)

// --- Constants ---
const (
	ConfigScope           = "acme_config"
	DNSProviderCloudflare = "cloudflare"
	// Add constants for other supported providers here
)

// --- Configuration Structs ---

type DNSProvider struct {
	APIToken string
	// Add other provider-specific fields here if needed (e.g., AWS credentials)
}

type Config struct {
	Email                 string
	Domains               []string
	DNSProviders          map[string]DNSProvider // Map provider name (e.g., "cloudflare") to its config
	CADirectoryURL        string
	AcmeAccountPrivateKey string // PEM format
}

// --- Job Handler ---

// CertRenewalHandler handles the job for renewing TLS certificates.
type CertRenewalHandler struct {
	config   *Config // Use Config defined in this package
	dbWriter Writer  // Use Writer interface defined in this package
	logger   *slog.Logger
}

// NewCertRenewalHandler creates a new handler instance.
// It requires the renewal configuration, a database writer, and a logger.
func NewCertRenewalHandler(cfg *Config, writer Writer, logger *slog.Logger) *CertRenewalHandler {
	if cfg == nil || writer == nil || logger == nil {
		panic("NewCertRenewalHandler: received nil config, writer, or logger")
	}
	return &CertRenewalHandler{
		config:   cfg,
		dbWriter: writer,
		logger:   logger.With("job_handler", "cert_renewal"), // Add context
	}
}

// AcmeUser implements lego's registration.User interface (internal helper type)
type AcmeUser struct {
	Email        string
	Registration *registration.Resource
	PrivateKey   crypto.PrivateKey
}

func (u *AcmeUser) GetEmail() string                        { return u.Email }
func (u *AcmeUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *AcmeUser) GetPrivateKey() crypto.PrivateKey        { return u.PrivateKey }

// Handle executes the certificate renewal logic.
func (h *CertRenewalHandler) Handle(ctx context.Context, job rip_queue.Job) error {
	cfg := h.config // Use the handler's config

	h.logger.Info("Attempting certificate renewal process", "domains", cfg.Domains)

	// --- Lego Client Setup (using cfg) ---
	// Parse ACME Account Key (expecting PEM format)
	acmePrivateKey, err := certcrypto.ParsePEMPrivateKey([]byte(cfg.AcmeAccountPrivateKey))
	if err != nil {
		h.logger.Error("Failed to parse ACME account private key from config", "error", err)
		return fmt.Errorf("failed to parse ACME account private key: %w", err)
	}

	acmeUser := AcmeUser{Email: cfg.Email, PrivateKey: acmePrivateKey}
	legoConfig := lego.NewConfig(&acmeUser)
	legoConfig.CADirURL = cfg.CADirectoryURL
	legoConfig.Certificate.KeyType = certcrypto.EC256 // Request ECDSA certs

	legoClient, err := lego.NewClient(legoConfig)
	if err != nil {
		h.logger.Error("Failed to create ACME client", "error", err)
		return fmt.Errorf("failed to create ACME client: %w", err)
	}

	// --- DNS Provider Setup (using cfg.DNSProviders map) ---
	// This example assumes only one provider (Cloudflare) is configured,
	// matching the previous logic but using the new map structure.
	// A more robust implementation would iterate or select the correct provider.
	providerName := DNSProviderCloudflare // Use constant
	providerConfig, ok := cfg.DNSProviders[providerName]
	if !ok {
		err := fmt.Errorf("required DNS provider '%s' not found in configuration", providerName)
		h.logger.Error(err.Error())
		return err
	}

	var dnsProvider challenge.Provider // Use interface type from imported package
	// err is already declared earlier in the function scope
	switch providerName {
	case DNSProviderCloudflare:
		cfLegoConfig := cloudflare.NewDefaultConfig()
		cfLegoConfig.AuthToken = providerConfig.APIToken // Get token from the map value
		// Add other CF config if needed (AuthEmail, AuthKey, ZoneToken etc.) based on your auth method

		var cfProvider *cloudflare.DNSProvider // Declare cfProvider here
		cfProvider, err = cloudflare.NewDNSProviderConfig(cfLegoConfig)
		if err != nil {
			h.logger.Error("Failed to create Cloudflare DNS provider", "error", err)
			return fmt.Errorf("failed to create Cloudflare provider: %w", err)
		}
		dnsProvider = cfProvider // Assign to the interface variable
	// Add cases for other providers here
	default:
		err := fmt.Errorf("unsupported DNS provider configured: %q", providerName)
		h.logger.Error(err.Error())
		return err
	}

	// Set DNS challenge provider with a suitable timeout
	err = legoClient.Challenge.SetDNS01Provider(dnsProvider, dns01.AddDNSTimeout(10*time.Minute))
	if err != nil {
		h.logger.Error("Failed to set DNS01 provider", "provider", providerName, "error", err)
		return fmt.Errorf("failed to set DNS01 provider: %w", err)
	}

	// --- Register Account (if needed) ---
	// Lego usually handles checking if registration exists based on the key.
	// Register needs TermsOfServiceAgreed: true
	if acmeUser.Registration == nil {
		reg, err := legoClient.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			h.logger.Error("ACME account registration failed", "email", acmeUser.Email, "error", err)
			return fmt.Errorf("ACME registration failed for %s: %w", acmeUser.Email, err)
		}
		acmeUser.Registration = reg
		h.logger.Info("ACME account registered/retrieved successfully", "email", acmeUser.Email)
		// Note: Registration info (like URI) isn't persisted by this handler currently.
	}

	// --- Obtain Certificate ---
	request := certificate.ObtainRequest{
		Domains: cfg.Domains,
		Bundle:  true, // Request the full chain including intermediates
	}

	// This is the main blocking call that performs the ACME flow (order, challenge, finalize)
	resource, err := legoClient.Certificate.Obtain(request)
	if err != nil {
		h.logger.Error("Failed to obtain certificate", "domains", request.Domains, "error", err)
		// Consider checking for specific lego errors if needed
		return fmt.Errorf("failed to obtain certificate for domains %v: %w", request.Domains, err)
	}
	h.logger.Info("Successfully obtained certificate", "domains", request.Domains, "certificate_url", resource.CertURL)

	// --- Save Certificate History to Database ---
	if err := h.saveCertificateHistory(resource, h.logger); err != nil {
		// Error is already logged by saveCertificateHistory
		return err
	}

	h.logger.Info("Successfully processed certificate renewal job.", "domains", request.Domains)
	return nil
}

// saveCertificateHistory saves the obtained certificate resource to the database history.
func (h *CertRenewalHandler) saveCertificateHistory(resource *certificate.Resource, logger *slog.Logger) error {
	// 1. Parse the certificate to get expiry and issue dates
	block, _ := pem.Decode(resource.Certificate)
	if block == nil {
		err := fmt.Errorf("failed to decode PEM block from obtained certificate chain")
		logger.Error(err.Error(), "domain", resource.Domain)
		return err
	}
	cert, err := x509.ParseCertificate(block.Bytes) // Parse the leaf certificate
	if err != nil {
		err = fmt.Errorf("failed to parse obtained leaf certificate: %w", err)
		logger.Error(err.Error(), "domain", resource.Domain)
		return err
	}

	// 2. Prepare domains list as JSON string (using the domains from the config used for this request)
	domainsJSON, err := json.Marshal(h.config.Domains)
	if err != nil {
		// This should ideally not happen if config validation passed
		err = fmt.Errorf("failed to marshal domains %v to JSON: %w", h.config.Domains, err)
		logger.Error(err.Error())
		return err
	}

	// 3. Create the Cert struct for database insertion (use directly)
	dbCert := Cert{
		Identifier:       resource.Domain, // Use primary domain from resource as identifier
		Domains:          string(domainsJSON),
		CertificateChain: string(resource.Certificate), // Full PEM chain
		PrivateKey:       string(resource.PrivateKey),  // Corresponding PEM private key (Sensitive!)
		IssuedAt:         cert.NotBefore.UTC(),         // Use parsed cert's NotBefore
		ExpiresAt:        cert.NotAfter.UTC(),          // Use parsed cert's NotAfter
	}

	// 4. Call AddCert via the dbWriter interface
	err = h.dbWriter.AddCert(dbCert)
	if err != nil {
		// Log the failure, error is already wrapped by the db layer
		logger.Error("Failed to add certificate record to history database", "identifier", dbCert.Identifier, "error", err)
		return err // Return the error from the db layer
	}

	logger.Info("Successfully added certificate record to history database", "identifier", dbCert.Identifier, "expiry", dbCert.ExpiresAt.Format(time.RFC3339))
	return nil
}
