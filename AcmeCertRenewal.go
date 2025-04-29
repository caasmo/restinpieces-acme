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
	rip_queue "github.com/caasmo/restinpieces/queue"
	"github.com/pelletier/go-toml/v2" // Import TOML library

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
)

const (
	ConfigScope            = "acme_config"
	CertificateOutputScope = "certificate_output" // Scope for saving the obtained cert+key
	DNSProviderCloudflare  = "cloudflare"
)


type DNSProvider struct {
	APIToken string
}

type Config struct {
	Email                 string
	Domains               []string
	DNSProviders          map[string]DNSProvider // Map provider name (e.g., "cloudflare") to its config
	CADirectoryURL        string
	AcmeAccountPrivateKey string // PEM format
}

// CertificateOutput defines the structure for the TOML config to be saved.
type CertificateOutput struct {
	CertificateChain string `toml:"certificate_chain"`
	PrivateKey       string `toml:"private_key"`
}

// CertRenewalHandler handles the job for renewing TLS certificates.
type CertRenewalHandler struct {
	config            *Config // Use Config defined in this package
	secureConfigStore config.SecureConfigStore
	logger            *slog.Logger
}

// NewCertRenewalHandler creates a new handler instance.
// It requires the renewal configuration, a secure config store, and a logger.
func NewCertRenewalHandler(cfg *Config, store config.SecureConfigStore, logger *slog.Logger) *CertRenewalHandler {
	if cfg == nil || store == nil || logger == nil {
		panic("NewCertRenewalHandler: received nil config, store, or logger")
	}
	return &CertRenewalHandler{
		config:            cfg,
		secureConfigStore: store,
		logger:            logger.With("job_handler", "cert_renewal"), // Add context
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

	// --- Save Certificate Configuration ---
	if err := h.saveCertificateConfig(resource, h.logger); err != nil {
		// Error is already logged by saveCertificateConfig
		return err
	}

	h.logger.Info("Successfully processed certificate renewal job.", "domains", request.Domains)
	return nil
}

// saveCertificateConfig saves the obtained certificate and private key to the SecureConfigStore.
func (h *CertRenewalHandler) saveCertificateConfig(resource *certificate.Resource, logger *slog.Logger) error {
	// 1. Prepare the data structure for TOML marshalling
	outputData := CertificateOutput{
		CertificateChain: string(resource.Certificate),
		PrivateKey:       string(resource.PrivateKey),
	}

	// 2. Marshal the data to TOML
	tomlBytes, err := toml.Marshal(outputData)
	if err != nil {
		logger.Error("Failed to marshal certificate output to TOML", "error", err)
		return fmt.Errorf("failed to marshal certificate output to TOML: %w", err)
	}

	// 3. Determine description
	// Parse the certificate to get expiry date for the description
	var expiryStr string
	block, _ := pem.Decode(resource.Certificate)
	if block != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			expiryStr = cert.NotAfter.UTC().Format(time.RFC3339)
		} else {
			logger.Warn("Could not parse certificate to get expiry for description", "error", err)
		}
	} else {
		logger.Warn("Could not decode PEM block to get expiry for description")
	}

	description := fmt.Sprintf("Obtained certificate for domains: %s", strings.Join(h.config.Domains, ", "))
	if expiryStr != "" {
		description += fmt.Sprintf(" (expires %s)", expiryStr)
	}

	// 4. Save using SecureConfigStore
	logger.Info("Saving obtained certificate configuration", "scope", CertificateOutputScope, "format", "toml")
	err = h.secureConfigStore.Save(CertificateOutputScope, tomlBytes, "toml", description)
	if err != nil {
		logger.Error("Failed to save certificate config via SecureConfigStore", "scope", CertificateOutputScope, "error", err)
		// Don't wrap here, Save should provide enough context
		return err
	}

	logger.Info("Successfully saved certificate configuration", "scope", CertificateOutputScope)
	return nil
}
