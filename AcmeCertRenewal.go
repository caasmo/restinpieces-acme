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

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
)

const (
	ScopeConfig           = "acme_config"        // Scope for storing ACME handler config (email, domains, keys)
	ScopeAcmeCertificate  = "acme_certificate"   // Scope for saving obtained cert+key
	DNSProviderCloudflare = "cloudflare"
)

type DNSProvider struct {
	APIToken string
}

type Config struct {
	// used by Let's Encrypt (the ACME CA) primarily for notifications. They
	// will send reminders about certificate expiry and potentially other
	// important account notices
	Email string
	// Obtaining wildcard certificates (e.g., *.example.com) requires using the
	// dns-01 challenge type. ACME best practices (and Let's Encrypt's policy)
	// require you to also include the base domain (example.com) in the same
	// certificate request Domains = ["example.com", "*.example.com"]
	Domains      []string
	DNSProviders map[string]DNSProvider // Map provider name (e.g., "cloudflare") to its config
	// The Let's Encrypt staging environment
	// (https://acme-staging-v02.api.letsencrypt.org/directory) and the
	// production environment (https://acme-v02.api.letsencrypt.org/directory)
	// are completely separate. Separate Accounts: An account registered on the
	// staging environment (identified by your AcmeAccountPrivateKey) is not
	// recognized by the production environment, and vice-versa. You need to
	// register your account key on each environment you interact with
	CADirectoryURL        string
	ActiveDNSProvider     string // Name of the provider key in DNSProviders map to use
    // openssl genpkey -algorithm Ed25519 -out acme_account_ed25519.key
    // this is account main identifier for acme providers 
    // For toml manual insertion the Multiline Literal String ('''...''') is
    // the best choice.
	AcmeAccountPrivateKey string
}

// Cert defines the structure for the TOML config to be saved.
// Note: TOML tags are not strictly needed here as we marshal the whole struct.
type Cert struct {
	Identifier       string    // Identifier for the cert request (e.g., primary domain)
	Domains          []string  // List of all domains covered
	CertificateChain string    // PEM encoded certificate chain
	PrivateKey       string    // PEM encoded private key for the cert (Sensitive!)
	IssuedAt         time.Time // UTC timestamp of issuance
	ExpiresAt        time.Time // UTC timestamp of expiry
}

type CertRenewalHandler struct {
	config            *Config
	secureConfigStore config.SecureStore
	logger            *slog.Logger
}

func NewCertRenewalHandler(cfg *Config, store config.SecureStore, logger *slog.Logger) *CertRenewalHandler {
	if cfg == nil || store == nil || logger == nil {
		panic("NewCertRenewalHandler: received nil config, store, or logger")
	}
	return &CertRenewalHandler{
		config:            cfg,
		secureConfigStore: store,
		logger:            logger.With("job_handler", "cert_renewal"),
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

// openssl genpkey -algorithm Ed25519 -out acme_account_ed25519.key
//
//	It's fully supported and often preferred for its modern design.
func (u *AcmeUser) GetPrivateKey() crypto.PrivateKey { return u.PrivateKey }

// Handle executes the certificate renewal logic.
func (h *CertRenewalHandler) Handle(ctx context.Context, job db.Job) error {
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

	// Get the DNS provider instance using the helper function
	dnsProvider, err := getDNSProvider(providerName, providerConfig, h.logger)
	if err != nil {
		// Error already logged by getDNSProvider or from config checks
		return err // Return the error directly
	}

	// Set DNS challenge provider with a suitable timeout
	err = legoClient.Challenge.SetDNS01Provider(dnsProvider, dns01.AddDNSTimeout(10*time.Minute))
	if err != nil {
		h.logger.Error("Failed to set DNS01 provider", "provider", providerName, "error", err)
		return fmt.Errorf("failed to set DNS01 provider: %w", err)
	}

	// --- Register/Retrieve ACME Account ---
	// We call Register on every run. This function is idempotent:
	// - If the account key is new, it registers a new account with the CA.
	// - If the account key already exists, it retrieves the existing account details.
	// Persisting the registration details (acmeUser.Registration) would add complexity
	// for only minor efficiency gains (saving one network call).
	// Register needs TermsOfServiceAgreed: true.
	reg, err := legoClient.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		h.logger.Error("ACME account registration/retrieval failed", "email", acmeUser.Email, "error", err)
		return fmt.Errorf("ACME registration/retrieval failed for %s: %w", acmeUser.Email, err)
	}
	acmeUser.Registration = reg // Store registration details in the temporary user object
	h.logger.Info("ACME account registered/retrieved successfully", "email", acmeUser.Email, "account_uri", reg.URI)

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

	if err := h.saveCertificate(resource, h.logger); err != nil {
		return err
	}

	h.logger.Info("Successfully processed certificate renewal job.", "domains", request.Domains)
	return nil
}

// getDNSProvider selects and configures the appropriate lego DNS challenge provider
// based on the provided name and configuration.
func getDNSProvider(providerName string, providerConfig DNSProvider, logger *slog.Logger) (challenge.Provider, error) {
	var dnsProvider challenge.Provider
	var err error

	switch providerName {
	case DNSProviderCloudflare:
		cfLegoConfig := cloudflare.NewDefaultConfig()
		cfLegoConfig.AuthToken = providerConfig.APIToken
		// Add other CF config if needed (AuthEmail, AuthKey, ZoneToken etc.) based on your auth method

		var cfProvider *cloudflare.DNSProvider // Declare cfProvider here
		cfProvider, err = cloudflare.NewDNSProviderConfig(cfLegoConfig)
		if err != nil {
			logger.Error("Failed to create Cloudflare DNS provider", "error", err)
			return nil, fmt.Errorf("failed to create Cloudflare provider: %w", err)
		}
		dnsProvider = cfProvider
	default:
		err := fmt.Errorf("unsupported DNS provider configured: %q", providerName)
		logger.Error(err.Error())
		return nil, err
	}

	return dnsProvider, nil
}

func (h *CertRenewalHandler) saveCertificate(resource *certificate.Resource, logger *slog.Logger) error {
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

	// 2. Create the Cert struct
	certData := Cert{
		Identifier:       resource.Domain,              // Use primary domain from resource as identifier
		Domains:          h.config.Domains,             // Assign the slice directly
		CertificateChain: string(resource.Certificate), // Full PEM chain
		PrivateKey:       string(resource.PrivateKey),  // Corresponding PEM private key
		IssuedAt:         cert.NotBefore.UTC(),         // Use parsed cert's NotBefore
		ExpiresAt:        cert.NotAfter.UTC(),          // Use parsed cert's NotAfter
	}

	// 4. Marshal the Cert struct to TOML
	tomlBytes, err := toml.Marshal(certData)
	if err != nil {
		logger.Error("Failed to marshal certificate data to TOML", "error", err)
		return fmt.Errorf("failed to marshal certificate data to TOML: %w", err)
	}

	// 5. Determine description using parsed expiry date
	expiryStr := certData.ExpiresAt.Format(time.RFC3339)
	description := fmt.Sprintf("Obtained certificate for domains: %s (expires %s)", strings.Join(h.config.Domains, ", "), expiryStr)

	// 6. Save using SecureConfigStore
	logger.Info("Saving obtained certificate configuration", "scope", ScopeAcmeCertificate, "format", "toml", "identifier", certData.Identifier)
	err = h.secureConfigStore.Save(ScopeAcmeCertificate, tomlBytes, "toml", description)
	if err != nil {
		logger.Error("Failed to save certificate config via SecureConfigStore", "scope", ScopeAcmeCertificate, "error", err)
		return err
	}

	logger.Info("Successfully saved certificate configuration", "scope", ScopeAcmeCertificate, "identifier", certData.Identifier)
	return nil
}
