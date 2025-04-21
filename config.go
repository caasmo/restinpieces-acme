package acme // Or root package of your module

import (
	"errors"
	"fmt"
	"log/slog" // Use slog for logging
	"os"       // For potential future env var loading
)

// Config holds settings specifically for the certificate renewal process.
type Config struct {
	Enabled               bool     // Master switch for this renewal config
	Email                 string   // ACME account email
	Domains               []string // Domains for the certificate
	DNSProvider           string   // Currently only "cloudflare" supported by handler example
	CloudflareApiToken    string   // !! Sensitive - Load securely later !!
	CADirectoryURL        string   // Let's Encrypt Staging/Prod URL
	AcmeAccountPrivateKey string   // !! Sensitive - PEM format - Load securely later !!
}

// Validate checks if the configuration is usable.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil // No validation needed if disabled
	}
	if c.Email == "" {
		return errors.New("config: email cannot be empty when enabled")
	}
	if len(c.Domains) == 0 {
		return errors.New("config: domains cannot be empty when enabled")
	}
	if c.DNSProvider == "" {
		return errors.New("config: dns_provider cannot be empty when enabled")
	}
	// Specific provider checks
	if c.DNSProvider == "cloudflare" && c.CloudflareApiToken == "" {
		return errors.New("config: cloudflare_api_token cannot be empty when dns_provider is 'cloudflare'")
	}
	// Key checks
	if c.AcmeAccountPrivateKey == "" {
		return errors.New("config: acme_account_private_key cannot be empty when enabled")
	}
	if c.CADirectoryURL == "" {
		// Defaulting might be an option, but explicit is better
		return errors.New("config: ca_directory_url cannot be empty when enabled")
	}

	// Add more checks as needed (e.g., URL format, key format basic check)

	return nil
}

// LoadConfig creates or loads the renewal configuration.
// Placeholder: Replace hardcoded values with secure loading (e.g., env vars, secret manager).
func LoadConfig() (*Config, error) {
	// TODO: Replace hardcoded values with loading from environment variables or a secret manager.
	// Example using environment variables (adjust names as needed):
	// email := os.Getenv("ACME_EMAIL")
	// domains := strings.Split(os.Getenv("ACME_DOMAINS"), ",") // Example parsing
	// ... etc ...

	cfg := &Config{
		// --- Hardcoded Example Values (Replace these!) ---
		Enabled:               true, // Set true/false via env or config file later
		Email:                 "your-acme-account@example.com",
		Domains:               []string{"your.domain.com", "www.your.domain.com"},
		DNSProvider:           "cloudflare",
		CloudflareApiToken:    "YOUR_CLOUDFLARE_API_TOKEN_HERE", // !! Load securely !!
		CADirectoryURL:        "https://acme-staging-v02.api.letsencrypt.org/directory", // Staging recommended for testing
		// CADirectoryURL:     "https://acme-v02.api.letsencrypt.org/directory", // Production
		AcmeAccountPrivateKey: `-----BEGIN EC PRIVATE KEY-----\nPASTE_YOUR_PEM_KEY_HERE\n-----END EC PRIVATE KEY-----`, // !! Load securely !!
		// --- End Hardcoded ---
	}

	// Log loading attempt (avoid logging sensitive data directly)
	slog.Info("Loading ACME renewal configuration (currently hardcoded)")

	if err := cfg.Validate(); err != nil {
		slog.Error("Invalid ACME renewal configuration", "error", err)
		return nil, fmt.Errorf("invalid renewal configuration: %w", err)
	}

	// Log success, maybe mask sensitive fields if logging config itself
	slog.Info("ACME renewal configuration loaded and validated successfully", "enabled", cfg.Enabled, "email", cfg.Email, "domains", cfg.Domains, "provider", cfg.DNSProvider, "ca_url", cfg.CADirectoryURL)

	// Warning about hardcoded secrets if applicable
	// This check is basic; refine based on how you load secrets later.
	if cfg.CloudflareApiToken == "YOUR_CLOUDFLARE_API_TOKEN_HERE" || cfg.AcmeAccountPrivateKey == `-----BEGIN EC PRIVATE KEY-----\nPASTE_YOUR_PEM_KEY_HERE\n-----END EC PRIVATE KEY-----` {
		slog.Warn("ACME configuration contains placeholder secrets. Replace hardcoded values!")
		// Optionally return an error here in production environments
		// return nil, errors.New("placeholder secrets detected in ACME configuration")
	}

	return cfg, nil
}
