package acme // Or root package of your module

import (
	"errors"
	"fmt"
	"log/slog"
)

type DNSProvider struct {
	APIToken string
}

type Config struct {
	Email                 string
	Domains               []string
	DNSProviders          map[string]DNSProvider
	CADirectoryURL        string
	AcmeAccountPrivateKey string
}

func (c *Config) Validate() error {
	if c.Email == "" {
		return errors.New("config: email cannot be empty")
	}
	if len(c.Domains) == 0 {
		return errors.New("config: domains cannot be empty")
	}
	if len(c.DNSProviders) == 0 {
		return errors.New("config: dns_providers cannot be empty")
	}
	for providerName, providerCfg := range c.DNSProviders {
		switch providerName {
		case "cloudflare":
			if providerCfg.APIToken == "" {
				return fmt.Errorf("config: api_token cannot be empty for dns_provider '%s'", providerName)
			}
		default:
			slog.Warn("config: validation not implemented for dns_provider", "provider", providerName)
		}
	}
	if c.AcmeAccountPrivateKey == "" {
		return errors.New("config: acme_account_private_key cannot be empty")
	}
	if c.CADirectoryURL == "" {
		// Defaulting might be an option, but explicit is better
		return errors.New("config: ca_directory_url cannot be empty")
	}

	// Add more checks as needed (e.g., URL format, key format basic check)

	return nil
}

func LoadConfig() (*Config, error) {

	cfg := &Config{
		Email:   "your-acme-account@example.com",
		Domains: []string{"your.domain.com", "www.your.domain.com"},
		DNSProviders: map[string]DNSProvider{
			"cloudflare": {
				APIToken: "YOUR_CLOUDFLARE_API_TOKEN_HERE",
			},
		},
		CADirectoryURL:        "https://acme-staging-v02.api.letsencrypt.org/directory",
		AcmeAccountPrivateKey: `-----BEGIN EC PRIVATE KEY-----\nPASTE_YOUR_PEM_KEY_HERE\n-----END EC PRIVATE KEY-----`,
	}

	slog.Info("Loading ACME renewal configuration (currently hardcoded)")

	if err := cfg.Validate(); err != nil {
		slog.Error("Invalid ACME renewal configuration", "error", err)
		return nil, fmt.Errorf("invalid renewal configuration: %w", err)
	}

	providerNames := make([]string, 0, len(cfg.DNSProviders))
	for k := range cfg.DNSProviders {
		providerNames = append(providerNames, k)
	}
	slog.Info("ACME renewal configuration loaded and validated successfully", "email", cfg.Email, "domains", cfg.Domains, "providers", providerNames, "ca_url", cfg.CADirectoryURL)

	placeholderSecretDetected := false
	if providerCfg, ok := cfg.DNSProviders["cloudflare"]; ok && providerCfg.APIToken == "YOUR_CLOUDFLARE_API_TOKEN_HERE" {
		placeholderSecretDetected = true
	}
	if cfg.AcmeAccountPrivateKey == `-----BEGIN EC PRIVATE KEY-----\nPASTE_YOUR_PEM_KEY_HERE\n-----END EC PRIVATE KEY-----` {
		placeholderSecretDetected = true
	}

	if placeholderSecretDetected {
		slog.Warn("ACME configuration contains placeholder secrets. Replace hardcoded values!")
	}

	return cfg, nil
}kkkkkkkkkkkkkkkkkkkkkkkkk
