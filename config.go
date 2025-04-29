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
