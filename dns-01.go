package acme

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/caasmo/restinpieces/config"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/providers/dns/cloudflare"
)

// DNSProviderCloudflare is the provider name for Cloudflare in an acme.dns-01
// entry.
const DNSProviderCloudflare = "cloudflare"

// dnsQueryTimeout bounds one DNS lookup while lego checks the dns-01 challenge
// record. It is applied to lego's shared DNS client.
const dnsQueryTimeout = 10 * time.Minute

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
