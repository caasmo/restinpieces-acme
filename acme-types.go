type AcmeCert struct {
    ID                   int64     // Primary Key
    Identifier           string    // Unique identifier (e.g., primary domain)
    Domains              string    // JSON array of domains
    CertificateChain     string    // PEM encoded certificate chain
    PrivateKey           string    // PEM encoded private key
    IssuedAt             time.Time // UTC timestamp
    ExpiresAt            time.Time // UTC timestamp
    LastRenewalAttemptAt time.Time // UTC timestamp (zero time if null/not set)
    CreatedAt            time.Time // UTC timestamp
    UpdatedAt            time.Time // UTC timestamp
}

type DbAcme interface {
    // Get retrieves the latest ACME certificate based on issued_at timestamp.
    Get() (*AcmeCert, error)
    // Save inserts or updates an ACME certificate record based on the Identifier.
    Save(cert AcmeCert) error
}


// config 
// Acme holds configuration for ACME (Let's Encrypt) certificate management.
type Acme struct {
    Enabled                 bool     `toml:"enabled" comment:"Enable ACME certificate management"`
    Email                   string   `toml:"email" comment:"ACME account email"`
    Domains                 []string `toml:"domains" comment:"Domains for certificate"`
    DNSProvider             string   `toml:"dns_provider" comment:"DNS provider for challenges (e.g. 'cloudflare')"`
    RenewalDaysBeforeExpiry int      `toml:"renewal_days_before_expiry" comment:"Days before expiry to renew"`
    CloudflareApiToken      string   `toml:"cloudflare_api_token" comment:"Cloudflare API token (set via env)"`
    CADirectoryURL          string   `toml:"ca_directory_url" comment:"ACME directory URL"`
    AcmePrivateKey          string   `toml:"acme_private_key" comment:"ACME account private key (set via env)"`
}

func validateAcme(acme *Acme) error {
    if !acme.Enabled {
        return nil // No validation needed if ACME is disabled
    }
    if acme.Email == "" {
        return fmt.Errorf("acme.email cannot be empty when enabled")
        }
    if len(acme.Domains) == 0 {
        return fmt.Errorf("acme.domains cannot be empty when enabled")
    }
    if acme.DNSProvider == "" {
        return fmt.Errorf("acme.dns_provider cannot be empty when enabled")
    }
    if acme.DNSProvider == "cloudflare" && acme.CloudflareApiToken == "" {
        return fmt.Errorf("acme.cloudflare_api_token cannot be empty when dns_provider is 'cloudflare'")
    }
    if acme.AcmePrivateKey == "" {
        return fmt.Errorf("acme.acme_private_key cannot be empty when enabled")
    }
    return nil
}
