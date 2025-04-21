package types // Assuming this package is at the root of your acme module

import (
	"fmt"
	"time"
)

// Cert represents a certificate record in the database history.
type Cert struct {
	ID               int64     // Primary Key (Populated on insert)
	Identifier       string    // Identifier for the cert request (e.g., primary domain)
	Domains          string    // JSON array of all domains covered
	CertificateChain string    // PEM encoded certificate chain
	PrivateKey       string    // PEM encoded private key for the cert (Sensitive!)
	IssuedAt         time.Time // UTC timestamp of issuance
	ExpiresAt        time.Time // UTC timestamp of expiry
	// CreatedAt/UpdatedAt managed by DB
}

// TimeFormat formats time.Time for SQLite TEXT columns (RFC3339 UTC).
func TimeFormat(t time.Time) string {
	if t.IsZero() {
		return "" // Represent zero time as empty string for DB
	}
	return t.UTC().Format(time.RFC3339)
}

// TimeParse parses RFC3339 UTC strings from SQLite TEXT columns.
func TimeParse(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil // Return zero time for empty/NULL strings
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse time string %q: %w", s, err)
	}
	return t, nil
}
