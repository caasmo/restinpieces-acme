package acme // Assuming this package is at the root of your acme module

import (
	"fmt"
	"time"
)

// Cert represents a certificate record 
type Cert struct {
	ID               int64     // Primary Key (Populated on insert)
	Identifier       string    // Identifier for the cert request (e.g., primary domain)
	Domains          string    // JSON array of all domains covered
	CertificateChain string    // PEM encoded certificate chain
	PrivateKey       string    // PEM encoded private key for the cert (Sensitive!)
	IssuedAt         time.Time // UTC timestamp of issuance
	ExpiresAt        time.Time // UTC timestamp of expiry
}

