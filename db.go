package acme // Or root package of your module

import "github.com/caasmo/restinpieces-acme" // Import the root acme package

// Writer defines the interface for storing certificate history records.
type Writer interface {
	// AddCert adds a new certificate record to the database history.
	AddCert(cert acme.Cert) error // Use acme.Cert
	// Potentially add: GetLatestByIdentifier(identifier string) (*acme.Cert, error)
}
