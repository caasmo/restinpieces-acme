package acme // Or root package of your module

import "github.com/your-org/restinpieces-acme/types" // Adjust import path

// Writer defines the interface for storing certificate history records.
type Writer interface {
	// AddCert adds a new certificate record to the database history.
	AddCert(cert types.Cert) error
	// Potentially add: GetLatestByIdentifier(identifier string) (*types.Cert, error)
}
