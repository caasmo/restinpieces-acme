package acme // Or root package of your module

// Writer defines the interface for storing certificate history records.
// Types like Cert are available directly as they are in the same package.
type Writer interface {
	// AddCert adds a new certificate record to the database history.
	AddCert(cert Cert) error // Use Cert directly
	// Potentially add: GetLatestByIdentifier(identifier string) (*Cert, error)
}
