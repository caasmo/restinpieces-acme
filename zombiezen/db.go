package zombiezen

import (
	"context"
	"fmt"
	// Adjust import path according to your module structure
	"github.com/caasmo/restinpieces-acme" // Import the root acme package
	"zombiezen.com/go/sqlite/sqlitex"
)

// Db implements the acme.Writer interface using zombiezen/sqlite.
type Db struct {
	pool *sqlitex.Pool
}

// NewWriter creates a new Db instance satisfying the Writer interface.
// It expects the sqlitex.Pool to be created and managed externally.
func NewWriter(pool *sqlitex.Pool) *Db {
	if pool == nil {
		// Or handle this more gracefully depending on requirements
		panic("zombiezen.NewWriter: received nil pool")
	}
	return &Db{pool: pool}
}

// AddCert adds a new certificate record to the 'certificates' table.
func (d *Db) AddCert(cert acme.Cert) error { // Use acme.Cert
	conn, err := d.pool.Take(context.TODO()) // Use appropriate context
	if err != nil {
		// Consider adding more context, like the identifier, if available and useful
		return fmt.Errorf("db: failed to get connection: %w", err)
	}
	defer d.pool.Put(conn)

	// Assumes table name is 'certificates' and columns match types.Cert
	// Relies on DB defaults for id, created_at, updated_at
	err = sqlitex.Execute(conn,
		`INSERT INTO certificates (
			identifier, domains, certificate_chain, private_key, issued_at, expires_at
		) VALUES (?, ?, ?, ?, ?, ?);`,
		&sqlitex.ExecOptions{
			Args: []interface{}{
				cert.Identifier,
				cert.Domains,
				cert.CertificateChain,
				cert.PrivateKey,
				acme.TimeFormat(cert.IssuedAt),  // Use acme.TimeFormat
				acme.TimeFormat(cert.ExpiresAt), // Use acme.TimeFormat
			},
		})

	if err != nil {
		// The error from Execute might already contain useful info (like constraint violations)
		return fmt.Errorf("db: failed to insert certificate for identifier %q: %w", cert.Identifier, err)
	}
	return nil
}

// Remove or comment out old Get() and Save() methods if they existed here.
