-- schema/certificates.sql
-- Stores historical records of obtained certificates. Append-only.
-- All time fields should be stored as UTC RFC3339 strings ('YYYY-MM-DDTHH:MM:SSZ').
CREATE TABLE certificates (
    -- Primary Key
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Identifier & Domains
    -- Identifier for the certificate request (e.g., primary domain name).
    -- Note: This schema doesn't enforce uniqueness on identifier, allowing multiple
    -- records for the same identifier over time. Add UNIQUE constraint if needed.
    identifier TEXT NOT NULL,
    -- JSON array of all domain names covered by this certificate (SANs included).
    -- Example: '["example.com", "www.example.com"]'
    domains TEXT NOT NULL,

    -- Certificate Data (PEM Encoded)
    -- The full certificate chain (leaf certificate + intermediates).
    certificate_chain TEXT NOT NULL,
    -- The private key corresponding to the certificate.
    -- !! SECURITY WARNING: Ensure database file has appropriate permissions. !!
    private_key TEXT NOT NULL,

    -- Timestamps (UTC, RFC3339 format: 'YYYY-MM-DDTHH:MM:SSZ')
    -- When the certificate was successfully issued.
    issued_at TEXT NOT NULL,
    -- When the certificate expires.
    expires_at TEXT NOT NULL,

    -- Audit Timestamps (Handled by SQLite defaults)
    -- Timestamp when this record was created in the database.
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
     -- Timestamp when this record was last updated (useful if updates were allowed).
     -- For append-only, this will be same as created_at unless explicitly updated.
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Optional: Index for faster lookups if needed later
-- CREATE INDEX idx_certificates_identifier_issued_at ON certificates(identifier, issued_at DESC);

