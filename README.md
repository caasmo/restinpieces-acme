# Go ACME Certificate Renewal Package

This Go package provides functionality for automating ACME (Let's Encrypt) certificate renewals using the DNS-01 challenge. It integrates with the [restinpieces framework](https://github.com/caasmo/restinpieces) for secure configuration storage and job handling.

## Features

*   Automated certificate issuance and renewal via ACME protocol.
*   Supports DNS-01 challenge for wildcard certificates.
*   Currently supports Cloudflare DNS provider (easily extensible).
*   Secure storage of ACME account keys, configuration, and obtained certificates using `age` encryption via the [restinpieces framework](https://github.com/caasmo/restinpieces).
*   Provides command-line tools for configuration generation, manual renewal, and application certificate updates.
*   Includes an example demonstrating integration as a job handler within the application framework.

## Getting Started

### Generate Blueprint

```bash
go run ./cmd/generate-blueprint-config
```

This creates `acme.blueprint.toml`.

### Fill Configuration

Edit `acme.blueprint.toml` with your:

- ACME account email (must be at a domain you control; Let's Encrypt rejects reserved domains such as `example.com` with `invalidContact`)
- Domains (e.g. ["example.com", "*.example.com"] for wildcard)
- DNS provider API credentials (required for wildcard certificates)
- ACME account private key (PEM format). Generate an ECDSA P-256 key with:

  ```bash
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out acme_account_ec256.key
  ```

  Then copy the contents into the `AcmeAccountPrivateKey` field.

### Encrypt Configuration

Use the `ripc save` command to encrypt and store the configuration:

```bash
go run ../restinpieces/cmd/ripc -dbpath path/to/database.db -agekey path/to/age.key save --scope acme_config acme.blueprint.toml
```

See all available commands in the [restinpieces CLI documentation](https://github.com/caasmo/restinpieces/tree/main/cmd).

### Initial Request (Optional but Recommended)

```bash
go run ./cmd/request-acme-cert -dbpath <db-path> -agekey <id-path>
```

Ensure necessary environment variables/flags are set.

### Integrate Handler

Use `cmd/example` as a reference to register `acme.CertHandler` in your framework application and schedule recurring jobs.

### Deploy Certificate

```bash
go run ./cmd/update-app-certificate -dbpath <db-path> -agekey <id-path>
```

Run this after successful renewals to deploy the new certificate.


## Core Package (`acme`)

The `acme` package (`acme_cert.go`) contains the primary logic:

*   `CertHandler`: Implements the job handler interface from [restinpieces](https://github.com/caasmo/restinpieces). This is the core component responsible for performing the certificate renewal process when triggered as a job.
*   `Config`: Struct defining the necessary configuration (email, domains, DNS provider details, ACME account key).
*   `Cert`: Struct representing the stored certificate data (certificate chain, private key, expiry).
*   Support for DNS providers (currently Cloudflare).

During a renewal, lego calls the Cloudflare API first to publish the `_acme-challenge` TXT record, then polls DNS until the record is visible, and only if that polling succeeds does it call Let's Encrypt to trigger validation.

## Commands

This repository includes several command-line utilities built using the `acme` package.

### `example`

**Purpose**:  
Demonstrates how to integrate the `acme.CertHandler` into a [restinpieces](https://github.com/caasmo/restinpieces) application.

**Functionality**:  
- Initializes the framework components (database, secure config store)
- Loads the ACME configuration (`acme.Config`) from the secure store
- Creates an instance of `acme.NewCertHandler`
- Registers the handler with the framework's job runner for the `job_type_acme_cert` job type
- Starts the framework server/runner

**Usage**:  
```bash
go run ./cmd/example -dbpath <path-to-db> -agekey <path-to-identity>
```

### `generate-blueprint-config`

**Purpose**:  
Generates a template TOML configuration file (`acme.blueprint.toml` by default).

**Wildcard Notes**:  
- Wildcard certificates require DNS-01 challenge
- Must include both base domain and wildcard (e.g. ["example.com", "*.example.com"])
- DNS provider credentials must be properly configured

**Functionality**:  
Outputs a TOML file containing the structure of the `acme.Config` struct with placeholder values.

**Usage**:  
```bash
go run ./cmd/generate-blueprint-config [-o <output-file.toml>]
```

### `request-acme-cert`

**Purpose**:  
Manually triggers an ACME certificate request or renewal process *outside* the framework's job runner.

**Functionality**:  
- Loads necessary configuration (ACME config, potentially DNS provider credentials)
- Initializes the ACME client (`lego`)
- Performs the certificate order and challenge process
- Saves the obtained certificate to the secure configuration store

**Usage**:  
```bash
go run ./cmd/request-acme-cert -dbpath <path> -agekey <path>
```

### `update-app-certificate`

**Purpose**:  
Retrieves the latest certificate and updates a target application's configuration or files.

**Functionality**:  
- Connects to the secure configuration store
- Reads the `acme.Cert` data
- Updates application configuration/files as needed

**Usage**:  
```bash
go run ./cmd/update-app-certificate -dbpath <path> -agekey <path>
```
