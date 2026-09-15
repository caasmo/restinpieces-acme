# Go ACME Certificate Renewal Package

This Go package provides functionality for automating ACME (Let's Encrypt) certificate renewals using the DNS-01 challenge. It integrates with the [restinpieces framework](https://github.com/caasmo/restinpieces) for secure configuration storage and job handling.

## Features

*   Automated certificate issuance and renewal via ACME protocol.
*   Supports DNS-01 challenge for wildcard certificates.
*   Currently supports Cloudflare DNS provider (easily extensible).
*   Secure storage of ACME account keys, configuration, and obtained certificates using `age` encryption via the [restinpieces framework](https://github.com/caasmo/restinpieces).
*   Provides command-line tools for manual renewal and application certificate updates.
*   Includes an example demonstrating integration as a job handler within the application framework.

## Getting Started

### Prepare the Application Config

```bash
ripc -dbpath app.db -agekey age.key app create
```

This applies the schema and stores the application configuration with the framework defaults, including the empty `acme` section.

### Add a dns-01 Entry

```bash
ripc -dbpath app.db -agekey age.key scaffold acme-dns-01 deeploid_cf
```

This creates `acme.dns-01.deeploid_cf` with an empty `provider` and an empty `api_token` credential.

### Fill the Acme Section

```bash
ripc -dbpath app.db -agekey age.key set acme.dns-01.deeploid_cf.provider cloudflare
ripc -dbpath app.db -agekey age.key set acme.dns-01.deeploid_cf.credentials.api_token @/path/to/token
ripc -dbpath app.db -agekey age.key set acme.account.email 'hostmaster@example.com'
ripc -dbpath app.db -agekey age.key set acme.account.key @acme_account_ec256.key
ripc -dbpath app.db -agekey age.key set acme.domains '["example.com", "*.example.com"]'
ripc -dbpath app.db -agekey age.key set acme.ca_directory_url 'https://acme-staging-v02.api.letsencrypt.org/directory'
```

Generate the account key with:

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out acme_account_ec256.key
```

### Request the Certificate

```bash
go run ./cmd/request-acme-cert -dbpath app.db -agekey age.key
```

### Deploy the Certificate

```bash
go run ./cmd/update-app-certificate -dbpath app.db -agekey age.key
```

## Core Package (`acme`)

The `acme` package (`acme_cert.go`) contains the primary logic:

*   `CertHandler`: Implements the job handler interface from [restinpieces](https://github.com/caasmo/restinpieces). This is the core component responsible for performing the certificate renewal process when triggered as a job.
*   The settings live in the `Acme` section of the application configuration.
*   Support for DNS providers (currently Cloudflare).

During a renewal, lego calls the Cloudflare API first to publish the `_acme-challenge` TXT record, then polls DNS until the record is visible, and only if that polling succeeds does it call Let's Encrypt to trigger validation.

## Commands

This repository includes several command-line utilities built using the `acme` package.

### `example`

**Purpose**:  
Demonstrates how to integrate the `acme.CertHandler` into a [restinpieces](https://github.com/caasmo/restinpieces) application.

**Functionality**:  
- Initializes the framework components (database, secure config store)
- Builds the handler from the application's config store (`app.ConfigStore()`)
- Registers the handler with the framework's job runner for the `job_type_acme_cert` job type
- Starts the framework server/runner

**Usage**:  
```bash
go run ./cmd/example -dbpath <path-to-db> -agekey <path-to-identity>
```

### `request-acme-cert`

**Purpose**:  
Manually triggers an ACME certificate request or renewal process *outside* the framework's job runner.

**Functionality**:  
- Connects to the secure configuration store
- The handler reads the `acme` section from the store
- Performs the certificate order and challenge process
- Stages the obtained certificate back into the application config

**Usage**:  
```bash
go run ./cmd/request-acme-cert -dbpath <path> -agekey <path>
```

### `update-app-certificate`

**Purpose**:  
Moves the staged certificate from `acme.certificate`/`acme.private_key` into `server.tls.certificate`/`server.tls.private_key`.

**Functionality**:  
- Connects to the secure configuration store
- Reads the staged pair from the `acme` section
- Moves them into the server TLS settings

**Usage**:  
```bash
go run ./cmd/update-app-certificate -dbpath <path> -agekey <path>
```
