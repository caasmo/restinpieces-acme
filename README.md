# Go ACME Certificate Renewal Package

This Go package provides functionality for automating ACME (Let's Encrypt) certificate renewals using the DNS-01 challenge. It integrates with the `restinpieces/go-application-framework` for secure configuration storage and job handling.

## Features

*   Automated certificate issuance and renewal via ACME protocol.
*   Supports DNS-01 challenge for wildcard certificates.
*   Currently supports Cloudflare DNS provider (easily extensible).
*   Secure storage of ACME account keys, configuration, and obtained certificates using `age` encryption via the `restinpieces/go-application-framework`.
*   Provides command-line tools for configuration generation, manual renewal, and application certificate updates.
*   Includes an example demonstrating integration as a job handler within the application framework.

## Getting Started

1.  **Generate Blueprint**: Run `go run ./cmd/generate-blueprint-config` to create `acme.blueprint.toml`.
2.  **Fill Configuration**: Edit `acme.blueprint.toml` with your ACME account email, domains, and DNS provider API credentials. Generate an ACME account private key if you don't have one (PEM format).
3.  **Encrypt Configuration**: Use the `restinpieces/go-application-framework` tools (e.g., its CLI or API) to encrypt the filled `acme.blueprint.toml` and store it in the secure configuration store under the `acme_config` scope, using your `age` identity.
4.  **Initial Request (Optional but Recommended)**: Run `go run ./cmd/request-acme-cert -db <db-path> -age-key <id-path>` (ensure necessary env vars/flags are set) to perform the first certificate request and store it.
5.  **Integrate Handler**: Use `cmd/example` as a reference to register `acme.CertRenewalHandler` in your framework application. Schedule a recurring job of type `certificate_renewal`.
6.  **Deploy Certificate**: After a renewal job runs successfully, use a mechanism (like `cmd/update-app-certificate` or a custom job) to retrieve the updated certificate from the `acme_certificate` scope and deploy it to your web server or application.

## Core Package (`acme`)

The `acme` package (`AcmeCertRenewal.go`) contains the primary logic:

*   `CertRenewalHandler`: Implements the `framework.JobHandler` interface. This is the core component responsible for performing the certificate renewal process when triggered as a job.
*   `Config`: Struct defining the necessary configuration (email, domains, DNS provider details, ACME account key).
*   `Cert`: Struct representing the stored certificate data (certificate chain, private key, expiry).
*   Support for DNS providers (currently Cloudflare).

## Commands (`cmd/`)

This repository includes several command-line utilities built using the `acme` package.

### `cmd/example`

*   **Purpose**: Demonstrates how to integrate the `acme.CertRenewalHandler` into a `restinpieces/go-application-framework` application.
*   **Functionality**:
    *   Initializes the framework components (database, secure config store).
    *   Loads the ACME configuration (`acme.Config`) from the secure store.
    *   Creates an instance of `acme.NewCertRenewalHandler`.
    *   Registers the handler with the framework's job runner for the `certificate_renewal` job type.
    *   Starts the framework server/runner.
*   **Usage**: This command serves as a blueprint for integrating ACME renewal into your own application based on the framework. Run it with `-db <path-to-db>` and `-age-key <path-to-identity>`.

### `cmd/generate-blueprint-config`

*   **Purpose**: Generates a template TOML configuration file (`acme.blueprint.toml` by default).
*   **Functionality**: Outputs a TOML file containing the structure of the `acme.Config` struct with placeholder values. This blueprint can then be filled with actual values and encrypted into the application's secure configuration store using the framework's tools.
*   **Usage**: `go run ./cmd/generate-blueprint-config [-o <output-file.toml>]`

### `cmd/request-acme-cert`

*   **Purpose**: Manually triggers an ACME certificate request or renewal process *outside* the framework's job runner.
*   **Functionality**:
    *   Loads necessary configuration (ACME config, potentially DNS provider credentials) - *Note: How it loads config needs clarification, likely expects environment variables or flags*.
    *   Initializes the ACME client (`lego`).
    *   Performs the certificate order and challenge process.
    *   Saves the obtained certificate (chain and private key) to the secure configuration store under the `acme_certificate` scope.
*   **Usage**: Useful for initial certificate acquisition or manual renewals/tests. Requires configuration details (e.g., via environment variables or flags - check its source/flags for specifics) and access to the secure config store (`-db <path>`, `-age-key <path>`).

### `cmd/update-app-certificate`

*   **Purpose**: Retrieves the latest certificate stored by the ACME handler and updates a target application's configuration or files.
*   **Functionality**:
    *   Connects to the secure configuration store.
    *   Reads the `acme.Cert` data stored under the `acme_certificate` scope.
    *   *How* it updates the application is specific to this command's implementation (e.g., updating specific config files, reloading a service). It likely reads another configuration scope (`app_config`?) to know *what* to update.
*   **Usage**: Intended to be run after a successful certificate renewal to deploy the new certificate to the application that needs it. Requires access to the secure config store (`-dbpath <path>`, `-age-key <path>`).

## Getting Started

1.  **Generate Blueprint**: Run `go run ./cmd/generate-blueprint-config` to create `acme.blueprint.toml`.
2.  **Fill Configuration**: Edit `acme.blueprint.toml` with your ACME account email, domains, and DNS provider API credentials. Generate an ACME account private key if you don't have one (PEM format).
3.  **Encrypt Configuration**: Use the `restinpieces/go-application-framework` tools (e.g., its CLI or API) to encrypt the filled `acme.blueprint.toml` and store it in the secure configuration store under the `acme_config` scope, using your `age` identity.
4.  **Initial Request (Optional but Recommended)**: Run `go run ./cmd/request-acme-cert -db <db-path> -age-key <id-path>` (ensure necessary env vars/flags are set) to perform the first certificate request and store it.
5.  **Integrate Handler**: Use `cmd/example` as a reference to register `acme.CertRenewalHandler` in your framework application. Schedule a recurring job of type `certificate_renewal`.
6.  **Deploy Certificate**: After a renewal job runs successfully, use a mechanism (like `cmd/update-app-certificate` or a custom job) to retrieve the updated certificate from the `acme_certificate` scope and deploy it to your web server or application.
