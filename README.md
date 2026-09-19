# Go ACME Certificate Renewal Package

This Go package provides functionality for automating ACME (Let's Encrypt) certificate renewals using the DNS-01 challenge. It integrates with the [restinpieces framework](https://github.com/caasmo/restinpieces) for secure configuration storage and job handling.

# Content

- [Features](#features)
- [Integrate the job in restinpieces](#integrate-the-job-in-restinpieces)
  - [Register the handler](#register-the-handler)
  - [Declare the schedule](#declare-the-schedule)
- [Get a certificate manually](#get-a-certificate-manually)
  - [Create a scratch database](#create-a-scratch-database)
  - [Add a dns-01 Entry](#add-a-dns-01-entry)
  - [Fill the Acme Section](#fill-the-acme-section)
  - [Request the Certificate](#request-the-certificate)
  - [Deploy the Certificate](#deploy-the-certificate)
- [Commands](#commands)
  - [`example`](#example)
  - [`request-acme-cert`](#request-acme-cert)

## Features

*   Automated certificate issuance and renewal via ACME protocol.
*   Supports DNS-01 challenge for wildcard certificates.
*   Currently supports Cloudflare DNS provider (easily extensible).
*   Secure storage of ACME account keys, configuration, and obtained certificates using `age` encryption via the [restinpieces framework](https://github.com/caasmo/restinpieces).
*   Provides a command-line tool for manual certificate requests and renewals.
*   Includes an example demonstrating integration as a job handler within the application framework.

## Integrate the job in restinpieces

Certificates are issued by a background job. That takes two steps: register the handler in your code, then declare the schedule with `ripc`.

Prerequisite: the `acme` section must be configured first (provider, credentials, account, domains) — the handler reads it on every run and fails without it. Follow [Get a certificate manually](#get-a-certificate-manually) up to filling the section; skip the request and deploy steps, the job does that part.

### Register the handler

Copy what [`cmd/example/main.go`](https://github.com/caasmo/restinpieces-acme/blob/master/cmd/example/main.go) does after `restinpieces.New()` in your app's `main.go`:

```go
certHandler := acme.NewCertHandler(app.ConfigStore(), logger)

err = srv.AddJobHandler("job_type_acme_cert", certHandler)
if err != nil {
    logger.Error("Failed to register certificate job handler", "error", err)
    os.Exit(1)
}
```

### Declare the schedule

Each entry under `scheduler.jobs` is one schedule:

```bash
ripc scaffold job acme_cert
ripc set scheduler.jobs.acme_cert.job_type job_type_acme_cert
ripc set scheduler.jobs.acme_cert.activated true
```

This creates `scheduler.jobs.acme_cert` with a 1h interval. Set it to around 8h — that stays outside the Let's Encrypt retry-later window:

```bash
ripc set scheduler.jobs.acme_cert.interval 8h
```

Reload the app so the scheduler picks it up, then verify:

```bash
ripc get scheduler.jobs.acme_cert
ripc job list
```

The scheduler adds one pending run. When it completes, the next run is added automatically. To stop scheduling new runs without removing the entry:

```bash
ripc set scheduler.jobs.acme_cert.activated false
```

## Get a certificate manually

Set these once — every `ripc` command below uses them, so the commands leave the flags out:

```bash
export RIPC_DB=scratch.db
export RIPC_AGE_KEY_PATH=age.key
```

### Create a scratch database

```bash
ripc app create
```

This creates a throwaway `scratch.db` with the framework defaults, including the empty `acme` section. Everything below runs against it.

### Add a dns-01 Entry

```bash
ripc scaffold acme-dns-01 my_cf
```

This creates `acme.dns-01.my_cf` with an empty `provider` and an empty `api_token` credential.

### Fill the Acme Section

```bash
ripc set acme.dns-01.my_cf.provider cloudflare
ripc set acme.dns-01.my_cf.credentials.api_token @/path/to/token
ripc set acme.account.email 'hostmaster@example.com'
ripc set acme.account.key @acme_account_ec256.key
ripc set acme.domains '["example.com", "*.example.com"]'
ripc set acme.ca_directory_url 'https://acme-staging-v02.api.letsencrypt.org/directory'
```

Generate the account key with:

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out acme_account_ec256.key
```

### Request the Certificate

```bash
go run ./cmd/request-acme-cert -dbpath scratch.db -agekey age.key
```

This contacts the CA and stages the new certificate in the application config.

### Deploy the Certificate

**scratch.db is not the production database.** Export the staged pair from scratch, import it into the production `app.db`, then move it into `server.tls` there:

```bash
ripc get acme.certificate > cert.pem
ripc get acme.private_key > key.pem
ripc -dbpath app.db -agekey age.key set acme.certificate @cert.pem
ripc -dbpath app.db -agekey age.key set acme.private_key @key.pem
ripc -dbpath app.db -agekey age.key update tls
```

Then reload the production app so the server picks up the new `server.tls` values.

**scratch.db already is the production `app.db`.** You ran everything above against the live database, so the staged pair is already where it belongs — just move it into `server.tls` and reload:

```bash
ripc update tls
```

This moves the staged certificate into `server.tls`, where the server reads it.

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

