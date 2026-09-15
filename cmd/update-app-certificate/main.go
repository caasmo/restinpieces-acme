package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/caasmo/restinpieces"
	"github.com/caasmo/restinpieces-acme"
	"github.com/caasmo/restinpieces/config"
	"github.com/caasmo/restinpieces/db/databasesql"
	"github.com/pelletier/go-toml/v2"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	dbPathFlag := flag.String("dbpath", "", "Path to the SQLite database file (required)")
	ageIdentityPathFlag := flag.String("agekey", "", "Path to the age identity file (private key 'AGE-SECRET-KEY-1...') (required)")

	flag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "Usage: %s -dbpath <db-file> -agekey <identity-file>\n", os.Args[0])
		_, _ = fmt.Fprintf(os.Stderr, "Updates the main application configuration with the latest certificate data from the secure store.\n")
		_, _ = fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *dbPathFlag == "" || *ageIdentityPathFlag == "" {
		flag.Usage()
		os.Exit(1)
	}

	// --- Database Setup ---
	logger.Info("Creating sqlite database pool", "path", *dbPathFlag)
	pool, err := restinpieces.NewModerncPool(*dbPathFlag)
	if err != nil {
		logger.Error("failed to create database pool", "db_path", *dbPathFlag, "error", err)
		os.Exit(1)
	}
	defer func() {
		logger.Info("Closing database pool")
		closeErr := pool.Close()
		if closeErr != nil {
			logger.Error("error closing database pool", "error", closeErr)
		}
	}()

	dbImpl, err := databasesql.New(pool)
	if err != nil {
		logger.Error("failed to instantiate sqlite db from pool", "error", err)
		os.Exit(1)
	}

	// --- Instantiate SecureConfig ---
	secureCfg, err := config.NewSecureStoreAge(dbImpl, *ageIdentityPathFlag)
	if err != nil {
		logger.Error("failed to instantiate secure config (age)", "age_key_path", *ageIdentityPathFlag, "error", err)
		os.Exit(1)
	}

	// --- Load Latest Certificate Data ---
	logger.Info("Loading latest certificate data", "scope", acme.ScopeAcmeCertificate)
	certTomlData, certFormat, err := secureCfg.Get(acme.ScopeAcmeCertificate, 0)
	if err != nil {
		logger.Error("failed to load certificate data from secure store", "scope", acme.ScopeAcmeCertificate, "error", err)
		os.Exit(1)
	}
	if len(certTomlData) == 0 {
		logger.Error("no certificate data found in secure store", "scope", acme.ScopeAcmeCertificate)
		os.Exit(1)
	}
	if certFormat != "toml" {
		logger.Error("certificate data is not in TOML format", "scope", acme.ScopeAcmeCertificate, "expected_format", "toml", "actual_format", certFormat)
		os.Exit(1)
	}

	var certData acme.Cert
	err = toml.Unmarshal(certTomlData, &certData)
	if err != nil {
		logger.Error("failed to unmarshal certificate TOML data", "scope", acme.ScopeAcmeCertificate, "error", err)
		os.Exit(1)
	}
	logger.Info("Successfully loaded and unmarshalled certificate data",
		"scope", acme.ScopeAcmeCertificate,
		"identifier", certData.Identifier,
		"domains", certData.Domains,
		"issued_at", certData.IssuedAt,
		"expires_at", certData.ExpiresAt,
	)

	// --- Load Latest Application Config ---
	logger.Info("Loading latest application configuration", "scope", config.ScopeApplication)
	appTomlData, appFormat, err := secureCfg.Get(config.ScopeApplication, 0)
	if err != nil {
		logger.Error("failed to load application config from secure store", "scope", config.ScopeApplication, "error", err)
		os.Exit(1)
	}
	if len(appTomlData) == 0 {
		logger.Warn("no existing application configuration found in secure store", "scope", config.ScopeApplication)
		os.Exit(1)
	}
	if appFormat != "toml" {
		logger.Error("application config is not in TOML format", "scope", config.ScopeApplication, "expected_format", "toml", "actual_format", appFormat)
		os.Exit(1)
	}

	var appCfg config.Config
	err = toml.Unmarshal(appTomlData, &appCfg)
	if err != nil {
		logger.Error("failed to unmarshal application config TOML data", "scope", config.ScopeApplication, "error", err)
		os.Exit(1)
	}
	logger.Info("Successfully loaded and unmarshalled application configuration", "scope", config.ScopeApplication)

	// --- Update Application Config with Cert Data ---
	logger.Info("Updating application config with certificate data")
	appCfg.Server.CertData = certData.CertificateChain
	appCfg.Server.KeyData = certData.PrivateKey

	// --- Marshal Updated Application Config ---
	updatedAppTomlBytes, err := toml.Marshal(appCfg)
	if err != nil {
		logger.Error("failed to marshal updated application config to TOML", "error", err)
		os.Exit(1)
	}

	// --- Save Updated Application Config ---
	description := fmt.Sprintf("Updated TLS cert/key data from certificate store (identifier: %s)", certData.Identifier)
	logger.Info("Saving updated application configuration", "scope", config.ScopeApplication)
	err = secureCfg.Save(config.ScopeApplication, updatedAppTomlBytes, "toml", description)
	if err != nil {
		logger.Error("failed to save updated application config via SecureConfig", "scope", config.ScopeApplication, "error", err)
		os.Exit(1)
	}

	logger.Info("Successfully updated application configuration with latest certificate data.")
}
