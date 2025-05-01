package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/caasmo/restinpieces"
	"github.com/caasmo/restinpieces-acme"
	"github.com/caasmo/restinpieces/config"
	dbz "github.com/caasmo/restinpieces/db/zombiezen"
	"github.com/pelletier/go-toml/v2"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	dbPathFlag := flag.String("dbpath", "", "Path to the SQLite database file (required)")
	ageIdentityPathFlag := flag.String("age-key", "", "Path to the age identity file (private key 'AGE-SECRET-KEY-1...') (required)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s -dbpath <db-file> -age-key <identity-file>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Updates the main application configuration with the latest certificate data from the secure store.\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *dbPathFlag == "" || *ageIdentityPathFlag == "" {
		flag.Usage()
		os.Exit(1)
	}

	// --- Database Setup ---
	logger.Info("Creating sqlite database pool", "path", *dbPathFlag)
	pool, err := restinpieces.NewZombiezenPool(*dbPathFlag)
	if err != nil {
		logger.Error("failed to create database pool", "db_path", *dbPathFlag, "error", err)
		os.Exit(1)
	}
	defer func() {
		logger.Info("Closing database pool")
		if err := pool.Close(); err != nil {
			logger.Error("error closing database pool", "error", err)
		}
	}()

	dbImpl, err := dbz.New(pool)
	if err != nil {
		logger.Error("failed to instantiate zombiezen db from pool", "error", err)
		os.Exit(1)
	}

	// --- Instantiate SecureConfig ---
	secureCfg, err := config.NewSecureConfigAge(dbImpl, *ageIdentityPathFlag, logger)
	if err != nil {
		logger.Error("failed to instantiate secure config (age)", "age_key_path", *ageIdentityPathFlag, "error", err)
		os.Exit(1)
	}

	// --- Load Latest Certificate Data ---
	logger.Info("Loading latest certificate data", "scope", acme.CertificateScope)
	certTomlData, err := secureCfg.Latest(acme.CertificateScope)
	if err != nil {
		logger.Error("failed to load certificate data from secure store", "scope", acme.CertificateScope, "error", err)
		os.Exit(1)
	}
	if len(certTomlData) == 0 {
		logger.Error("no certificate data found in secure store", "scope", acme.CertificateScope)
		os.Exit(1)
	}

	var certData acme.Cert
	if err := toml.Unmarshal(certTomlData, &certData); err != nil {
		logger.Error("failed to unmarshal certificate TOML data", "scope", acme.CertificateScope, "error", err)
		os.Exit(1)
	}
	logger.Info("Successfully loaded and unmarshalled certificate data", "scope", acme.CertificateScope, "identifier", certData.Identifier)

	// --- Load Latest Application Config ---
	logger.Info("Loading latest application configuration", "scope", config.ScopeApplication)
	appTomlData, err := secureCfg.Latest(config.ScopeApplication)
	if err != nil {
		logger.Error("failed to load application config from secure store", "scope", config.ScopeApplication, "error", err)
		os.Exit(1)
	}
	if len(appTomlData) == 0 {
		// This might be okay if it's the very first time, but usually an app config should exist.
		logger.Warn("no existing application configuration found in secure store", "scope", config.ScopeApplication)
		// Decide if this is an error or if we should proceed with a default/empty config
		// For now, let's treat it as an error, assuming an app config should exist to be updated.
		os.Exit(1)
	}

	var appCfg config.Config
	if err := toml.Unmarshal(appTomlData, &appCfg); err != nil {
		logger.Error("failed to unmarshal application config TOML data", "scope", config.ScopeApplication, "error", err)
		os.Exit(1)
	}
	logger.Info("Successfully loaded and unmarshalled application configuration", "scope", config.ScopeApplication)

	// --- Update Application Config with Cert Data ---
	logger.Info("Updating application config with certificate data")
	appCfg.Server.CertData = certData.CertificateChain
	appCfg.Server.KeyData = certData.PrivateKey
	// Optionally clear file paths if data is now embedded
	// appCfg.Server.CertFile = ""
	// appCfg.Server.KeyFile = ""

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
