package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/caasmo/restinpieces"
	"github.com/caasmo/restinpieces/config"
	"github.com/caasmo/restinpieces/db/databasesql"
	"github.com/pelletier/go-toml"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	dbPathFlag := flag.String("dbpath", "", "Path to the SQLite database file (required)")
	ageIdentityPathFlag := flag.String("agekey", "", "Path to the age identity file (private key 'AGE-SECRET-KEY-1...') (required)")

	flag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "Usage: %s -dbpath <db-file> -agekey <identity-file>\n", os.Args[0])
		_, _ = fmt.Fprintf(os.Stderr, "Moves the staged certificate from the acme section into the server TLS settings.\n")
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

	// --- Load the Application Config ---
	logger.Info("Loading application configuration", "scope", config.ScopeApplication)
	appTomlData, appFormat, err := secureCfg.Get(config.ScopeApplication, 0)
	if err != nil {
		logger.Error("failed to load application config from secure store", "scope", config.ScopeApplication, "error", err)
		os.Exit(1)
	}
	if len(appTomlData) == 0 {
		logger.Error("no application configuration found in secure store", "scope", config.ScopeApplication)
		os.Exit(1)
	}
	if appFormat != "toml" {
		logger.Error("application config is not in TOML format", "scope", config.ScopeApplication, "expected_format", "toml", "actual_format", appFormat)
		os.Exit(1)
	}

	tree, err := toml.LoadBytes(appTomlData)
	if err != nil {
		logger.Error("failed to parse application config TOML data", "scope", config.ScopeApplication, "error", err)
		os.Exit(1)
	}

	acmeTree, ok := tree.Get("acme").(*toml.Tree)
	if !ok {
		logger.Error("no acme section found in application config", "scope", config.ScopeApplication)
		os.Exit(1)
	}

	var acmeCfg config.Acme
	err = acmeTree.Unmarshal(&acmeCfg)
	if err != nil {
		logger.Error("failed to read the acme section from application config", "scope", config.ScopeApplication, "error", err)
		os.Exit(1)
	}
	logger.Info("Successfully loaded application configuration", "scope", config.ScopeApplication)

	// --- Move the Staged Certificate into the Server TLS Settings ---
	if acmeCfg.Certificate == "" || acmeCfg.PrivateKey == "" {
		logger.Error("no staged certificate found in the acme section", "scope", config.ScopeApplication)
		os.Exit(1)
	}

	logger.Info("Moving the staged certificate into the server TLS settings", "domains", acmeCfg.Domains)
	tree.Set("server.tls.certificate", acmeCfg.Certificate)
	tree.Set("server.tls.private_key", acmeCfg.PrivateKey)

	// --- Marshal and Save the Updated Application Config ---
	updatedAppTomlBytes, err := toml.Marshal(tree)
	if err != nil {
		logger.Error("failed to marshal updated application config to TOML", "error", err)
		os.Exit(1)
	}

	// --- Save Updated Application Config ---
	description := fmt.Sprintf("Deployed staged certificate for domains: %v", acmeCfg.Domains)
	logger.Info("Saving updated application configuration", "scope", config.ScopeApplication)
	err = secureCfg.Save(config.ScopeApplication, updatedAppTomlBytes, appFormat, description)
	if err != nil {
		logger.Error("failed to save updated application config via SecureConfig", "scope", config.ScopeApplication, "error", err)
		os.Exit(1)
	}

	logger.Info("Successfully moved the staged certificate into the server TLS settings.")
}
