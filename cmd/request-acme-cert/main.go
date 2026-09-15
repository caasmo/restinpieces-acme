package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/caasmo/restinpieces"
	"github.com/caasmo/restinpieces-acme"
	"github.com/caasmo/restinpieces/config"
	"github.com/caasmo/restinpieces/db"
	"github.com/caasmo/restinpieces/db/databasesql"
	"github.com/pelletier/go-toml/v2"
)

func main() {
	logLevel := slog.LevelInfo
	if os.Getenv("LOG_LEVEL") == "debug" {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger) // Set globally for libraries that might use slog's default

	logger.Info("Starting ACME certificate renewal runner...")

	// --- Flags ---
	dbPath := flag.String("dbpath", "app.db", "path to SQLite database file")
	ageKeyPath := flag.String("agekey", "", "Path to the age identity (private key) file (required)")

	flag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "Usage: %s -dbpath <db-path> -agekey <id-path>\n\n", os.Args[0])
		_, _ = fmt.Fprintf(os.Stderr, "Runs the ACME certificate renewal process using config from the database.\n\n")
		_, _ = fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *dbPath == "" || *ageKeyPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	// --- Database Connection ---
	logger.Info("Connecting to database pool...", "path", *dbPath)
	pool, err := restinpieces.NewModerncPool(*dbPath)
	if err != nil {
		logger.Error("Failed to open database pool", "path", *dbPath, "error", err)
		os.Exit(1)
	}
	defer func() {
		logger.Info("Closing database pool...")
		closeErr := pool.Close()
		if closeErr != nil {
			logger.Error("Failed to close database pool", "error", closeErr)
		}
	}()

	// --- Secure Config Store ---
	dbImpl, err := databasesql.New(pool)
	if err != nil {
		logger.Error("failed to instantiate sqlite db from pool", "error", err)
		os.Exit(1)
	}

	secureCfgStore, err := config.NewSecureStoreAge(dbImpl, *ageKeyPath)
	if err != nil {
		logger.Error("failed to instantiate secure config (age)", "age_key_path", *ageKeyPath, "error", err)
		os.Exit(1)
	}

	// --- Load ACME Config from Secure Store ---
	logger.Info("Loading ACME configuration from database", "scope", acme.ScopeConfig)
	configTomlData, format, err := secureCfgStore.Get(acme.ScopeConfig, 0)
	if err != nil {
		logger.Error("failed to load ACME config from DB", "scope", acme.ScopeConfig, "error", err)
		os.Exit(1)
	}
	if len(configTomlData) == 0 {
		logger.Error("ACME config data loaded from DB is empty", "scope", acme.ScopeConfig)
		os.Exit(1)
	}
	if format != "toml" {
		logger.Error("ACME config data is not in TOML format", "scope", acme.ScopeConfig, "expected_format", "toml", "actual_format", format)
		os.Exit(1)
	}

	var renewalCfg acme.Config
	err = toml.Unmarshal(configTomlData, &renewalCfg)
	if err != nil {
		logger.Error("failed to unmarshal ACME TOML config", "scope", acme.ScopeConfig, "error", err)
		os.Exit(1)
	}
	logger.Info("Successfully unmarshalled ACME config", "scope", acme.ScopeConfig)

	// --- Handler Instantiation ---
	certHandler := acme.NewCertHandler(&renewalCfg, secureCfgStore, logger)

	// --- Job Execution ---
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// Create a dummy job (payload is not used by the acme handler)
	dummyJob := db.Job{ID: 1}

	logger.Info("Executing ACME Handle method...")
	err = certHandler.Handle(ctx, dummyJob)

	// --- Result ---
	if err != nil {
		logger.Error("Handler execution failed", "error", err)
		os.Exit(1)
	}

	logger.Info("Handler execution completed successfully.")
	logger.Info("Certificate should now be saved in the database via SecureConfigStore.", "db_path", *dbPath, "scope", acme.ScopeAcmeCertificate)
	logger.Info("You can check the database content using sqlite commands or a config dump command.")
}
