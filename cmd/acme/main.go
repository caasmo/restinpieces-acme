package main

import (
	"context"
	"flag"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/caasmo/restinpieces"
	"github.com/caasmo/restinpieces-acme" // Import the local acme package
	"github.com/caasmo/restinpieces/config"
	dbz "github.com/caasmo/restinpieces/db/zombiezen" // Import zombiezen db implementation
	rip_db "github.com/caasmo/restinpieces/db"        // Import db interface package
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
	dbPath := flag.String("dbfile", "app.db", "path to SQLite database file")
	ageKeyPath := flag.String("age-key", "", "Path to the age identity (private key) file (required)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s -dbfile <db-path> -age-key <id-path>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Runs the ACME certificate renewal process using config from the database.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *dbPath == "" || *ageKeyPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	// --- Database Connection ---
	logger.Info("Connecting to database pool...", "path", *dbPath)
	pool, err := restinpieces.NewZombiezenPool(*dbPath)
	if err != nil {
		logger.Error("Failed to open database pool", "path", *dbPath, "error", err)
		os.Exit(1)
	}
	defer func() {
		logger.Info("Closing database pool...")
		if err := pool.Close(); err != nil {
			logger.Error("Failed to close database pool", "error", err)
		}
	}()

	// --- Secure Config Store ---
	dbImpl, err := dbz.New(pool) // Create zombiezen db implementation from pool
	if err != nil {
		logger.Error("failed to instantiate zombiezen db from pool", "error", err)
		os.Exit(1)
	}
	secureCfgStore, err := config.NewSecureConfigAge(dbImpl, *ageKeyPath, logger)
	if err != nil {
		logger.Error("failed to instantiate secure config (age)", "age_key_path", *ageKeyPath, "error", err)
		os.Exit(1)
	}

	// --- Load ACME Config from Secure Store ---
	logger.Info("Loading ACME configuration from database", "scope", acme.ConfigScope)
	encryptedTomlData, err := secureCfgStore.Latest(acme.ConfigScope)
	if err != nil {
		logger.Error("failed to load ACME config from DB", "scope", acme.ConfigScope, "error", err)
		os.Exit(1)
	}
	if len(encryptedTomlData) == 0 {
		logger.Error("ACME config data loaded from DB is empty", "scope", acme.ConfigScope)
		os.Exit(1)
	}

	var renewalCfg acme.Config
	if err := toml.Unmarshal(encryptedTomlData, &renewalCfg); err != nil {
		logger.Error("failed to unmarshal ACME TOML config", "scope", acme.ConfigScope, "error", err)
		os.Exit(1)
	}
	logger.Info("Successfully unmarshalled ACME config", "scope", acme.ConfigScope)

	// --- Handler Instantiation ---
	renewalHandler := acme.NewCertRenewalHandler(&renewalCfg, secureCfgStore, logger)

	// --- Job Execution ---
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// Create a dummy job (payload is not used by the acme handler)
	dummyJob := rip_db.Job{ID: 1}

	logger.Info("Executing ACME Handle method...")
	err = renewalHandler.Handle(ctx, dummyJob)

	// --- Result ---
	if err != nil {
		logger.Error("Handler execution failed", "error", err)
		os.Exit(1)
	}

	logger.Info("Handler execution completed successfully.")
	logger.Info("Certificate should now be saved in the database via SecureConfigStore.", "db_file", *dbPath, "scope", acme.CertificateOutputScope)
	logger.Info("You can check the database content using sqlite tools or a config dump command.")
}
