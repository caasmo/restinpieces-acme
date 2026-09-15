package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/caasmo/restinpieces"

	"github.com/caasmo/restinpieces-acme"
	"github.com/pelletier/go-toml/v2"
)

const JobTypeAcmeCert = "job_type_acme_cert"

func main() {
	// Create a simple slog text logger that outputs to stdout
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	dbPath := flag.String("dbpath", "", "Path to the SQLite database file (required)")
	ageKeyPath := flag.String("agekey", "", "Path to the age identity (private key) file (required)")

	flag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "Usage: %s -dbpath <db-path> -agekey <id-path>\n\n", os.Args[0])
		_, _ = fmt.Fprintf(os.Stderr, "Start the restinpieces application server with ACME support.\n\n")
		_, _ = fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *dbPath == "" || *ageKeyPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	// --- Create Database Pool (Shared by framework and ACME history) ---
	dbPool, err := restinpieces.NewModerncPool(*dbPath)
	if err != nil {
		logger.Error("failed to create database pool", "path", *dbPath, "error", err)
		os.Exit(1)
	}

	defer func() {
		logger.Info("Closing database pool...")
		closeErr := dbPool.Close()
		if closeErr != nil {
			logger.Error("Error closing database pool", "error", closeErr)
		}
	}()

	// --- Initialize restinpieces ---
	app, srv, err := restinpieces.New(
		restinpieces.WithModerncPool(dbPool),
		restinpieces.WithAgeKeyPath(*ageKeyPath),
		restinpieces.WithLogger(logger), // Inject the created logger
	)
	if err != nil {
		logger.Error("failed to initialize restinpieces application", "error", err)
		os.Exit(1) // Pool closed by defer
	}
	// Re-assign logger to the one provided by the app, as it might have additional context or handlers.
	logger = app.Logger()

	// --- Load ACME Renewal Config from SecureConfigStore ---
	logger.Info("Loading ACME configuration from database", "scope", acme.ScopeConfig)
	configTomlData, format, err := app.ConfigStore().Get(acme.ScopeConfig, 0)
	if err != nil {
		logger.Error("failed to load ACME config from DB", "scope", acme.ScopeConfig, "error", err)
		os.Exit(1)
	}
	if len(configTomlData) == 0 {
		logger.Error("ACME config data loaded from DB is empty", "scope", acme.ScopeConfig)
		os.Exit(1)
	}

	// Check if the format is TOML before unmarshalling
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

	certHandler := acme.NewCertHandler(&renewalCfg, app.ConfigStore(), logger)

	err = srv.AddJobHandler(JobTypeAcmeCert, certHandler)
	if err != nil {
		logger.Error("Failed to register certificate job handler", "job_type", JobTypeAcmeCert, "error", err)
		os.Exit(1)
	}
	logger.Info("Registered certificate job handler", "job_type", JobTypeAcmeCert)

	srv.Run()

	logger.Info("Server shut down gracefully.")
}
