package main

import (
	"flag"
	"fmt"
	"log/slog" // Import slog
	"os"

	"github.com/caasmo/restinpieces"

	"github.com/caasmo/restinpieces-acme"
	"github.com/pelletier/go-toml/v2"
)

const JobTypeCertRenewal = "certificate_renewal"

// Pool creation helpers moved to restinpieces package

func main() {
	// Create a simple slog text logger that outputs to stdout
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	dbPath := flag.String("db", "", "Path to the SQLite DB (used by framework AND acme history)")
	ageKeyPath := flag.String("age-key", "", "Path to the age identity (private key) file (required)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s -db <db-path> -age-key <id-path>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Start the restinpieces application server with ACME support.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *dbPath == "" || *ageKeyPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	// --- Create Database Pool (Shared by framework and ACME history) ---
	dbPool, err := restinpieces.NewZombiezenPool(*dbPath) // Use dbPath
	if err != nil {
		logger.Error("failed to create database pool", "path", *dbPath, "error", err) // Use the new logger
		os.Exit(1) // Exit if pool creation fails
	}

	defer func() {
		logger.Info("Closing database pool...") // Use the new logger
		if err := dbPool.Close(); err != nil {
			logger.Error("Error closing database pool", "error", err) // Use the new logger
		}
	}()

	// --- Initialize restinpieces ---
	app, srv, err := restinpieces.New(
		restinpieces.WithZombiezenPool(dbPool),
		restinpieces.WithAgeKeyPath(*ageKeyPath),
		restinpieces.WithLogger(logger), // Inject the created logger
	)
	if err != nil {
		logger.Error("failed to initialize restinpieces application", "error", err) // Use the new logger
		os.Exit(1) // Pool closed by defer
	}
	// Re-assign logger to the one provided by the app, as it might have additional context or handlers.
	logger = app.Logger()

	// --- Load ACME Renewal Config from SecureConfigStore ---
	logger.Info("Loading ACME configuration from database", "scope", acme.ScopeConfig)
	encryptedTomlData, format, err := app.ConfigStore().Get(acme.ScopeConfig, 0)
	if err != nil {
		logger.Error("failed to load ACME config from DB", "scope", acme.ScopeConfig, "error", err)
		os.Exit(1)
	}
	if len(encryptedTomlData) == 0 {
		logger.Error("ACME config data loaded from DB is empty", "scope", acme.ScopeConfig)
		os.Exit(1)
	}

	// Check if the format is TOML before unmarshalling
	if format != "toml" {
		logger.Error("ACME config data is not in TOML format", "scope", acme.ScopeConfig, "expected_format", "toml", "actual_format", format)
		os.Exit(1)
	}

	var renewalCfg acme.Config // Declare variable to hold the config
	if err := toml.Unmarshal(encryptedTomlData, &renewalCfg); err != nil {
		logger.Error("failed to unmarshal ACME TOML config", "scope", acme.ScopeConfig, "error", err)
		os.Exit(1)
	}
	logger.Info("Successfully unmarshalled ACME config", "scope", acme.ScopeConfig)

	certHandler := acme.NewCertRenewalHandler(&renewalCfg, app.ConfigStore(), logger)

	err = srv.AddJobHandler(JobTypeCertRenewal, certHandler)
	if err != nil {
		logger.Error("Failed to register certificate renewal job handler", "job_type", JobTypeCertRenewal, "error", err)
		os.Exit(1)
	}
	logger.Info("Registered certificate renewal job handler", "job_type", JobTypeCertRenewal)

	srv.Run()

	logger.Info("Server shut down gracefully.")
}
