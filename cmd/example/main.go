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

const JobTypeCertRenewal = "certificate_renewal"

// Pool creation helpers moved to restinpieces package

func main() {
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
		slog.Error("failed to create database pool", "path", *dbPath, "error", err)
		os.Exit(1) // Exit if pool creation fails
	}

	defer func() {
		slog.Info("Closing database pool...")
		if err := dbPool.Close(); err != nil {
			slog.Error("Error closing database pool", "error", err)
		}
	}()

	// --- Initialize restinpieces ---
	app, srv, err := restinpieces.New(
		restinpieces.WithDbZombiezen(dbPool),     // Provide the pool
		restinpieces.WithAgeKeyPath(*ageKeyPath), // Provide age key path
		restinpieces.WithRouterServeMux(),
		restinpieces.WithCacheRistretto(),
		restinpieces.WithTextLogger(nil), // Use default text logger
	)
	if err != nil {
		slog.Error("failed to initialize restinpieces application", "error", err)
		os.Exit(1) // Pool closed by defer
	}
	logger := app.Logger() // Get logger from framework

	// --- Load ACME Renewal Config from SecureConfigStore ---
	logger.Info("Loading ACME configuration from database", "scope", acme.ConfigScope)
	encryptedTomlData, err := app.SecureConfigStore().Latest(acme.ConfigScope)
	if err != nil {
		logger.Error("failed to load ACME config from DB", "scope", acme.ConfigScope, "error", err)
		os.Exit(1)
	}
	if len(encryptedTomlData) == 0 {
		logger.Error("ACME config data loaded from DB is empty", "scope", acme.ConfigScope)
		os.Exit(1)
	}

	var renewalCfg acme.Config // Declare variable to hold the config
	if err := toml.Unmarshal(encryptedTomlData, &renewalCfg); err != nil {
		logger.Error("failed to unmarshal ACME TOML config", "scope", acme.ConfigScope, "error", err)
		os.Exit(1)
	}
	logger.Info("Successfully unmarshalled ACME config", "scope", acme.ConfigScope)

	certHandler := acme.NewCertRenewalHandler(&renewalCfg, app.SecureConfigStore(), logger)

	err = srv.AddJobHandler(JobTypeCertRenewal, certHandler)
	if err != nil {
		logger.Error("Failed to register certificate renewal job handler", "job_type", JobTypeCertRenewal, "error", err)
		os.Exit(1)
	}
	logger.Info("Registered certificate renewal job handler", "job_type", JobTypeCertRenewal)

	srv.Run()

	slog.Info("Server shut down gracefully.")
}
