package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/caasmo/restinpieces"

	"github.com/caasmo/restinpieces-acme"
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

	certHandler := acme.NewCertHandler(app.ConfigStore(), logger)

	err = srv.AddJobHandler(JobTypeAcmeCert, certHandler)
	if err != nil {
		logger.Error("Failed to register certificate job handler", "job_type", JobTypeAcmeCert, "error", err)
		os.Exit(1)
	}
	logger.Info("Registered certificate job handler", "job_type", JobTypeAcmeCert)

	srv.Run()

	logger.Info("Server shut down gracefully.")
}
