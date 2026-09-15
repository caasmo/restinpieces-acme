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
)

func main() {
	logLevel := slog.LevelInfo
	if os.Getenv("LOG_LEVEL") == "debug" {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger) // Set globally for libraries that might use slog's default

	logger.Info("Starting ACME certificate request runner...")

	// --- Flags ---
	dbPath := flag.String("dbpath", "app.db", "path to SQLite database file")
	ageKeyPath := flag.String("agekey", "", "Path to the age identity (private key) file (required)")

	flag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "Usage: %s -dbpath <db-path> -agekey <id-path>\n\n", os.Args[0])
		_, _ = fmt.Fprintf(os.Stderr, "Obtains a certificate using the acme section of the application configuration.\n\n")
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

	// --- Handler Instantiation ---
	certHandler := acme.NewCertHandler(secureCfgStore, logger)

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
	logger.Info("Certificate staged in the application config.", "db_path", *dbPath, "scope", config.ScopeApplication)
	logger.Info("Run the deploy command to move it into the server TLS settings.")
}
