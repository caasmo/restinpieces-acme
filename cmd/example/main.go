package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/caasmo/restinpieces"
	// rip_queue "github.com/caasmo/restinpieces/queue" // Removed unused import

	"github.com/caasmo/restinpieces-acme"
	acme_db "github.com/caasmo/restinpieces-acme/zombiezen"
	"github.com/pelletier/go-toml/v2" // Import TOML library
)

// Define job type constant for clarity
const JobTypeCertRenewal = "certificate_renewal"

// Pool creation helpers moved to restinpieces package

func main() {
	// --- Setup Logging ---
	// Configure slog globally (optional, but good practice)
	logLevel := slog.LevelInfo
	if os.Getenv("LOG_LEVEL") == "debug" {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger) // Set globally

	// --- Flags ---
	// --- Framework Flags ---
	dbPath := flag.String("db", "", "Path to the SQLite DB (used by framework AND acme history)")
	ageKeyPath := flag.String("age-key", "", "Path to the age identity (private key) file (required)")
	acmeConfigPath := flag.String("acme-config", "", "Path to the ACME configuration TOML file (required)")

	// Set custom usage message for the application
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s -db <db-path> -age-key <id-path> -acme-config <acme-cfg-path>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Start the restinpieces application server with ACME support.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	// Parse flags
	flag.Parse()

	// Validate required flags
	if *dbPath == "" || *ageKeyPath == "" || *acmeConfigPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	// --- Load ACME Renewal Config from File ---
	slog.Info("Loading ACME renewal configuration", "path", *acmeConfigPath)
	acmeCfgBytes, err := os.ReadFile(*acmeConfigPath)
	if err != nil {
		slog.Error("Failed to read ACME configuration file", "path", *acmeConfigPath, "error", err)
		os.Exit(1)
	}

	var renewalCfg acme.Config
	err = toml.Unmarshal(acmeCfgBytes, &renewalCfg)
	if err != nil {
		slog.Error("Failed to parse ACME configuration TOML", "path", *acmeConfigPath, "error", err)
		os.Exit(1)
	}

	slog.Info("ACME renewal configuration loaded successfully")
	// Note: Add logic here to replace placeholders in renewalCfg (e.g., API tokens, keys)
	// with values from environment variables or a secret management system.
	// Example:
	// if token := os.Getenv("CLOUDFLARE_API_TOKEN"); token != "" {
	//     if provider, ok := renewalCfg.DNSProviders["cloudflare"]; ok {
	//         provider.APIToken = token
	//         renewalCfg.DNSProviders["cloudflare"] = provider // Update map value
	//     }
	// }
	// if key := os.Getenv("ACME_ACCOUNT_PRIVATE_KEY"); key != "" {
	//     renewalCfg.AcmeAccountPrivateKey = key
	// }
	// Re-validate after potential modifications if necessary.

	// --- Create Database Pool (Shared by framework and ACME history) ---
	// Use the helper from the library to create a pool with suitable defaults.
	dbPool, err := restinpieces.NewZombiezenPool(*dbPath) // Use dbPath
	if err != nil {
		slog.Error("failed to create database pool", "path", *dbPath, "error", err)
		os.Exit(1) // Exit if pool creation fails
	}
	// Defer closing the pool here, as main owns it now.
	defer func() {
		slog.Info("Closing database pool...")
		if err := dbPool.Close(); err != nil {
			slog.Error("Error closing database pool", "error", err)
		}
	}()

	// --- Initialize restinpieces Framework ---
	// Pass ageKeyPath as the first argument
	app, srv, err := restinpieces.New(
		*ageKeyPath,                          // Framework needs this for its own config
		restinpieces.WithDbZombiezen(dbPool), // Provide the pool to the framework
		restinpieces.WithRouterServeMux(),
		restinpieces.WithCacheRistretto(),
		restinpieces.WithTextLogger(nil), // Use default text logger
	)
	if err != nil {
		slog.Error("failed to initialize restinpieces application", "error", err)
		// Pool will be closed by the deferred function
		os.Exit(1) // Exit if app initialization fails
	}

	// --- Setup ACME Dependencies ---
	// Create the DbWriter implementation instance using the shared pool
	certDbWriter := acme_db.NewWriter(dbPool)
	frameworkLogger := app.Logger() // Get logger from framework for consistency

	// --- Instantiate and Register ACME Handler ---
	certHandler := acme.NewCertRenewalHandler(renewalCfg, certDbWriter, frameworkLogger)

	// Register the handler with the framework's server instance
	err = srv.AddJobHandler(JobTypeCertRenewal, certHandler)
	if err != nil {
		frameworkLogger.Error("Failed to register certificate renewal job handler", "job_type", JobTypeCertRenewal, "error", err)
		os.Exit(1)
	}
	frameworkLogger.Info("Registered certificate renewal job handler", "job_type", JobTypeCertRenewal)

	// Reminder: This setup registers the handler, but doesn't automatically
	// schedule the JobTypeCertRenewal job. That needs a separate mechanism:
	// - A manual trigger (API call, CLI command to enqueue the job)
	// - A dedicated scheduler daemon added via srv.AddDaemon()
	// - Integration with an external scheduler.

	// PreRouter initialization is handled internally within restinpieces.New

	// --- Start Server ---
	// The Run method blocks until the server stops (e.g., via signal).
	// It manages the lifecycle of registered daemons (like the scheduler).
	srv.Run()

	slog.Info("Server shut down gracefully.")
	// No explicit os.Exit(0) needed, successful completion implies exit 0
}
