package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/pelletier/go-toml/v2"

	"github.com/caasmo/restinpieces-acme" // Import your acme package
)

// generateBlueprintConfig creates an acme.Config struct populated with example/dummy data.
func generateBlueprintConfig() acme.Config {
	// Define example DNS providers
	dnsProviders := map[string]acme.DNSProvider{
		"cloudflare": {
			APIToken: "YOUR_CLOUDFLARE_API_TOKEN_ENV_VAR_OR_SECRET", // Placeholder: Load securely
		},
		// Add other provider examples if needed
		// "route53": {
		//  AccessKeyID: "YOUR_AWS_ACCESS_KEY_ID_ENV_VAR",
		//  SecretAccessKey: "YOUR_AWS_SECRET_ACCESS_KEY_ENV_VAR",
		//  Region: "us-east-1",
		// },
	}

	// Create the main config struct with example values
	cfg := acme.Config{
		Email:        "your-acme-account@example.com",                     // Placeholder: Your ACME account email
		Domains:      []string{"example.com", "www.example.com"},          // Placeholder: Domains for the certificate
		DNSProviders: dnsProviders,                                        // Example DNS providers map
		CADirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory", // Staging URL (use production URL carefully)
		// CADirectoryURL: "https://acme-v02.api.letsencrypt.org/directory", // Production URL
		AcmeAccountPrivateKey: `-----BEGIN EC PRIVATE KEY-----\nPASTE_YOUR_ACME_ACCOUNT_PRIVATE_KEY_PEM_HERE\n-----END EC PRIVATE KEY-----`, // Placeholder: Load securely
	}

	return cfg
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	outputFileFlag := flag.String("output", "acme.blueprint.toml", "Output file path for the blueprint TOML configuration")
	flag.StringVar(outputFileFlag, "o", "acme.blueprint.toml", "Output file path (shorthand)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Generates a blueprint ACME TOML configuration file with example values.\n")
		fmt.Fprintf(os.Stderr, "Remember to replace placeholder values and load secrets securely.\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	logger.Info("Generating ACME blueprint configuration...")
	blueprintCfg := generateBlueprintConfig()

	// Validate the generated blueprint config (optional but good practice)
	if err := blueprintCfg.Validate(); err != nil {
		// Log validation errors for the blueprint itself
		logger.Warn("Generated blueprint configuration has validation issues (this is expected for placeholders)", "error", err)
	}

	logger.Info("Marshalling configuration to TOML...")
	tomlBytes, err := toml.Marshal(blueprintCfg)
	if err != nil {
		logger.Error("Failed to marshal blueprint config to TOML", "error", err)
		os.Exit(1)
	}

	logger.Info("Writing blueprint configuration", "path", *outputFileFlag)
	err = os.WriteFile(*outputFileFlag, tomlBytes, 0644)
	if err != nil {
		logger.Error("Failed to write blueprint config file",
			"path", *outputFileFlag,
			"error", err)
		os.Exit(1)
	}

	logger.Info("ACME blueprint configuration generated successfully", "path", *outputFileFlag)
	logger.Warn("IMPORTANT: Review the generated file, replace placeholders, and ensure secrets (API tokens, private keys) are loaded securely (e.g., via environment variables or a secret manager) in your actual application configuration.")
}
