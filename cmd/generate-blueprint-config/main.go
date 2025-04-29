package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/pelletier/go-toml/v2"

	"github.com/caasmo/restinpieces-acme"
)

func generateBlueprintConfig() acme.Config {
	dnsProviders := map[string]acme.DNSProvider{
		acme.DNSProviderCloudflare: {
			APIToken: "YOUR_CLOUDFLARE_API_TOKEN_ENV_VAR_OR_SECRET",
		},
	}

	cfg := acme.Config{
		Email:                 "your-acme-account@example.com",
		Domains:               []string{"example.com", "www.example.com"},
		DNSProviders:          dnsProviders,
		CADirectoryURL:        "https://acme-staging-v02.api.letsencrypt.org/directory",
		AcmeAccountPrivateKey: `-----BEGIN EC PRIVATE KEY-----\nPASTE_YOUR_ACME_ACCOUNT_PRIVATE_KEY_PEM_HERE\n-----END EC PRIVATE KEY-----`,
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
