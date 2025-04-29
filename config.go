package acme // Or root package of your module

import (
	"errors"
	"fmt"
	"log/slog"
)

type DNSProvider struct {
	APIToken string
}

type Config struct {
	Email                 string
	Domains               []string
	DNSProviders          map[string]DNSProvider
	CADirectoryURL        string
	AcmeAccountPrivateKey string
}
