// Package acme obtains TLS certificates with Let's Encrypt and stages them in
// the application's encrypted configuration store.
//
// A TLS certificate proves to a browser that it is talking to the real
// example.com. Let's Encrypt issues such certificates for free, but only after
// you prove that you control the domain. That proof happens over ACME
// (Automatic Certificate Management Environment), the protocol this package
// speaks.
//
// The proof used here is the dns-01 challenge. The package asks the DNS
// provider that hosts the domain to publish a temporary TXT record, Let's
// Encrypt reads that record from the public DNS, and only then issues the
// certificate. dns-01 is the only challenge type that can issue a wildcard
// certificate such as "*.example.com".
//
// The package decides when to renew with ACME Renewal Information (ARI,
// RFC 9773): it asks the CA for the certificate's suggested renewal window
// and requests a new certificate only when the CA asks for it or when the
// remaining lifetime falls to acme.remaining_lifetime_fraction. A job that
// runs on a short interval therefore stays idle until the certificate is
// due.
//
// The settings live in the Acme section of the application configuration. The
// obtained certificate is staged back into the same section as Certificate and
// PrivateKey, ready for the deploy step that moves them into the server's TLS
// settings.
package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"strings"
	"time"

	"github.com/caasmo/restinpieces/config"
	"github.com/caasmo/restinpieces/db"
	"github.com/pelletier/go-toml"

	legoacme "github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/lego"
	legolog "github.com/go-acme/lego/v5/log"
	"github.com/go-acme/lego/v5/registration"

	"golang.org/x/net/idna"
)

// CertHandler obtains a certificate when the job queue runs an acme_cert job.
type CertHandler struct {
	secureConfigStore config.SecureStore
	logger            *slog.Logger
}

// NewCertHandler builds a handler from the encrypted store that holds the
// application configuration, and a logger. The handler reads the configuration
// from the store at each request and stages the obtained certificate back into
// it. It also points lego's own logger at the handler's logger, so lego's step
// logs (dns-01 progress, order validation) share the same format and level as
// the handler's lines.
func NewCertHandler(store config.SecureStore, logger *slog.Logger) *CertHandler {
	if store == nil || logger == nil {
		panic("NewCertHandler: received nil store or logger")
	}
	handlerLogger := logger.With("job_handler", "acme_cert")
	legolog.SetDefault(handlerLogger)

	return &CertHandler{
		secureConfigStore: store,
		logger:            handlerLogger,
	}
}

// AcmeUser carries the ACME account details that lego needs: the contact
// email, the account private key, and the account registration once it is
// known. It implements lego's registration.User interface.
type AcmeUser struct {
	Email        string
	Registration *legoacme.ExtendedAccount
	PrivateKey   crypto.Signer
}

// GetEmail returns the account's contact email.
func (u *AcmeUser) GetEmail() string { return u.Email }

// GetRegistration returns the account registration, if the account has been
// registered.
func (u *AcmeUser) GetRegistration() *legoacme.ExtendedAccount { return u.Registration }

// GetPrivateKey returns the account's private key. lego uses it to sign the
// requests it sends to the ACME server.
func (u *AcmeUser) GetPrivateKey() crypto.Signer { return u.PrivateKey }

// Handle obtains a certificate and stages it in the Acme section of the
// application configuration. It reads the Acme section from the encrypted
// store at the start, so it always sees the latest saved values. The job
// queue calls it for each acme_cert job; the job value itself is not used.
//
// Handle first decides whether a new certificate is needed (see
// decideRequest) and returns without a request when the staged one
// is still fresh, so a job running on a short interval does not ask the CA
// over and over.
//
// The steps follow the ACME order of operations: load the Acme section, parse
// the account key and build a client for the configured ACME server, decide
// whether to renew, select the dns-01 entry and register its solver, register
// the account (idempotent, so an existing account is looked up rather than
// created), obtain the certificate, and stage it.
func (h *CertHandler) Handle(ctx context.Context, job db.Job) error {
	acmeCfg, err := h.loadAcmeConfig()
	if err != nil {
		return err
	}

	// --- ACME client ---
	// The account key is the account's identity, a private key in PEM form.
	// Parse it into a crypto.Signer that lego can use.
	acmePrivateKey, err := certcrypto.ParsePEMPrivateKey([]byte(acmeCfg.Account.Key))
	if err != nil {
		h.logger.Error("Failed to parse ACME account private key from config", "error", err)
		return fmt.Errorf("failed to parse ACME account private key: %w", err)
	}

	acmeUser := AcmeUser{Email: acmeCfg.Account.Email, PrivateKey: acmePrivateKey}
	legoConfig := lego.NewConfig(&acmeUser)
	legoConfig.CADirURL = acmeCfg.CADirectoryURL

	legoClient, err := lego.NewClient(legoConfig)
	if err != nil {
		h.logger.Error("Failed to create ACME client", "error", err)
		return fmt.Errorf("failed to create ACME client: %w", err)
	}

	// --- Request decision ---
	// Ask the CA for the certificate's renewal information, then apply our
	// own remaining lifetime fraction.
	decision := h.decideRequest(ctx, legoClient, acmeCfg)
	if !decision.shouldRequest {
		return nil
	}

	h.logger.Info("Attempting certificate request", "domains", acmeCfg.Domains)

	// --- DNS provider ---
	entryLabel, entry, err := dns01Entry(acmeCfg.DNS01)
	if err != nil {
		h.logger.Error(err.Error())
		return err
	}
	h.logger.Debug("Using dns-01 entry", "entry", entryLabel, "provider", entry.Provider)

	dnsProvider, err := getDNSProvider(entryLabel, entry, h.logger)
	if err != nil {
		return err
	}

	// lego looks up the challenge record through a shared DNS client. Set how
	// long one lookup may take, then register the DNS-01 solver. The client is
	// rebuilt on every run on purpose: the timeout belongs to the shared client,
	// not to the solver.
	dns01.SetDefaultClient(dns01.NewClient(&dns01.Options{Timeout: dnsQueryTimeout}))

	// Require the challenge record only on the domain's authoritative servers.
	// lego's default also requires it on the local recursive resolvers, but they
	// cache the NXDOMAIN from lego's zone lookup, which runs before the record
	// exists, for the zone's negative TTL (30 minutes on Cloudflare). The cached
	// answer outlives the propagation window, so that check can never pass.
	// Let's Encrypt validates against the authoritative servers, so that is the
	// check that matters.
	err = legoClient.Challenge.SetDNS01Provider(dnsProvider, dns01.DisableRecursiveNSsPropagationRequirement())
	if err != nil {
		h.logger.Error("Failed to set DNS01 provider", "provider", entry.Provider, "error", err)
		return fmt.Errorf("failed to set DNS01 provider: %w", err)
	}

	// --- Account registration ---
	// Register is idempotent: a new key creates an account, an existing key
	// returns the existing account. TermsOfServiceAgreed must be true.
	reg, err := legoClient.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		h.logger.Error("ACME account registration/retrieval failed", "email", acmeUser.Email, "error", err)
		return fmt.Errorf("ACME registration/retrieval failed for %s: %w", acmeUser.Email, err)
	}
	acmeUser.Registration = reg
	h.logger.Info("ACME account registered/retrieved successfully", "email", acmeUser.Email, "account_location", reg.Location)

	// --- Obtain the certificate ---
	// Bundle asks for the full chain (the certificate plus its intermediate).
	// KeyType asks for an ECDSA P-256 key pair for the certificate.
	request := certificate.ObtainRequest{
		Domains:        acmeCfg.Domains,
		Bundle:         true,
		KeyType:        certcrypto.EC256,
		Profile:        acmeCfg.Profile,
		ReplacesCertID: decision.replacesCertID,
	}

	// This is the blocking call that runs the ACME flow: order, DNS-01
	// challenge, validation, and download.
	resource, err := legoClient.Certificate.Obtain(ctx, request)
	if err != nil {
		h.logger.Error("Failed to obtain certificate", "domains", request.Domains, "error", err)
		return fmt.Errorf("failed to obtain certificate for domains %v: %w", request.Domains, err)
	}
	h.logger.Info("Successfully obtained certificate", "domains", request.Domains, "certificate_url", resource.CertURL)

	err = h.saveCertificate(resource)
	if err != nil {
		return err
	}

	h.logger.Info("Successfully processed certificate request.", "domains", request.Domains)
	return nil
}

// requestDecision is what the handler must do with the staged certificate:
// request a new one, and the ARI certificate identifier the request should
// replace.
type requestDecision struct {
	shouldRequest  bool
	replacesCertID string
}

// decideRequest decides whether the handler must request a new certificate,
// and carries the identifier the order should replace when the CA answered ARI.
//
// The staged pair is validated first: nothing staged yet, a PEM that does not
// parse, a private key that does not parse or does not match the certificate,
// and a certificate that covers different domains than configured all mean a
// new certificate is requested. Waiting cannot repair any of those states.
//
// When the staged pair is usable, the decision combines two sources:
//
//   - ACME Renewal Information (ARI, RFC 9773), the CA's own answer. The CA
//     uses it to spread renewals over time and to ask for an immediate
//     renewal, for example before a mass revocation.
//
//   - The remaining lifetime fraction from acme.remaining_lifetime_fraction,
//     our own rule, enforced on every check. It renews when the remaining
//     lifetime drops to that share of the certificate's total lifetime; the
//     default of 0.25 renews with a quarter of the lifetime left.
//
// The handler renews when either source says so, and skips only when both
// agree the certificate is still fresh.
func (h *CertHandler) decideRequest(ctx context.Context, client *lego.Client, acmeCfg config.Acme) requestDecision {
	if acmeCfg.Certificate == "" {
		h.logger.Info("Nothing is staged yet. Requesting certificate")
		return requestDecision{shouldRequest: true}
	}

	leaf, err := stagedCertificate(acmeCfg.Certificate)
	if err != nil {
		h.logger.Info("The staged certificate is not usable. Requesting certificate", "reason", err)
		return requestDecision{shouldRequest: true}
	}

	if acmeCfg.PrivateKey == "" {
		h.logger.Info("The staged private key is missing. Requesting certificate")
		return requestDecision{shouldRequest: true}
	}

	privateKey, err := certcrypto.ParsePEMPrivateKey([]byte(acmeCfg.PrivateKey))
	if err != nil {
		h.logger.Info("The staged private key is not usable. Requesting certificate", "reason", err)
		return requestDecision{shouldRequest: true}
	}

	keyMatches, err := privateKeyMatchesCertificate(leaf, privateKey)
	if err != nil {
		h.logger.Info("The staged pair cannot be compared. Requesting certificate", "reason", err)
		return requestDecision{shouldRequest: true}
	}

	if !keyMatches {
		h.logger.Info("The staged private key does not match the staged certificate. Requesting certificate")
		return requestDecision{shouldRequest: true}
	}

	domainsMatch, err := coversDomains(leaf, acmeCfg.Domains)
	if err != nil {
		h.logger.Info("The configured domains cannot be compared. Requesting certificate", "reason", err)
		return requestDecision{shouldRequest: true}
	}

	if !domainsMatch {
		h.logger.Info("The staged certificate covers different domains. Requesting certificate",
			"staged", leaf.DNSNames, "configured", acmeCfg.Domains)
		return requestDecision{shouldRequest: true}
	}

	now := time.Now()
	if !now.Before(leaf.NotAfter) {
		h.logger.Info("The staged certificate has expired. Requesting certificate", "expired_at", leaf.NotAfter)
		return requestDecision{shouldRequest: true}
	}

	// RFC 9773 forbids querying renewal information for an expired
	// certificate, and the expired case returned above, so the query is safe
	// here.
	renewalTime := h.ariRenewalTime(ctx, client, leaf)
	if !renewalTime.IsZero() {
		h.logger.Info("The CA asks to renew now. Requesting certificate",
			"renewal_time", renewalTime)
		return requestDecision{shouldRequest: true, replacesCertID: h.ariCertID(leaf)}
	}

	if remainingFractionReached(leaf, acmeCfg.RemainingLifetimeFraction, now) {
		h.logger.Info("The remaining lifetime reached acme.remaining_lifetime_fraction. Requesting certificate",
			"fraction", acmeCfg.RemainingLifetimeFraction, "expires_at", leaf.NotAfter)
		// Only the CA's ARI answer proves it knows this certificate.
		return requestDecision{shouldRequest: true}
	}

	h.logger.Info("The staged certificate is still fresh. Skipping the request",
		"expires_at", leaf.NotAfter, "fraction", acmeCfg.RemainingLifetimeFraction)
	return requestDecision{shouldRequest: false}
}

// ariRenewalTime asks the CA for the staged certificate's renewal
// information (ACME Renewal Information, RFC 9773) and returns the time to
// renew at, or the zero time when there is no renewal time to act on.
//
// The CA's Retry-After is not tracked: the handler keeps no state between
// runs, so the job's recurrence is the checking interval. Schedule the
// acme_cert job about hourly.
//
// The RFC 9773 recommended algorithm is implemented faithfully. Random time
// inside the window, past time returns now, future time returned only if
// within willingToSleep, otherwise nil.
//
// lego implements the algorithm in RenewalInfo.ShouldRenewAt. The handler
// never sleeps inside a run, so it asks with a zero willingness to sleep: a
// non-zero result always means "renew now".
//
// A zero result covers three cases: the suggested window is still in the
// future, the CA does not support ARI, or the query failed.
func (h *CertHandler) ariRenewalTime(ctx context.Context, client *lego.Client, leaf *x509.Certificate) time.Time {
	renewalInfo, err := client.Certificate.GetRenewalInfo(ctx, leaf)
	if err != nil {
		if errors.Is(err, api.ErrNoARI) {
			h.logger.Info("The CA does not support ACME Renewal Information")
		} else {
			h.logger.Warn("ACME Renewal Information query failed", "error", err)
		}
		return time.Time{}
	}

	if renewalInfo.ExplanationURL != "" {
		h.logger.Info("The CA explained its renewal window", "explanation_url", renewalInfo.ExplanationURL)
	}

	renewalTime := renewalInfo.ShouldRenewAt(time.Now(), 0)
	if renewalTime == nil {
		return time.Time{}
	}

	return *renewalTime
}

// ariCertID builds the certificate identifier that a renewal order sends in
// its replaces field (RFC 9773 section 5). lego sends the field only when the
// CA advertises ARI support in its directory. An empty identifier means the
// order is sent without replaces.
func (h *CertHandler) ariCertID(leaf *x509.Certificate) string {
	certID, err := api.MakeARICertID(leaf)
	if err != nil {
		h.logger.Warn("Failed to build the ARI certificate identifier", "error", err)
		return ""
	}

	return certID
}

// remainingFractionReached reports whether the certificate's remaining
// lifetime has dropped to the share of its total lifetime given by fraction.
// The lifetime comes from the certificate itself (NotAfter minus NotBefore),
// so the check follows the CA when it changes lifetimes. With the default
// fraction of 0.25 it renews when a quarter of the lifetime remains.
func remainingFractionReached(leaf *x509.Certificate, fraction float64, now time.Time) bool {
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	remaining := leaf.NotAfter.Sub(now)

	return remaining <= time.Duration(float64(lifetime)*fraction)
}

// stagedCertificate parses the leaf certificate from the PEM chain staged in
// acme.certificate.
func stagedCertificate(certificatePEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certificatePEM))
	if block == nil {
		return nil, fmt.Errorf("staged certificate is not a PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse staged certificate: %w", err)
	}

	return cert, nil
}

// privateKeyMatchesCertificate reports whether privateKey is the key pair of
// the certificate. It compares the public keys in their DER form, the only
// comparison that is reliable across key types.
func privateKeyMatchesCertificate(leaf *x509.Certificate, privateKey crypto.Signer) (bool, error) {
	certPublicKey, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return false, fmt.Errorf("failed to marshal certificate public key: %w", err)
	}

	keyPublicKey, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return false, fmt.Errorf("failed to marshal private key public part: %w", err)
	}

	return bytes.Equal(certPublicKey, keyPublicKey), nil
}

// coversDomains reports whether the certificate covers exactly the configured
// domains, ignoring order, letter case and repeats. A difference means the
// certificate no longer matches the configuration and must be replaced.
func coversDomains(leaf *x509.Certificate, domains []string) (bool, error) {
	covered, err := nameSet(leaf.DNSNames)
	if err != nil {
		return false, err
	}

	for _, ip := range leaf.IPAddresses {
		covered[ip.String()] = true
	}

	configured, err := nameSet(domains)
	if err != nil {
		return false, err
	}

	return maps.Equal(covered, configured), nil
}

// nameSet returns the names as a set of lower-case A-labels, so a Unicode name
// and its punycode form compare equal. An entry that parses as an IP address is
// stored in its canonical form, so an IPv6 address compares equal however it is
// written.
func nameSet(names []string) (map[string]bool, error) {
	set := make(map[string]bool, len(names))
	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			set[ip.String()] = true
			continue
		}

		ascii, err := idna.ToASCII(name)
		if err != nil {
			return nil, fmt.Errorf("failed to convert %q to an A-label: %w", name, err)
		}

		set[strings.ToLower(ascii)] = true
	}

	return set, nil
}

// loadAcmeConfig reads the Acme section of the application configuration from
// the encrypted store. The rest of the document belongs to the framework, so
// only the Acme section is parsed.
func (h *CertHandler) loadAcmeConfig() (config.Acme, error) {
	tomlData, format, err := h.secureConfigStore.Get(config.ScopeApplication, 0)
	if err != nil {
		h.logger.Error("Failed to load application config from secure store", "scope", config.ScopeApplication, "error", err)
		return config.Acme{}, fmt.Errorf("failed to load application config: %w", err)
	}
	if len(tomlData) == 0 {
		err := fmt.Errorf("application config loaded from secure store is empty")
		h.logger.Error(err.Error(), "scope", config.ScopeApplication)
		return config.Acme{}, err
	}
	if format != "toml" {
		err := fmt.Errorf("application config is not in TOML format, got %q", format)
		h.logger.Error(err.Error(), "scope", config.ScopeApplication)
		return config.Acme{}, err
	}

	var document struct {
		Acme config.Acme `toml:"acme"`
	}
	document.Acme = config.NewAcmeDefaults()

	err = toml.Unmarshal(tomlData, &document)
	if err != nil {
		h.logger.Error("Failed to unmarshal Acme section from application config", "scope", config.ScopeApplication, "error", err)
		return config.Acme{}, fmt.Errorf("failed to unmarshal Acme section: %w", err)
	}

	return document.Acme, nil
}

// saveCertificate stages the obtained certificate chain and its private key in
// the Acme section of the application configuration, so the deploy step can
// move them into the server's TLS settings. Like 'ripc set', it reads the
// stored document and sets only the two acme keys, so every other key and
// comment in the configuration is left as it is.
func (h *CertHandler) saveCertificate(resource *certificate.Resource) error {
	// The chain starts with the certificate itself. Decode it to read when it
	// expires for the stored version's description.
	block, _ := pem.Decode(resource.Certificate)
	if block == nil {
		err := fmt.Errorf("failed to decode PEM block from obtained certificate chain")
		h.logger.Error(err.Error(), "domain", resource.ID)
		return err
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		err = fmt.Errorf("failed to parse obtained leaf certificate: %w", err)
		h.logger.Error(err.Error(), "domain", resource.ID)
		return err
	}

	// Read the document fresh so edits made while the request was running are
	// not overwritten.
	tomlData, format, err := h.secureConfigStore.Get(config.ScopeApplication, 0)
	if err != nil {
		h.logger.Error("Failed to load application config from secure store", "scope", config.ScopeApplication, "error", err)
		return fmt.Errorf("failed to load application config: %w", err)
	}

	tree, err := toml.LoadBytes(tomlData)
	if err != nil {
		h.logger.Error("Failed to parse application config TOML", "scope", config.ScopeApplication, "error", err)
		return fmt.Errorf("failed to parse application config TOML: %w", err)
	}

	tree.Set("acme.certificate", string(resource.Certificate))
	tree.Set("acme.private_key", string(resource.PrivateKey))

	tomlBytes, err := toml.Marshal(tree)
	if err != nil {
		h.logger.Error("Failed to marshal application config to TOML", "error", err)
		return fmt.Errorf("failed to marshal application config to TOML: %w", err)
	}

	expiryStr := cert.NotAfter.UTC().Format(time.RFC3339)
	description := fmt.Sprintf("Staged certificate for domains: %s (expires %s)", strings.Join(resource.Domains, ", "), expiryStr)

	h.logger.Info("Staging obtained certificate", "scope", config.ScopeApplication, "format", "toml", "identifier", resource.ID)
	err = h.secureConfigStore.Save(config.ScopeApplication, tomlBytes, format, description)
	if err != nil {
		h.logger.Error("Failed to save application config via SecureConfigStore", "scope", config.ScopeApplication, "error", err)
		return err
	}

	h.logger.Info("Successfully staged certificate", "scope", config.ScopeApplication, "identifier", resource.ID)
	return nil
}
