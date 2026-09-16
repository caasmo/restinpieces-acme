# acme_cert.go Handle: a broken dns-01 config stays hidden while the certificate is fresh

The request decision runs right after the ACME client is built and returns early
when the staged certificate is still good, so `dns01Entry` and `getDNSProvider`
never run on a skipping job. An unsupported provider name or a missing
`api_token` passes config validation and is only reported when a renewal is
finally due. Move the decision after the dns-01 entry/provider setup so every
run checks the provider.

- `acme_cert.go` — `Handle` (decision placement), `dns01Entry`, `getDNSProvider`
- `restinpieces/config/config_validate.go` — `ValidateAcme` checks only the active-entry count and non-empty credentials
- `restinpieces/config/acme.go` — `AcmeDNS01Entry` comment: the framework does not know the credential field names
