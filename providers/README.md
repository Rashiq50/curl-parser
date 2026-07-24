# Providers (Test Fixtures for API Sync)

This directory contains **dummy provider integrations** used to test the API Sync
scanner. Each subfolder represents a third-party API/auth provider that a customer
repo might integrate (Stripe, Auth0, OAuth2, Twilio, etc.).

Every provider folder contains:

- **`config.json`** — machine-readable metadata the scanner reads: the SDK package,
  the pinned SDK version, the API version, auth type, and the endpoints/snippets used.
- **`*.integration.js`** — a realistic code snippet showing how the provider is wired
  up. This is what a source scanner would parse for deprecated patterns.

## Ground truth (what "latest / good" looks like)

The table below is the reference the scanner should compare against. Providers marked
**OUTDATED** are intentionally stale so you can verify detection works. Providers marked
**CURRENT** should pass a scan clean.

| Provider       | Folder            | SDK version (repo) | Latest SDK | API version (repo) | Latest API   | Status   |
| -------------- | ----------------- | ------------------ | ---------- | ------------------ | ------------ | -------- |
| Stripe         | `stripe/`         | 8.222.0            | 17.5.0     | 2020-08-27         | 2025-06-30   | OUTDATED |
| Auth0          | `auth0/`          | 2.42.0             | 4.9.0      | —                  | —            | OUTDATED |
| Generic OAuth2 | `oauth2/`         | —                  | —          | implicit flow      | PKCE         | OUTDATED |
| Twilio         | `twilio/`         | 3.84.1             | 5.4.0      | 2010-04-01         | 2010-04-01   | OUTDATED |
| SendGrid       | `sendgrid/`       | 8.1.3              | 8.1.3      | v3                 | v3           | CURRENT  |
| GitHub OAuth   | `github-oauth/`   | —                  | —          | OAuth App          | OAuth App    | CURRENT  |
| AWS S3         | `aws-s3/`         | 2.1691.0 (v2)      | 3.x (v3)   | —                  | —            | OUTDATED |
| Firebase Auth  | `firebase/`       | 10.14.1            | 11.10.0    | —                  | —            | OUTDATED |

## How the scanner should use this

1. Discover provider folders (or detect providers by scanning imports in source).
2. Read `config.json` for the declared SDK/API versions.
3. Compare against a registry of "latest known good" versions/patterns.
4. Flag deprecated auth flows, EOL SDK majors, and stale API versions.

> These are fixtures only — none of the keys/secrets are real.
