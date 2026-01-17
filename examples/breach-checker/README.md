# Privacy-first breach checker (demo)

This example adds a privacy-first email breach checker with a minimal PHP backend, strict security headers, and a lightweight UI.

## Features

- Email-only lookup with a clean responsive UI.
- `POST /api/check` with validation, rate limiting, CSRF, and safe responses.
- Minimal logging (salted hashes only), no email storage.
- Optional notification flow with one-time verification link; stores hashed email + preferences.
- Privacy and security pages.

## Setup

1. From the repo root, start the PHP dev server:

```bash
php -S 0.0.0.0:8000 -t examples/breach-checker/public examples/breach-checker/public/router.php
```

2. Open `http://localhost:8000` in your browser.

### Environment variables

| Variable | Purpose | Default |
| --- | --- | --- |
| `LOG_HASH_SALT` | Salt/pepper for hashing emails in logs and notifications. | `local-dev-pepper` |
| `CORS_ALLOWED_ORIGINS` | Comma-separated list of allowed origins. | Same-origin only |

## API

### `POST /api/check`

Payload:

```json
{ "email": "you@example.com" }
```

Response:

```json
{ "found": false, "breaches": [], "message": "..." }
```

### `POST /api/notify/request`

Payload:

```json
{ "email": "you@example.com" }
```

Response:

```json
{ "message": "Verification link sent if the email exists." }
```

### `GET /notify/verify?token=...`

Verifies the one-time link and enables notifications.

## Notes

- Demo data only: `demo@example.com` will return matches using the default salt.
- No emails are stored or logged in plaintext.
- If you wire up a third-party breach API, keep its API key on the server and forward only safe responses.

## Minimal test plan

1. Submit a valid email and confirm a success message.
2. Submit an invalid email and confirm a validation error.
3. Click “Send verification link” and confirm a generic success message.
4. Open `/privacy` and `/security` pages.
