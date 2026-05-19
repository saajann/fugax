# fugax

A zero-knowledge secret sharing service built with Go. Secrets are encrypted client-side before storage — the server never holds plaintext data or decryption keys.

## How it works

1. **Create** — the client sends a secret via `POST /secrets`. The server generates a random AES-256 key, encrypts the content, stores only the ciphertext, and returns a single `url` field containing the complete shareable link (incorporating the secret ID and decryption key) to the caller.
2. **Share** — the caller shares the returned link. Since the key is never stored on the server, only someone with the full link can read the secret.
3. **Read** — on first access the server decrypts the content on the fly, returns it, and immediately deletes the record (burn-on-read). A background worker also purges any time-expired secrets every 5 minutes.

```
POST /secrets          → { url }
GET  /secrets/{id}?key → { content }  (then deleted)
```

## Stack

| Layer    | Technology                          |
|----------|-------------------------------------|
| Language | Go 1.26                             |
| Database | PostgreSQL via Supabase             |
| Crypto   | AES-256-GCM (stdlib `crypto/aes`)   |
| Container| Docker (multi-stage build, ~15 MB)  |
| Hosting  | Render (Docker runtime)             |

## Project structure

```
fugax/
├── cmd/api/
│   └── main.go          # Entry point — server, router, background worker
├── internal/
│   ├── crypto/
│   │   └── crypto.go    # AES-256-GCM encrypt / decrypt
│   ├── db/
│   │   └── db.go        # PostgreSQL connection pool and queries
│   └── handler/
│       └── handler.go   # HTTP handlers and route registration
├── Dockerfile
└── docker-compose.yml
```

## API

### Create a secret

```bash
curl -X POST http://localhost:8080/secrets \
  -H "Content-Type: application/json" \
  -d '{
    "content": "my secret",
    "burn_on_read": true,
    "expires_in_minutes": 60
  }'
```

Response:
```json
{
  "url": "http://localhost:8080/secrets/550e8400-e29b-41d4-a716-446655440000?key=3f9a2c8b..."
}
```

### Read a secret

```bash
curl "http://localhost:8080/secrets/<id>?key=<key>"
```

Response:
```json
{
  "content": "my secret"
}
```

The record is deleted immediately after this response. A second request returns `404`.

## Running locally

**Prerequisites:** Go 1.26+, Docker, a Supabase project.

1. Clone the repo and create a `.env` file:

```env
DATABASE_URL=postgresql://postgres:[password]@[host]:6543/postgres
APP_PORT=8080
APP_BASE_URL=http://localhost:8080
```

> [!IMPORTANT]
> **Production / Render Configuration:** In production, remember to set the `APP_BASE_URL` environment variable (e.g. `https://fugax.onrender.com`) in your deployment environment (like the Render dashboard) so the system generates shareable URLs using your live domain.

2. Create the `secrets` table in Supabase SQL Editor:

```sql
CREATE TABLE secrets (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    encrypted_content TEXT NOT NULL,
    expires_at        TIMESTAMP WITH TIME ZONE,
    burn_on_read      BOOLEAN DEFAULT true,
    created_at        TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

3. Run directly with Go:

```bash
go run ./cmd/api
```

Or with Docker Compose:

```bash
docker compose up
```

## Security design

- **Zero-knowledge**: the server stores only AES-256-GCM ciphertext. The decryption key is returned once at creation time and never persisted.
- **Nonce**: a fresh random nonce is generated per encryption and prepended to the ciphertext, ensuring that two encryptions of the same plaintext produce different outputs.
- **Burn-on-read**: secrets are deleted from the database immediately after the first successful read.
- **TTL**: an optional `expires_in_minutes` field sets a hard expiry. A goroutine-based background worker purges expired records every 5 minutes.
- **No logging of plaintext**: handlers only log errors, never request content.