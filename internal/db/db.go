package db

import (
	"context"
	"encoding/hex"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DB wraps a pgx connection pool
type DB struct {
	pool *pgxpool.Pool
}

// Secret represents a row in the secrets table
type Secret struct {
	ID               string
	EncryptedContent []byte
	ExpiresAt        *time.Time
	BurnOnRead       bool
}

// Connect opens a connection pool using DATABASE_URL from the environment
func Connect() (*DB, error) {
	url := os.Getenv("DATABASE_URL")

	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		return nil, err
	}

	return &DB{pool: pool}, nil
}

// Close shuts down the connection pool
func (db *DB) Close() {
	db.pool.Close()
}

// SaveSecret stores an encrypted secret and returns the generated UUID
func (db *DB) SaveSecret(encryptedContent []byte, expiresAt *time.Time, burnOnRead bool) (string, error) {
	// Store bytes as hex string — TEXT is simpler to handle than BYTEA
	hexContent := hex.EncodeToString(encryptedContent)

	var id string
	err := db.pool.QueryRow(
		context.Background(),
		`INSERT INTO secrets (encrypted_content, expires_at, burn_on_read)
		 VALUES ($1, $2, $3)
		 RETURNING id`,
		hexContent, expiresAt, burnOnRead,
	).Scan(&id)

	if err != nil {
		return "", err
	}

	return id, nil
}

// GetSecret retrieves a secret by its UUID
func (db *DB) GetSecret(id string) (*Secret, error) {
	var hexContent string
	secret := &Secret{}

	err := db.pool.QueryRow(
		context.Background(),
		`SELECT id, encrypted_content, expires_at, burn_on_read
		 FROM secrets WHERE id = $1`,
		id,
	).Scan(&secret.ID, &hexContent, &secret.ExpiresAt, &secret.BurnOnRead)

	if err != nil {
		return nil, err
	}

	// Decode hex string back to raw bytes
	secret.EncryptedContent, err = hex.DecodeString(hexContent)
	if err != nil {
		return nil, err
	}

	return secret, nil
}

// DeleteSecret removes a secret by its UUID
func (db *DB) DeleteSecret(id string) error {
	_, err := db.pool.Exec(
		context.Background(),
		`DELETE FROM secrets WHERE id = $1`,
		id,
	)
	return err
}

// DeleteExpired removes all secrets past their expiry time (called by background worker)
func (db *DB) DeleteExpired() error {
	_, err := db.pool.Exec(
		context.Background(),
		`DELETE FROM secrets WHERE expires_at < NOW()`,
	)
	return err
}