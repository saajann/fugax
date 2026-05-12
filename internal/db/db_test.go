package db

import (
	"fmt"
	"testing"
	"time"
)

// mockDB is an in-memory implementation of Storage used in tests
type mockDB struct {
	secrets map[string]*Secret
}

func newMockDB() *mockDB {
	return &mockDB{secrets: make(map[string]*Secret)}
}

func (m *mockDB) SaveSecret(encryptedContent []byte, expiresAt *time.Time, burnOnRead bool) (string, error) {
	id := "test-uuid-1234"
	m.secrets[id] = &Secret{
		ID:               id,
		EncryptedContent: encryptedContent,
		ExpiresAt:        expiresAt,
		BurnOnRead:       burnOnRead,
	}
	return id, nil
}

func (m *mockDB) GetSecret(id string) (*Secret, error) {
	secret, ok := m.secrets[id]
	if !ok {
		return nil, fmt.Errorf("secret not found: %s", id)
	}
	return secret, nil
}

func (m *mockDB) DeleteSecret(id string) error {
	delete(m.secrets, id)
	return nil
}

func (m *mockDB) DeleteExpired() error {
	now := time.Now()
	for id, s := range m.secrets {
		if s.ExpiresAt != nil && now.After(*s.ExpiresAt) {
			delete(m.secrets, id)
		}
	}
	return nil
}

// --- Tests ---

func TestSaveAndGetSecret(t *testing.T) {
	store := newMockDB()

	content := []byte("encrypted-content")
	id, err := store.SaveSecret(content, nil, true)
	if err != nil {
		t.Fatalf("SaveSecret failed: %v", err)
	}

	secret, err := store.GetSecret(id)
	if err != nil {
		t.Fatalf("GetSecret failed: %v", err)
	}

	if string(secret.EncryptedContent) != string(content) {
		t.Errorf("got %q, want %q", secret.EncryptedContent, content)
	}
}

func TestGetSecretNotFound(t *testing.T) {
	store := newMockDB()

	_, err := store.GetSecret("non-existent-id")
	if err == nil {
		t.Error("expected error for missing secret, got nil")
	}
}

func TestDeleteSecret(t *testing.T) {
	store := newMockDB()

	id, _ := store.SaveSecret([]byte("content"), nil, true)
	store.DeleteSecret(id)

	_, err := store.GetSecret(id)
	if err == nil {
		t.Error("expected secret to be deleted, but it was found")
	}
}

func TestDeleteExpired(t *testing.T) {
	store := newMockDB()

	// Save a secret that expired 1 hour ago
	past := time.Now().Add(-1 * time.Hour)
	id, _ := store.SaveSecret([]byte("expired"), &past, true)

	store.DeleteExpired()

	_, err := store.GetSecret(id)
	if err == nil {
		t.Error("expected expired secret to be deleted, but it was found")
	}
}

func TestDeleteExpiredKeepsValidSecrets(t *testing.T) {
	store := newMockDB()

	// Save a secret that expires in 1 hour
	future := time.Now().Add(1 * time.Hour)
	id, _ := store.SaveSecret([]byte("still valid"), &future, true)

	store.DeleteExpired()

	_, err := store.GetSecret(id)
	if err != nil {
		t.Error("expected valid secret to survive DeleteExpired, but it was deleted")
	}
}