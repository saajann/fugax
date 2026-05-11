package handler

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/saajann/fugax/internal/crypto"
	"github.com/saajann/fugax/internal/db"
)

type Handler struct {
	db *db.DB
}

func New(db *db.DB) *Handler {
	return &Handler{db: db}
}

// RegisterRoutes attaches all routes to the given mux
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /secrets", h.CreateSecret)
	mux.HandleFunc("GET /secrets/{id}", h.ReadSecret)
}

// --- Request / Response types ---

type createSecretRequest struct {
	Content    string `json:"content"`
	BurnOnRead bool   `json:"burn_on_read"`
	ExpiresIn  int    `json:"expires_in_minutes"` // 0 = no expiry
}

type createSecretResponse struct {
	ID  string `json:"id"`
	Key string `json:"key"` // hex-encoded decryption key
}

type readSecretResponse struct {
	Content string `json:"content"`
}

// --- Handlers ---

// CreateSecret encrypts and stores a new secret
func (h *Handler) CreateSecret(w http.ResponseWriter, r *http.Request) {
	var req createSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Content == "" {
		http.Error(w, "content cannot be empty", http.StatusBadRequest)
		return
	}

	// Generate key and encrypt
	key, err := crypto.GenerateKey()
	if err != nil {
		http.Error(w, "failed to generate key", http.StatusInternalServerError)
		return
	}

	encrypted, err := crypto.Encrypt([]byte(req.Content), key)
	if err != nil {
		http.Error(w, "failed to encrypt secret", http.StatusInternalServerError)
		return
	}

	// Optional expiry
	var expiresAt *time.Time
	if req.ExpiresIn > 0 {
		t := time.Now().Add(time.Duration(req.ExpiresIn) * time.Minute)
		expiresAt = &t
	}

	id, err := h.db.SaveSecret(encrypted, expiresAt, req.BurnOnRead)
	if err != nil {
		http.Error(w, "failed to save secret", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, createSecretResponse{
		ID:  id,
		Key: hex.EncodeToString(key),
	})
}

// ReadSecret decrypts and returns a secret, then deletes it if burn_on_read
func (h *Handler) ReadSecret(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	keyHex := r.URL.Query().Get("key")

	if id == "" || keyHex == "" {
		http.Error(w, "missing id or key", http.StatusBadRequest)
		return
	}

	// Decode the key from hex
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		http.Error(w, "invalid key format", http.StatusBadRequest)
		return
	}

	secret, err := h.db.GetSecret(id)
	if err != nil {
		http.Error(w, "secret not found", http.StatusNotFound)
		return
	}

	// Check expiry
	if secret.ExpiresAt != nil && time.Now().After(*secret.ExpiresAt) {
		h.db.DeleteSecret(id)
		http.Error(w, "secret has expired", http.StatusGone)
		return
	}

	plaintext, err := crypto.Decrypt(secret.EncryptedContent, key)
	if err != nil {
		http.Error(w, "failed to decrypt secret", http.StatusUnprocessableEntity)
		return
	}

	// Burn after reading
	if secret.BurnOnRead {
		h.db.DeleteSecret(id)
	}

	writeJSON(w, http.StatusOK, readSecretResponse{
		Content: string(plaintext),
	})
}

// --- Helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}