package crypto

import (
"bytes"
"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
key := bytes.Repeat([]byte{1}, 32)
plaintext := []byte("round trip plaintext")

ciphertext, err := Encrypt(plaintext, key)
if err != nil {
t.Fatalf("Encrypt() error = %v", err)
}

decrypted, err := Decrypt(ciphertext, key)
if err != nil {
t.Fatalf("Decrypt() error = %v", err)
}

if !bytes.Equal(decrypted, plaintext) {
t.Fatalf("decrypted plaintext = %q, want %q", decrypted, plaintext)
}
}

func TestEncryptProducesDifferentCiphertextsForSamePlaintext(t *testing.T) {
key := bytes.Repeat([]byte{2}, 32)
plaintext := []byte("same plaintext")

ciphertext1, err := Encrypt(plaintext, key)
if err != nil {
t.Fatalf("first Encrypt() error = %v", err)
}

ciphertext2, err := Encrypt(plaintext, key)
if err != nil {
t.Fatalf("second Encrypt() error = %v", err)
}

if bytes.Equal(ciphertext1, ciphertext2) {
t.Fatal("ciphertexts should differ for same plaintext due to unique nonce")
}
}

func TestDecryptFailsWithWrongKey(t *testing.T) {
correctKey := bytes.Repeat([]byte{3}, 32)
wrongKey := bytes.Repeat([]byte{4}, 32)
plaintext := []byte("sensitive value")

ciphertext, err := Encrypt(plaintext, correctKey)
if err != nil {
t.Fatalf("Encrypt() error = %v", err)
}

_, err = Decrypt(ciphertext, wrongKey)
if err == nil {
t.Fatal("Decrypt() with wrong key error = nil, want non-nil")
}
}

func TestDecryptFailsWithShortCiphertext(t *testing.T) {
key := bytes.Repeat([]byte{5}, 32)
shortCiphertext := []byte{1, 2, 3}

_, err := Decrypt(shortCiphertext, key)
if err == nil {
t.Fatal("Decrypt() with short ciphertext error = nil, want non-nil")
}

if err.Error() != "ciphertext too short" {
t.Fatalf("Decrypt() error = %q, want %q", err.Error(), "ciphertext too short")
}
}
