package shroud

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

var (
	ErrInvalidKey    = errors.New("invalid encryption key")
	ErrInvalidSecret = errors.New("invalid secret format")
	ErrEmptyValue    = errors.New("value cannot be empty")
)

// Client handles encryption and decryption of secrets
type Client struct {
	encryptionKey []byte
}

// Secret represents an encrypted secret value
type Secret struct {
	encrypted string
	client    *Client
}

// NewSecretClient creates a new secret client with the given encryption key
func NewSecretClient(encryptionKey []byte) (*Client, error) {
	if len(encryptionKey) != 32 {
		return nil, ErrInvalidKey
	}

	return &Client{
		encryptionKey: encryptionKey,
	}, nil
}

// Shroud encrypts a value of any type and returns a new Secret
func (c *Client) Shroud(value any) (*Secret, error) {
	// Convert value to JSON bytes
	jsonData, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal value: %w", err)
	}

	if len(jsonData) == 0 {
		return nil, ErrEmptyValue
	}

	// Create cipher
	block, err := aes.NewCipher(c.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Create nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the value
	ciphertext := gcm.Seal(nonce, nonce, jsonData, nil)
	encrypted := base64.StdEncoding.EncodeToString(ciphertext)

	return &Secret{
		encrypted: encrypted,
		client:    c,
	}, nil
}

// CreateFromEncrypted creates a Secret from an already encrypted value
func (c *Client) CreateFromEncrypted(encrypted string) (*Secret, error) {
	if encrypted == "" {
		return nil, ErrEmptyValue
	}

	// Validate the encrypted format
	_, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, ErrInvalidSecret
	}

	return &Secret{
		encrypted: encrypted,
		client:    c,
	}, nil
}

// Expose decrypts and returns the original value into the provided destination
func (s *Secret) Expose(dest any) error {
	// Decode the base64 encrypted value
	ciphertext, err := base64.StdEncoding.DecodeString(s.encrypted)
	if err != nil {
		return ErrInvalidSecret
	}

	// Create cipher
	block, err := aes.NewCipher(s.client.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Extract nonce and ciphertext
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return ErrInvalidSecret
	}

	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	// Decrypt the value
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return ErrInvalidSecret
	}

	// Unmarshal the JSON data into the destination
	if err := json.Unmarshal(plaintext, dest); err != nil {
		return fmt.Errorf("failed to unmarshal value: %w", err)
	}

	return nil
}

// EncryptedValue returns the encrypted value for storage
func (s *Secret) EncryptedValue() string {
	return s.encrypted
}
