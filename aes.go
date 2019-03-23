package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/pkg/errors"
)

const (
	KeySize   = 32
	NonceSize = 12
)

// GenerateKey generates a new AES key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateNonce generates a new AES.
func GenerateNonce(size int) (nonce []byte, err error) {

	nonce = make([]byte, size)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return
	}
	return nonce, nil
}

// Encrypt secures a msg using AES-GCM.
func Encrypt(key, msg []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce, err := GenerateNonce(gcm.NonceSize())
	if err != nil {
		return nil, errors.Wrap(err, "encrypt Generatenonce failed")
	}

	out := gcm.Seal(nonce, nonce, msg, nil)
	return out, nil
}

// Decrypt recovers a msg secured using AES.
func Decrypt(key, msg []byte) ([]byte, error) {
	if len(msg) <= NonceSize {
		return nil, errors.New("decrypt failed, msg less than nonce size")
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, errors.Wrap(err, "decrypt NewGCM failed")
	}

	nonce := make([]byte, NonceSize)
	copy(nonce, msg)

	out, err := gcm.Open(nil, nonce, msg[NonceSize:], nil)
	if err != nil {
		return nil, errors.Wrap(err, "decrypt Open failed")
	}
	return out, nil
}
