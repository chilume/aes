package aes

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testMessage = "Hello"
)

func TestEncrypt(t *testing.T) {
	key, err := GenerateKey()
	assert.Equal(t, err, nil)
	sec, err := Encrypt(key, []byte(testMessage))
	assert.Equal(t, err, nil)
	val, err := Decrypt(key, sec)
	assert.Equal(t, err, nil)
	assert.Equal(t, testMessage, string(val))
}
