package main

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
	"log"
)

//https://github.com/alinz/crypto.go/blob/main/chacha20.go

func main() {
	shellcode := []byte("Im a shellcode")
	// Key must be 32 bytes
	key := []byte("OffensiveGolang1OffensiveGolang1")

	chacha := NewChaCha20()
	src, err := chacha.Encrypt(shellcode, key)
	if err != nil {
		log.Fatal("Error while encrypting chacha20 : ", err)
	}
	fmt.Println("Encrypted shellcode: ", string(src))

	out, err := chacha.Decrypt(src, key)
	if err != nil {
		log.Fatal("Error while decrypting chacha20 : ", err)
	}
	fmt.Println("Decrypted shellcode: ", string(out))
}

type ChaCha20 struct{}

func NewChaCha20() *ChaCha20 {
	return &ChaCha20{}
}

func (c *ChaCha20) prepareKey(key []byte) (cipher.AEAD, int, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, 0, err
	}
	return aead, aead.NonceSize(), nil
}

// Encrypt encrypts data using given key
func (c *ChaCha20) Encrypt(data []byte, key []byte) ([]byte, error) {
	aead, nonceSize, err := c.prepareKey(key)
	if err != nil {
		return nil, err
	}

	// Select a random nonce, and leave capacity for the ciphertext.
	nonce := make([]byte, nonceSize, nonceSize+len(data)+aead.Overhead())

	// Encrypt the message and append the ciphertext to the nonce.
	return aead.Seal(nonce, nonce, data, nil), nil
}

// DecryptChaCha decrypts data using given key
func (c *ChaCha20) Decrypt(data []byte, key []byte) ([]byte, error) {
	aead, nonceSize, err := c.prepareKey(key)
	if err != nil {
		return nil, err
	}

	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	// Split nonce and ciphertext.
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// Decrypt the message and check it wasn't tampered with.
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		if err.Error() == "chacha20poly1305: message authentication failed" {
			return nil, errors.New("wrong key")
		}
		return nil, err
	}
	return plaintext, nil
}
