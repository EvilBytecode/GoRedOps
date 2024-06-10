package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"log"
)

// Taken from : https://github.com/HZzz2/go-shellcode-loader/blob/main/go-sc.go

// Example usage
func main() {
	shellcode := []byte("Im a shellcode")
	// Key must be 16 bytes
	key := []byte("OffensiveGolang1")

	a := NewAes()
	src, err := a.Encrypt(shellcode, key)
	if err != nil {
		log.Fatal("Error while encrypting AES : ", err)
	}
	fmt.Println("Encrypted shellcode: ", string(src))

	out, err := a.Decrypt(src, key)
	if err != nil {
		log.Fatal("Error while encrypting AES : ", err)
	}
	fmt.Println("Decrypted shellcode: ", string(out))
}

type Aes struct{}

func NewAes() *Aes {
	return &Aes{}
}

// pad payload with to reach block size (PKCS#7 padding)
func (a *Aes) pad(str []byte, blockSize int) []byte {
	paddingCount := blockSize - len(str)%blockSize
	paddingStr := bytes.Repeat([]byte{byte(paddingCount)}, paddingCount)
	newPaddingStr := append(str, paddingStr...)
	return newPaddingStr
}

// Encrypt with AES-CBC
func (a *Aes) Encrypt(src, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	src = a.pad(src, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key)
	blockMode.CryptBlocks(src, src)
	return src, nil

}

// Unpad payload
func (a *Aes) unPad(str []byte) []byte {
	n := len(str)
	count := int(str[n-1])
	newPaddingText := str[:n-count]
	return newPaddingText
}

// Decrypt with AES-CBC
func (a *Aes) Decrypt(src, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key)
	blockMode.CryptBlocks(src, src)
	src = a.unPad(src)
	return src, nil
}
