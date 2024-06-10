package main

import (
	"crypto/rc4"
	"fmt"
	"log"
)

// Taken from : https://github.com/firdasafridi/gocrypt/blob/main/rc4.go

// Example usage
func main() {
	shellcode := []byte("Im a shellcode")
	// Key must be 16 bytes
	key := []byte("OffensiveGolang1")

	r := NewRC4()
	enc, err := r.Encrypt(shellcode, key)
	if err != nil {
		log.Fatal("Error while encrypting rc4: ", err)
	}
	fmt.Println("Encrypted shellcode:", string(enc))
	plain, err := r.Decrypt(enc, key)
	if err != nil {
		log.Fatal("Error while decrypting rc4: ", err)
	}
	fmt.Println("Decrypted shellcode:", string(plain))
}

// RC4 is the aes option structure
type RC4 struct {
}

// NewRC4 is a function to create new configuration of aes algorithm option
// the secret must be hexa a-f & 0-9
func NewRC4() *RC4 {
	return &RC4{}
}

// Encrypt encrypts the first block in src into dst.
// Dst and src may point at the same memory.
func (rc4Opt *RC4) Encrypt(src []byte, key []byte) ([]byte, error) {
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	dst := make([]byte, len(src))
	cipher.XORKeyStream(dst, src)
	return dst, nil
}

// Decrypt decrypts the first block in src into dst.
// Dst and src may point at the same memory.
func (rc4Opt *RC4) Decrypt(src []byte, key []byte) ([]byte, error) {
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	dst := make([]byte, len(src))
	cipher.XORKeyStream(dst, src)
	return dst, nil
}
