package main

import (
	"fmt"
)

// Example usage
func main() {
	// Calc
	shellcode := []byte("Im a shellcode")
	// Xor shellcode with key
	key := []byte("key")
	enc := Xor(shellcode, key)
	fmt.Println("Encrypted shellcode:", string(enc))
	out := Xor(shellcode, key)
	fmt.Println("Decrypted shellcode:", string(out))
}

func Xor(data []byte, key []byte) []byte {
	for i := 0; i < len(data); i++ {
		data[i] ^= key[i%len(key)]
	}
	return data
}
