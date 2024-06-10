# GolangObfuscator
- GO / Golang Obfuscator  / AST Obfuscation
- rewritten version of gomambojambo

### AST-based obfuscation. The idea is to give it a package path, and it will obfuscate it.

- Randomization of function names, and function calls
- For loops converted to goto with tags
- Strings obfuscated/encrypted using AES
- Adding some deadcode to functions

### How to invoke it?
```go
go run GoFuscator.go -srcpath HEREPUTTHEFILEPATHTOOBFUSCATE -writechanges -calls -loops -strings -stringsKey "0101010101010101010101010101010101010101010101010101010101010101" -stringNonce "010101010101010101010101" -verbose -deadcode
```

### Showcase:
- given code to be obfuscated:

```go
package main

import f"fmt"
func main() {
f.Println("HELLO WORLD!!!")
f.Scanln()
}
```

- will be obfuscated to:
```go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	f "fmt"
)

func Cccsanurtswmkdkmwehqrryyrefqaeoo(s string) string {
	key, _ := hex.DecodeString("0101010101010101010101010101010101010101010101010101010101010101")
	ciphertext, _ := hex.DecodeString(s)
	nonce, _ := hex.DecodeString("010101010101010101010101")
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return string(plaintext)
}

func main() {
	(func() {
		zXXX := int64(1)
		sXXX :=
			float64(10)
		{
			goto LOOP_INIT_rqeqqu
		LOOP_INIT_rqeqqu:
			;
			iXXX := 8
			goto LOOP_COND_vtkqrp
		LOOP_COND_vtkqrp:
			if iXXX < 15 {
				goto LOOP_BODY_gmhcpa
			} else {
				goto LOOP_END_jgbues
			}
		LOOP_BODY_gmhcpa:
			{
				{
					goto LOOP_INIT_aubjmu
				LOOP_INIT_aubjmu:
					;
					jXXX := iXXX
					goto LOOP_COND_euhtju
				LOOP_COND_euhtju:
					if jXXX < 15 {
						goto LOOP_BODY_ojpzle
					} else {
						goto LOOP_END_trkleq
					}
				LOOP_BODY_ojpzle:
					{
						{
							goto LOOP_INIT_uaiajl
						LOOP_INIT_uaiajl:
							;
							zXXX := jXXX
							goto LOOP_COND_xynqml
						LOOP_COND_xynqml:
							if zXXX < 15 {
								goto LOOP_BODY_fyntxm
							} else {
								goto LOOP_END_ddxtia
							}
						LOOP_BODY_fyntxm:
							{
								sXXX = (float64(iXXX+jXXX) * float64(zXXX)) / float64(iXXX)
								zXXX++
								goto LOOP_COND_xynqml
							}
						LOOP_END_ddxtia:
							{
							}
						}
						jXXX++
						goto LOOP_COND_euhtju
					}
				LOOP_END_trkleq:
					{
					}
				}
				iXXX++
				goto LOOP_COND_vtkqrp
			}
		LOOP_END_jgbues:
			{
			}
		}
		if sXXX == float64(zXXX) {
		}
	})()

	f.Println(Cccsanurtswmkdkmwehqrryyrefqaeoo("fa3cf6d626d752bcb8e94bbc8fc7947be9599ce7ab093a220ffd9c58d4"))
	f.Scanln()
}
```