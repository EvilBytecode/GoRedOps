package main

import (
	"fmt"
	"github.com/Microsoft/go-winio"
	"log"
)

func main() {
	pipePath := `\\.\pipe\mypipename`

	f, err := winio.DialPipe(pipePath, nil)
	if err != nil {
		log.Fatal("Error while reading pipe: ", err)
	}
	defer f.Close()
	n, err := f.Write([]byte("Hello World!"))
	if err != nil {
		log.Fatal("Error while writing: ", err)
	}
	fmt.Println("wrote:", n)
}
