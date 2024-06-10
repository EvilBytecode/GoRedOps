package main

import (
	"fmt"
	"log"
	"net"
)

func main() {
	conn, err := net.Dial("tcp", "127.0.0.1:1338")
	if err != nil {
		log.Fatal("Error while connecting to server: ", err)
	}
	_, err = conn.Write([]byte("Hello World!"))
	if err != nil {
		log.Fatal("Error while writing to target: ", err)
	}
	fmt.Println("[*] Message sent to the server")
	defer conn.Close()
}
