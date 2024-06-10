package main

import (
	"fmt"
	"log"
	"net"
)

func main() {
	listener, err := net.Listen("tcp", "127.0.0.1:1338")
	if err != nil {
		log.Fatal("Error while listening: ", err)
	}
	fmt.Println("[*] Server is running on port 1337")
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal("Error while accepting connection: ", err)
		}

		fmt.Println("[*] Accepted a new TCP connection.")
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	bytes := make([]byte, 1024)
	for {
		n, err := conn.Read(bytes)
		if err != nil {
			log.Println("Error while reading:", err)
			return
		}

		fmt.Println("Received:", string(bytes[:n]))
	}
}
