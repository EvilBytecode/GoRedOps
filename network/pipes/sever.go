package main

/*
Modified from https://stackoverflow.com/questions/71196548/receive-message-with-windows-named-pipe-in-golang-and-winio
*/

import (
	"fmt"
	"github.com/Microsoft/go-winio"
	"io"
	"log"
	"net"
)

func handleClient(c net.Conn) {
	defer c.Close()
	fmt.Println("Client connected", c.RemoteAddr().Network())

	buf := make([]byte, 512)
	for {
		n, err := c.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Fatal("Error while reading: ", err)
			}
			break
		}
		str := string(buf[:n])
		fmt.Printf("read %d bytes: %q\n", n, str)
	}
	fmt.Println("Client disconnected")
}

func main() {
	pipePath := `\\.\pipe\mypipename`

	l, err := winio.ListenPipe(pipePath, nil)
	if err != nil {
		log.Fatal("Error while listening: ", err)
	}
	defer l.Close()
	fmt.Println("Server listening on pipe", pipePath)

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal("Error while accept: ", err)
		}
		go handleClient(conn)
	}
}
