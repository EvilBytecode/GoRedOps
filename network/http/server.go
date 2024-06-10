package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"log"
)

func main() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	// Ping handler
	r.GET("/ping", handler)
	address := "127.0.0.1:8080"
	fmt.Println("Listening on", address)
	err := r.Run(address)
	if err != nil {
		log.Fatal("Error while starting the web server: ", err)
	}
}

func handler(c *gin.Context) {
	c.String(200, "pong")
}
