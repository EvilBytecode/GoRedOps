package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// TODO: avoid Go-Http-client user agent

func main() {
	host := "http://127.0.0.1:8080/ping"
	request, err := getRequest(host)
	if err != nil {
		log.Fatal("Error connecting to the server: ", err)
	}
	fmt.Println("Response:", string(request))
}

func getRequest(url string) ([]byte, error) {
	var body []byte
	c := http.Client{Timeout: time.Duration(3) * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return body, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return body, err
	}
	return body, nil
}
