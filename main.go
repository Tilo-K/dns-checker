package main

import (
	"net/http"
	"os"
)

func main() {
	port := "8080"
	envPort, present := os.LookupEnv("PORT")
	if present {
		port = envPort
	}

	http.ListenAndServe(":"+port, nil)
}
