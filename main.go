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

	http.Handle("/", http.FileServer(http.Dir("./static")))

	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		panic(err)
	}
}
