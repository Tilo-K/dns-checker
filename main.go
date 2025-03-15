package main

import (
	"net/http"
	"os"
	"tilok.dev/dns-checker/web"
)

func main() {
	port := "8080"
	envPort, present := os.LookupEnv("PORT")
	if present {
		port = envPort
	}

	http.HandleFunc("/hx/dnsResult", web.DnsResult)
	http.Handle("/", http.FileServer(http.Dir("./static")))

	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		panic(err)
	}
}
