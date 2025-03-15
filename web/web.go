package web

import (
	"fmt"
	"net/http"
	"tilok.dev/dns-checker/dns"
)

func DnsResult(w http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		fmt.Println(err)
	}

	d := req.Form.Encode()
	fmt.Println(d)

	results, _ := dns.QueryServers("tilo.host")
	table := dns.ConvertResultToTable(results)
	_, err = w.Write([]byte(table))
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(500)
		return
	}

	w.WriteHeader(200)
}
