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

	data := req.Form.Get("domain")
	results, errors := dns.QueryServers(data)

	if len(results) == 0 {
		w.WriteHeader(200)
		for _, erro := range errors {
			_, _ = w.Write([]byte(erro.Error()))
		}
	}

	table := dns.ConvertResultToTable(results)
	_, err = w.Write([]byte(table))
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(500)
		return
	}

	w.WriteHeader(200)
}
