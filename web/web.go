package web

import (
	"fmt"
	"strings"

	"tilok.dev/dns-checker/dns"
)

func todo() {
	results, _ := dns.QueryServers("tilo.host")

	for _, result := range results {
		fmt.Printf("%17s: %s\t%s\n", result.DnsServer, result.RequestDuration, strings.Join(result.Addreses, ", "))
	}
}
