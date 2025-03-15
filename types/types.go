package types

import "time"

type DnsCounts struct {
	Addreses string
	Cname    string
	Txts     string
	Ns       string
}

type DnsResult struct {
	Operator        string
	DnsServer       string
	Addreses        []string
	Cname           string
	Txts            []string
	Ns              []string
	RequestDuration time.Duration
}

type DnsServer struct {
	Operator string
	Address  string
}
