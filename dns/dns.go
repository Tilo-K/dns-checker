package dns

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"tilok.dev/dns-checker/types"
	"tilok.dev/dns-checker/util"
	"time"
)

type ByDuration []types.DnsResult

func (b ByDuration) Len() int      { return len(b) }
func (b ByDuration) Swap(i, j int) { b[i], b[j] = b[j], b[i] }
func (b ByDuration) Less(i, j int) bool {
	return b[i].RequestDuration.Microseconds() < b[j].RequestDuration.Microseconds()
}

func createCustomResolver(dnsServer string, timeout time.Duration) *net.Resolver {
	if timeout == 0 {
		timeout = time.Second * 10
	}

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: timeout,
			}
			return d.DialContext(ctx, network, dnsServer)
		},
	}
}

func GetDnsServers() []types.DnsServer {
	data, err := os.ReadFile("servers.csv")
	if err != nil {
		panic(err)
	}

	lines := strings.Split(string(data), "\n")
	servers := make([]types.DnsServer, 0)

	skippedFirst := false
	for _, line := range lines {
		if !skippedFirst {
			skippedFirst = true
			continue
		}

		cols := strings.Split(line, ";")
		if len(cols) < 2 {
			continue
		}
		ip := cols[1]
		if !strings.Contains(ip, ":") && strings.Contains(ip, ".") {
			ip += ":53"
		}

		if strings.Contains(ip, ":") && !strings.Contains(ip, ".") && !strings.Contains(ip, "[") {
			ip = fmt.Sprintf("[%s]:53", ip)
		}
		servers = append(servers, types.DnsServer{
			Operator: cols[0],
			Address:  ip,
		})
	}
	return servers
}

func getContext() context.Context {
	timeout, _ := time.ParseDuration("5s")
	ctxt, err := context.WithTimeout(context.Background(), timeout)
	if err != nil {
		fmt.Println(err)
	}

	return ctxt
}

func QueryServers(host string) ([]types.DnsResult, []error) {
	var wg sync.WaitGroup

	results := make([]types.DnsResult, 0)
	errors := make([]error, 0)

	servers := GetDnsServers()

	for _, server := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resolver := createCustomResolver(server.Address, 0)

			start := time.Now()
			hosts, err := resolver.LookupHost(getContext(), host)
			if err != nil {
				errors = append(errors, err)
				return
			}
			cname, err := resolver.LookupCNAME(getContext(), host)
			if err != nil {
				errors = append(errors, err)
				return
			}
			txts, err := resolver.LookupTXT(getContext(), host)
			if err != nil {
				errors = append(errors, err)
				return
			}
			ns, err := resolver.LookupNS(getContext(), host)
			if err != nil {
				errors = append(errors, err)
				return
			}
			elapsed := time.Since(start)

			if err != nil {
				errors = append(errors, err)
				return
			}

			nss := make([]string, 0)
			for _, nserver := range ns {
				nss = append(nss, nserver.Host)
			}

			results = append(results, types.DnsResult{
				Operator:        server.Operator,
				DnsServer:       server.Address,
				Addreses:        hosts,
				RequestDuration: elapsed,
				Cname:           cname,
				Txts:            txts,
				Ns:              nss,
			})
		}()
	}

	wg.Wait()
	sort.Sort(ByDuration(results))

	return results, errors
}

func ConvertResultToTable(results []types.DnsResult) string {
	counts := util.CountResults(results)
	result := "<table>\n<thead><tr><th>Operator</th><th>Server</th><th>A</th><th>TXT</th><th>NS</th><th>CNAME</th><th>Request Duration</th></tr></thead>\n<tbody>\n"
	for _, dnsResult := range results {
		addrClasses := ""
		cnameClasses := ""
		txtClasses := ""
		nsClasses := ""

		if counts.Addreses == util.Hash(dnsResult.Addreses) {
			addrClasses = "highlight"
		}
		if counts.Cname == util.Hash([]string{dnsResult.Cname}) {
			cnameClasses = "highlight"
		}
		if counts.Txts == util.Hash(dnsResult.Txts) {
			txtClasses = "highlight"
		}
		if counts.Ns == util.Hash(dnsResult.Ns) {
			nsClasses = "highlight"
		}

		result += "<tr>\n"
		result += "<td>" + dnsResult.Operator + "</td>\n"
		result += "<td>" + dnsResult.DnsServer + "</td>\n"
		result += "<td class=\"" + addrClasses + "\">" + strings.Join(dnsResult.Addreses, "<br />") + "</td>\n"
		result += "<td class=\"" + txtClasses + "\">" + strings.Join(dnsResult.Txts, "<br />") + "</td>\n"
		result += "<td class=\"" + nsClasses + "\">" + strings.Join(dnsResult.Ns, "<br />") + "</td>\n"
		result += "<td class=\"" + cnameClasses + "\">" + dnsResult.Cname + "</td>\n"
		result += "<td>" + dnsResult.RequestDuration.String() + "</td>\n"
		result += "</tr>\n"
	}
	result += "</tbody>\n</table>"

	return result
}
