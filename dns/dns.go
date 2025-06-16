package dns

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"tilok.dev/dns-checker/types"
	"tilok.dev/dns-checker/util"
)

type ByDuration []types.DnsResult
type ByOperator []types.DnsResult

func (b ByDuration) Len() int      { return len(b) }
func (b ByDuration) Swap(i, j int) { b[i], b[j] = b[j], b[i] }
func (b ByDuration) Less(i, j int) bool {
	return b[i].RequestDuration.Microseconds() < b[j].RequestDuration.Microseconds()
}

func (b ByOperator) Len() int      { return len(b) }
func (b ByOperator) Swap(i, j int) { b[i], b[j] = b[j], b[i] }
func (b ByOperator) Less(i, j int) bool {
	return b[i].Operator < b[j].Operator
}

func createCustomResolver(dnsAddr string, timeout time.Duration) (*net.Resolver, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	host, port, err := net.SplitHostPort(dnsAddr)
	if err != nil {
		host = dnsAddr
		port = "53"
	}
	dnsAddr = net.JoinHostPort(host, port)

	dialer := &net.Dialer{Timeout: timeout}

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if network[0] == 'u' { // udp*, tcp*
				network = "udp"
			} else {
				network = "tcp"
			}
			return dialer.DialContext(ctx, network, dnsAddr)
		},
		StrictErrors: false}, nil
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

func getContext() (context.Context, context.CancelFunc) {
	timeout, _ := time.ParseDuration("5s")
	ctxt, cancel := context.WithTimeout(context.Background(), timeout)

	return ctxt, cancel
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
			resolver, err := createCustomResolver(server.Address, 0)
			if err != nil {
				errors = append(errors, err)
				return
			}
			context, cancel := getContext()
			defer cancel()
			start := time.Now()
			hosts, err := resolver.LookupHost(context, host)
			if err != nil {
				errors = append(errors, err)
				return
			}
			cname, err := resolver.LookupCNAME(context, host)
			if err != nil {
				errors = append(errors, err)
				return
			}
			txts, err := resolver.LookupTXT(context, host)
			if err != nil {
				errors = append(errors, err)
				return
			}
			ns, err := resolver.LookupNS(context, host)
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

			sort.Strings(hosts)
			sort.Strings(nss)
			sort.Strings(txts)

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
	sort.Sort(ByOperator(results))

	return results, errors
}

func ConvertResultToTable(results []types.DnsResult) string {
	currentTime := time.Now().Format(time.RFC3339)
	counts := util.CountResults(results)
	result := currentTime + "<table>\n<thead><tr><th>Operator</th><th>Server</th><th>A</th><th>TXT</th><th>NS</th><th>CNAME</th><th>Request Duration</th></tr></thead>\n<tbody>\n"
	for _, dnsResult := range results {
		addrClasses := ""
		cnameClasses := ""
		txtClasses := ""
		nsClasses := ""

		if counts.Addreses != util.Hash(dnsResult.Addreses) {
			fmt.Println(counts.Addreses)
			fmt.Println(util.Hash(dnsResult.Addreses))
			addrClasses = "highlight"
		}
		if counts.Cname != util.Hash([]string{dnsResult.Cname}) {
			cnameClasses = "highlight"
		}
		if counts.Txts != util.Hash(dnsResult.Txts) {
			txtClasses = "highlight"
		}
		if counts.Ns != util.Hash(dnsResult.Ns) {
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
