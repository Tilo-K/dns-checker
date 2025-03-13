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
)

type DnsResult struct {
	DnsServer       string
	Addreses        []string
	RequestDuration time.Duration
}

type ByDuration []DnsResult

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

func GetDnsServers() []string {
	data, err := os.ReadFile("servers.csv")
	if err != nil {
		panic(err)
	}

	lines := strings.Split(string(data), "\n")
	var servers []string
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
		servers = append(servers, ip)
	}
	return servers
}

func QueryServers(host string) ([]DnsResult, []error) {
	var wg sync.WaitGroup

	results := make([]DnsResult, 0)
	errors := make([]error, 0)

	servers := GetDnsServers()

	for _, server := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resolver := createCustomResolver(server, 0)

			start := time.Now()
			hosts, err := resolver.LookupHost(context.Background(), host)
			elapsed := time.Now().Sub(start)

			if err != nil {
				errors = append(errors, err)
				return
			}

			results = append(results, DnsResult{
				DnsServer:       server,
				Addreses:        hosts,
				RequestDuration: elapsed,
			})
		}()
	}

	wg.Wait()
	sort.Sort(ByDuration(results))

	return results, errors
}
