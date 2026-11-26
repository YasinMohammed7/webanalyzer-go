package webanalyze

import (
	"context"
	"io"
	"sort"
	"strings"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

type SubdomainDiscoverer struct {
	runner *runner.Runner
}

func NewSubdomainDiscoverer() (*SubdomainDiscoverer, error) {
	r, err := runner.NewRunner(&runner.Options{
		Threads:            4,  // Active DNS resolution concurrency.
		Timeout:            30, // Per-source timeout, seconds.
		MaxEnumerationTime: 1,  // Enumeration limit, minutes.
	})
	if err != nil {
		return nil, err
	}

	return &SubdomainDiscoverer{runner: r}, nil
}

// domain must be a normalized hostname, without scheme, path, or port.
// Call sequentially initially; do not share across workers concurrently.
func (d *SubdomainDiscoverer) Discover(
	ctx context.Context,
	domain string,
) ([]string, error) {
	found, err := d.runner.EnumerateSingleDomainWithCtx(
		ctx,
		domain,
		[]io.Writer{io.Discard},
	)

	seen := make(map[string]struct{})
	for hostname := range found {
		hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))

		if strings.Contains(hostname, "*") ||
			!strings.HasSuffix(hostname, "."+domain) {
			continue
		}

		seen[hostname] = struct{}{}
	}

	names := make([]string, 0, len(seen))
	for hostname := range seen {
		names = append(names, hostname)
	}
	sort.Strings(names)

	// Preserve any partial results alongside an error.
	return names, err
}

func (d *SubdomainDiscoverer) DiscoverMany(
	ctx context.Context,
	roots []string,
	output io.Writer,
) error {
	input := strings.NewReader(strings.Join(roots, "\n"))
	return d.runner.EnumerateMultipleDomainsWithCtx(
		ctx,
		input,
		[]io.Writer{output},
	)
}
