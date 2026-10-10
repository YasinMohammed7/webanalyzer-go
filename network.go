package webanalyze

import (
	"context"
	"sync"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

type NetworkCollector struct {
	mu   sync.Mutex
	urls []string
	seen map[string]struct{}
}

func (c *NetworkCollector) Add(url string) {

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.seen[url]; exists {
		return
	}
	c.seen[url] = struct{}{}
	c.urls = append(c.urls, url)

}

func (c *NetworkCollector) URLs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return append([]string(nil), c.urls...)
}

func (b *Browser) CollectXHR(
	ctx context.Context,
) *NetworkCollector {

	collector := &NetworkCollector{
		seen: make(map[string]struct{}),
	}

	events := chromedp.Events(
		ctx,
		network.RequestWillBeSent,
	)

	go func() {
		for event, err := range events {
			if err != nil {
				return
			}

			if event.Type != network.ResourceTypeXHR &&
				event.Type != network.ResourceTypeFetch {
				continue
			}

			if event.Request == nil {
				continue
			}

			collector.Add(event.Request.URL)
		}
	}()

	return collector
}
