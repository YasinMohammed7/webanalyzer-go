package webanalyze

import (
	"context"
	"strings"
	"sync"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/css"
	"github.com/chromedp/chromedp"
)

type CSSCollector struct {
	mu sync.Mutex

	// Actual CSS we've successfully copied from Chrome.
	sheets map[cdp.StyleSheetID]string

	// Prevent duplicate stylesheet processing.
	seen map[cdp.StyleSheetID]struct{}

	// StyleSheetAdded → capture worker.
	queue chan cdp.StyleSheetID

	// Caller tells collector to finish.
	stop chan struct{}

	// Collector tells caller it has finished.
	done chan struct{}

	// Prevent closing stop twice.
	stopOnce sync.Once
}

func NewCSSCollector() *CSSCollector {
	return &CSSCollector{
		sheets: make(map[cdp.StyleSheetID]string),
		seen:   make(map[cdp.StyleSheetID]struct{}),

		queue: make(chan cdp.StyleSheetID, 128),

		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
}

func (c *CSSCollector) Queue(id cdp.StyleSheetID) {
	c.mu.Lock()

	if _, exists := c.seen[id]; exists {
		c.mu.Unlock()
		return
	}

	c.seen[id] = struct{}{}

	c.mu.Unlock()

	select {
	case c.queue <- id:
	case <-c.stop:
		return
	}
}

func (c *CSSCollector) Store(
	id cdp.StyleSheetID,
	text string,
) {
	if text == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.sheets[id] = text
}

func (c *CSSCollector) Stop() {
	c.stopOnce.Do(func() {
		close(c.stop)
	})
}

func (c *CSSCollector) Wait(
	ctx context.Context,
) error {
	select {
	case <-c.done:
		return nil

	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *CSSCollector) Text() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	var builder strings.Builder

	for _, text := range c.sheets {
		builder.WriteString(text)
		builder.WriteByte('\n')
	}

	return builder.String()
}

func (c *CSSCollector) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.sheets)
}

func (b *Browser) CollectCSS(
	ctx context.Context,
) *CSSCollector {

	collector := NewCSSCollector()

	events := chromedp.Events(
		ctx,
		css.StyleSheetAdded,
	)

	// Producer:
	// Chrome CSS event → queue stylesheet ID.
	go func() {
		for event, err := range events {
			if err != nil {
				return
			}

			if event.Header == nil {
				continue
			}

			collector.Queue(
				event.Header.StyleSheetID,
			)
		}
	}()

	// Consumer:
	// stylesheet ID → retrieve actual CSS.
	go func() {
		defer close(collector.done)

		for {
			select {

			case id := <-collector.queue:
				result, err := chromedp.Call(
					ctx,
					css.GetStyleSheetText,
					css.GetStyleSheetTextParams{
						StyleSheetID: id,
					},
				)

				if err != nil {
					continue
				}

				collector.Store(
					id,
					result.Text,
				)

			case <-collector.stop:

				// Finish IDs that were already queued.
				for {
					select {

					case id := <-collector.queue:
						result, err := chromedp.Call(
							ctx,
							css.GetStyleSheetText,
							css.GetStyleSheetTextParams{
								StyleSheetID: id,
							},
						)

						if err != nil {
							continue
						}

						collector.Store(
							id,
							result.Text,
						)

					default:
						return
					}
				}

			case <-ctx.Done():
				return
			}
		}
	}()

	return collector
}
