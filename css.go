package webanalyze

import (
	"context"
	"sync"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/css"
	"github.com/chromedp/chromedp"
)

// CSSDetection contains only the result of scanning one stylesheet.
// The CSS source itself is never retained.
type CSSDetection struct {
	Matches    [][]string
	Version    string
	Confidence int
}

// CSSCollector retrieves stylesheets, scans them immediately,
// stores only detections, and releases the CSS source.
type CSSCollector struct {
	mu sync.Mutex

	// Prevent processing the same stylesheet more than once.
	seen map[cdp.StyleSheetID]struct{}

	// appName -> CSS detections
	detections map[string][]CSSDetection

	// Precomputed CSS regexes from loadApps().
	cssRegexes map[string][]AppRegexp

	// StyleSheetAdded -> worker.
	queue chan cdp.StyleSheetID

	// Caller tells collector to finish.
	stop chan struct{}

	// Collector tells caller it has finished.
	done chan struct{}

	stopOnce sync.Once
}

func NewCSSCollector(
	cssRegexes map[string][]AppRegexp,
) *CSSCollector {
	return &CSSCollector{
		seen: make(
			map[cdp.StyleSheetID]struct{},
		),

		detections: make(
			map[string][]CSSDetection,
		),

		cssRegexes: cssRegexes,

		queue: make(
			chan cdp.StyleSheetID,
			128,
		),

		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
}

// Queue adds a stylesheet only once.
func (c *CSSCollector) Queue(
	id cdp.StyleSheetID,
) {
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

// Scan scans one stylesheet immediately.
//
// The CSS text is never stored in CSSCollector.
// Once this function returns, the caller can release it.
func (c *CSSCollector) Scan(
	text string,
) {
	if text == "" {
		return
	}

	localDetections := make(
		map[string][]CSSDetection,
	)

	// Do not hold the mutex while regex matching.
	for appName, regexes := range c.cssRegexes {
		matches, version, confidence := findMatches(
			text,
			regexes,
		)

		if len(matches) == 0 {
			continue
		}

		localDetections[appName] = append(
			localDetections[appName],
			CSSDetection{
				Matches:    matches,
				Version:    version,
				Confidence: confidence,
			},
		)
	}

	if len(localDetections) == 0 {
		return
	}

	// Only lock while saving the tiny detection results.
	c.mu.Lock()

	for appName, detections := range localDetections {
		c.detections[appName] = append(
			c.detections[appName],
			detections...,
		)
	}

	c.mu.Unlock()
}

// Detections returns CSS detections for one technology.
func (c *CSSCollector) Detections(
	appName string,
) []CSSDetection {
	c.mu.Lock()
	defer c.mu.Unlock()

	detections := c.detections[appName]

	if len(detections) == 0 {
		return nil
	}

	result := make(
		[]CSSDetection,
		len(detections),
	)

	copy(result, detections)

	return result
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

// CollectCSS starts listening for stylesheets.
func (b *Browser) CollectCSS(
	ctx context.Context,
	cssRegexes map[string][]AppRegexp,
) *CSSCollector {

	collector := NewCSSCollector(
		cssRegexes,
	)

	events := chromedp.Events(
		ctx,
		css.StyleSheetAdded,
	)

	// Producer:
	// Chrome stylesheet event -> queue stylesheet ID.
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
	// stylesheet ID -> retrieve -> scan -> discard.
	go func() {
		defer close(collector.done)

		process := func(
			id cdp.StyleSheetID,
		) {
			result, err := chromedp.Call(
				ctx,
				css.GetStyleSheetText,
				css.GetStyleSheetTextParams{
					StyleSheetID: id,
				},
			)

			if err != nil {
				return
			}

			if result.Text == "" {
				return
			}

			// Scan immediately.
			collector.Scan(
				result.Text,
			)

			// result.Text is not stored.
			//
			// After process() returns it becomes
			// eligible for garbage collection.
		}

		for {
			select {

			case id := <-collector.queue:
				process(id)

			case <-collector.stop:

				// Finish anything already queued.
				for {
					select {

					case id := <-collector.queue:
						process(id)

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
