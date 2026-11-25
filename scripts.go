package webanalyze

import (
	"context"
	"crypto/sha256"
	"sync"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

type ScriptDetection struct {
	URL        string
	Matches    [][]string
	Version    string
	Confidence int
}

type ScriptCollector struct {
	// mu protects requests, seenBodies, and detections.
	mu sync.Mutex

	requests   map[network.RequestID]string
	seenBodies map[[32]byte]struct{}
	detections map[string][]ScriptDetection

	// Initialized before collection starts and read by scan workers.
	scriptRegexes map[string][]AppRegexp

	// Tracks workers that retrieve and scan script bodies.
	wg sync.WaitGroup

	// Canceling the listener lets already registered workers finish on ctx.
	cancel context.CancelFunc

	// eventMu coordinates worker registration with Stop.
	eventMu sync.Mutex
	stopped bool
}

func NewScriptCollector(scriptRegexes map[string][]AppRegexp) *ScriptCollector {
	return &ScriptCollector{
		requests:      make(map[network.RequestID]string),
		seenBodies:    make(map[[32]byte]struct{}),
		detections:    make(map[string][]ScriptDetection),
		scriptRegexes: scriptRegexes,
	}
}

// AddRequest remembers the URL for an in-flight script request.
func (c *ScriptCollector) AddRequest(id network.RequestID, url string) {
	if url == "" {
		return
	}

	c.mu.Lock()
	c.requests[id] = url
	c.mu.Unlock()
}

// TakeRequest retrieves the URL and removes the pending request.
func (c *ScriptCollector) TakeRequest(id network.RequestID) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	url, exists := c.requests[id]
	if exists {
		delete(c.requests, id)
	}

	return url, exists
}

// Scan checks one script body and records the URL alongside each detection.
func (c *ScriptCollector) Scan(url string, source []byte) {
	if len(source) == 0 {
		return
	}

	hash := sha256.Sum256(source)

	// Claim the body before scanning so concurrent workers scan it only once.
	c.mu.Lock()
	if _, exists := c.seenBodies[hash]; exists {
		c.mu.Unlock()
		return
	}
	c.seenBodies[hash] = struct{}{}
	c.mu.Unlock()

	// Regex matching happens outside the lock.
	content := string(source)
	localDetections := make(map[string][]ScriptDetection)

	for appName, regexes := range c.scriptRegexes {
		matches, version, confidence := findMatches(content, regexes)
		if len(matches) == 0 {
			continue
		}

		localDetections[appName] = append(
			localDetections[appName],
			ScriptDetection{
				URL:        url,
				Matches:    matches,
				Version:    version,
				Confidence: confidence,
			},
		)
	}

	if len(localDetections) == 0 {
		return
	}

	c.mu.Lock()
	for appName, detections := range localDetections {
		c.detections[appName] = append(c.detections[appName], detections...)
	}
	c.mu.Unlock()
}

// Detections returns a shallow copy of one application's detection slice.
func (c *ScriptCollector) Detections(appName string) []ScriptDetection {
	c.mu.Lock()
	defer c.mu.Unlock()

	detections := c.detections[appName]
	if len(detections) == 0 {
		return nil
	}

	result := make([]ScriptDetection, len(detections))
	copy(result, detections)
	return result
}

// Stop prevents new scan workers from being registered.
func (c *ScriptCollector) Stop() {
	c.eventMu.Lock()
	c.stopped = true
	c.eventMu.Unlock()

	if c.cancel != nil {
		c.cancel()
	}
}

// Wait waits for registered scans or for ctx to expire.
// Call Stop first so the set of registered workers is final.
func (c *ScriptCollector) Wait(ctx context.Context) error {
	done := make(chan struct{})

	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// CollectScripts registers the listener before the caller navigates the tab.
func (b *Browser) CollectScripts(
	ctx context.Context,
	scriptRegexes map[string][]AppRegexp,
) (*ScriptCollector, error) {
	collector := NewScriptCollector(scriptRegexes)

	eventCtx, cancel := context.WithCancel(ctx)
	collector.cancel = cancel

	err := chromedp.Listen(eventCtx, func(event any) {
		switch e := event.(type) {
		case *network.EventRequestWillBeSent:
			if e.Type == network.ResourceTypeScript && e.Request != nil {
				collector.AddRequest(e.RequestID, e.Request.URL)
			} else {
				// A redirect can reuse the request ID.
				collector.TakeRequest(e.RequestID)
			}

		case *network.EventLoadingFailed:
			collector.TakeRequest(e.RequestID)

		case *network.EventLoadingFinished:
			id := e.RequestID
			url, ok := collector.TakeRequest(id)
			if !ok {
				return
			}

			// Hold eventMu until wg.Go has registered the worker.
			// Stop takes the same lock before it marks the collector stopped.
			collector.eventMu.Lock()
			defer collector.eventMu.Unlock()

			if collector.stopped {
				return
			}

			collector.wg.Go(func() {
				// Use the tab context so Stop can cancel the listener
				// while this body retrieval finishes.
				result, err := chromedp.Call(
					ctx,
					network.GetResponseBody,
					network.GetResponseBodyParams{RequestID: id},
				)
				if err == nil {
					collector.Scan(url, result.Body)
				}
			})
		}
	})

	if err != nil {
		cancel()
		return nil, err
	}

	return collector, nil
}
