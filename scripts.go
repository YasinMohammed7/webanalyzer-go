package webanalyze

import (
	"context"
	"crypto/sha256"
	"sync"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// ScriptDetection contains only the result of scanning one script.
// The JavaScript source itself is NOT retained.
type ScriptDetection struct {
	URL        string
	Matches    [][]string
	Version    string
	Confidence int
}

// ScriptCollector receives JavaScript responses, scans them immediately,
// stores only detections, and then allows the script body to be released.
type ScriptCollector struct {
	mu sync.Mutex

	// requestID -> script URL
	//
	// Used only while waiting for LoadingFinished.
	requests map[network.RequestID]string

	// Hashes of JavaScript bodies already scanned.
	//
	// This prevents scanning identical scripts multiple times.
	// A SHA-256 hash is only 32 bytes, so this is much cheaper than
	// retaining the actual JavaScript source.
	seenBodies map[[32]byte]struct{}

	// appName -> detections
	//
	// Indexing by app name means process() can retrieve detections
	// directly instead of scanning every detection for every app.
	detections map[string][]ScriptDetection

	// Script regexes grouped by application.
	scriptRegexes map[string][]AppRegexp

	// Tracks GetResponseBody operations already started.
	wg sync.WaitGroup

	// Cancels only the Network event listeners.
	cancel context.CancelFunc

	stopOnce sync.Once
}

// NewScriptCollector creates a collector using the already-compiled
// "scripts" regexes from the technology definitions.
func NewScriptCollector(scriptRegexes map[string][]AppRegexp) *ScriptCollector {

	return &ScriptCollector{
		requests:      make(map[network.RequestID]string),
		seenBodies:    make(map[[32]byte]struct{}),
		detections:    make(map[string][]ScriptDetection),
		scriptRegexes: scriptRegexes,
	}

}

// AddRequest remembers the URL belonging to a JavaScript RequestID.
func (c *ScriptCollector) AddRequest(
	id network.RequestID,
	url string,
) {
	if url == "" {
		return
	}

	c.mu.Lock()
	c.requests[id] = url
	c.mu.Unlock()
}

// TakeRequest removes and returns a pending JavaScript request.
func (c *ScriptCollector) TakeRequest(
	id network.RequestID,
) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	url, exists := c.requests[id]

	if exists {
		delete(c.requests, id)
	}

	return url, exists
}

// Scan immediately scans one JavaScript body.
//
// The source is NOT stored anywhere in ScriptCollector.
// Once this function returns and the caller releases its reference,
// the body becomes eligible for garbage collection.
func (c *ScriptCollector) Scan(
	url string,
	source []byte,
) {
	if len(source) == 0 {
		return
	}

	hash := sha256.Sum256(source)

	c.mu.Lock()

	if _, exists := c.seenBodies[hash]; exists {
		c.mu.Unlock()
		return
	}

	c.seenBodies[hash] = struct{}{}

	c.mu.Unlock()

	// Convert ONCE per script.
	content := string(source)

	localDetections := make(
		map[string][]ScriptDetection,
	)

	for appName, regexes := range c.scriptRegexes {

		matches, version, confidence := findMatches(
			content,
			regexes,
		)

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
		c.detections[appName] = append(
			c.detections[appName],
			detections...,
		)
	}

	c.mu.Unlock()
}

// Detections returns the detections for one application.
//
// Returning a copy prevents callers from depending on the collector's
// internal slice while collection may still be happening.
func (c *ScriptCollector) Detections(
	appName string,
) []ScriptDetection {
	c.mu.Lock()
	defer c.mu.Unlock()

	detections := c.detections[appName]

	if len(detections) == 0 {
		return nil
	}

	result := make(
		[]ScriptDetection,
		len(detections),
	)

	copy(result, detections)

	return result
}

// Stop prevents the collector from accepting new Network events.
//
// GetResponseBody operations that have already started continue using
// the original browser context.
func (c *ScriptCollector) Stop() {
	c.stopOnce.Do(func() {
		if c.cancel != nil {
			c.cancel()
		}
	})
}

// Wait waits for all GetResponseBody + script scanning operations that
// have already started.
func (c *ScriptCollector) Wait(
	ctx context.Context,
) error {
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

// CollectScripts starts listening for JavaScript resources.
func (b *Browser) CollectScripts(ctx context.Context, scriptRegexes map[string][]AppRegexp) *ScriptCollector {

	collector := NewScriptCollector(
		scriptRegexes,
	)

	// Separate event context:
	//
	// Stop() can stop accepting new Network events without cancelling
	// GetResponseBody calls already running on ctx.
	eventCtx, cancel := context.WithCancel(ctx)

	collector.cancel = cancel

	requestEvents := chromedp.Events(
		eventCtx,
		network.RequestWillBeSent,
	)

	finishedEvents := chromedp.Events(
		eventCtx,
		network.LoadingFinished,
	)

	// ---------------------------------------------------------
	// Track script requests
	// ---------------------------------------------------------

	go func() {
		for event, err := range requestEvents {
			if err != nil {
				return
			}

			if event.Type != network.ResourceTypeScript {
				continue
			}

			collector.AddRequest(
				event.RequestID,
				event.Request.URL,
			)
		}
	}()

	// ---------------------------------------------------------
	// Retrieve + immediately scan finished scripts
	// ---------------------------------------------------------

	go func() {
		for event, err := range finishedEvents {
			if err != nil {
				return
			}

			url, exists := collector.TakeRequest(
				event.RequestID,
			)

			if !exists {
				continue
			}

			requestID := event.RequestID

			collector.wg.Go(func() {

				result, err := chromedp.Call(
					ctx,
					network.GetResponseBody,
					network.GetResponseBodyParams{
						RequestID: requestID,
					},
				)

				if err != nil {
					return
				}

				if len(result.Body) == 0 {
					return
				}

				// Scan immediately.
				//
				// We DO NOT save result.Body in the collector.
				collector.Scan(
					url,
					result.Body,
				)

				// After this goroutine returns, result.Body is no
				// longer referenced by us and can be garbage collected.
			})
		}
	}()

	return collector
}
