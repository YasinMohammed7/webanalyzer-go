package webanalyze

import (
	"context"
	"crypto/sha256"
	"sync"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// Script represents one JavaScript resource loaded by the browser.
//
// Scripts are deliberately kept separate instead of concatenating all
// JavaScript into one giant string. This allows us to scan each script
// independently later.
type Script struct {
	URL    string
	Source []byte
}

// ScriptCollector collects JavaScript responses loaded by Chrome.
type ScriptCollector struct {
	mu sync.Mutex

	// requestID -> script
	scripts map[network.RequestID]Script

	// Avoid storing/scanning identical JavaScript bodies more than once.
	seenBodies map[[32]byte]struct{}

	// requestID -> URL
	//
	// RequestWillBeSent tells us that a request is a Script.
	// LoadingFinished later gives us the RequestID, so we remember
	// the URL here.
	requests map[network.RequestID]string

	// Tracks GetResponseBody operations that have already started.
	wg sync.WaitGroup

	// Stops the event listeners from accepting new script requests.
	//
	// Important:
	// this only cancels the event-listener context. It does NOT cancel
	// GetResponseBody calls that are already running.
	cancel context.CancelFunc

	stopOnce sync.Once
}

func NewScriptCollector() *ScriptCollector {
	return &ScriptCollector{
		scripts:    make(map[network.RequestID]Script),
		seenBodies: make(map[[32]byte]struct{}),
		requests:   make(map[network.RequestID]string),
	}
}

// AddRequest remembers that a RequestID belongs to a JavaScript resource.
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

// TakeRequest returns the URL associated with a request.
//
// LoadingFinished should be the final event we need for this RequestID,
// so remove it from the pending request map immediately.
func (c *ScriptCollector) TakeRequest(
	id network.RequestID,
) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	url, exists := c.requests[id]
	if !exists {
		return "", false
	}

	delete(c.requests, id)

	return url, true
}

// Store saves one JavaScript body.
//
// Identical script bodies are stored only once, even if Chrome loaded
// the same body from multiple requests/URLs.
func (c *ScriptCollector) Store(
	id network.RequestID,
	url string,
	source []byte,
) {
	if len(source) == 0 {
		return
	}

	hash := sha256.Sum256(source)

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.seenBodies[hash]; exists {
		return
	}

	c.seenBodies[hash] = struct{}{}

	c.scripts[id] = Script{
		URL:    url,
		Source: source,
	}
}

// Scripts returns a snapshot of all collected JavaScript resources.
func (c *ScriptCollector) Scripts() []Script {
	c.mu.Lock()
	defer c.mu.Unlock()

	scripts := make([]Script, 0, len(c.scripts))

	for _, script := range c.scripts {
		scripts = append(scripts, script)
	}

	return scripts
}

// Count returns the number of unique JavaScript bodies collected.
func (c *ScriptCollector) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.scripts)
}

// Bytes returns the total number of JavaScript bytes collected.
func (c *ScriptCollector) Bytes() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	total := 0

	for _, script := range c.scripts {
		total += len(script.Source)
	}

	return total
}

// Stop prevents the collector from accepting any more Network events.
//
// Already-started GetResponseBody operations continue running because
// they use the original browser context, not the event context.
func (c *ScriptCollector) Stop() {
	c.stopOnce.Do(func() {
		if c.cancel != nil {
			c.cancel()
		}
	})
}

// Wait waits until all GetResponseBody operations that were already
// started have completed.
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

// CollectScripts starts collecting JavaScript resources loaded by Chrome.
//
// There are intentionally two contexts:
//
//	eventCtx
//	    Controls RequestWillBeSent / LoadingFinished listeners.
//	    Stop() cancels this context so no new scripts are accepted.
//
//	ctx
//	    Original browser context.
//	    GetResponseBody uses this so requests that already started can
//	    finish even after Stop() is called.
func (b *Browser) CollectScripts(
	ctx context.Context,
) *ScriptCollector {
	collector := NewScriptCollector()

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

	// Track JavaScript requests.
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

	// Once a JavaScript resource finishes loading, retrieve its body.
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

				collector.Store(
					requestID,
					url,
					result.Body,
				)
			})
		}
	}()

	return collector
}
