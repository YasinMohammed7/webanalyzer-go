package webanalyze

import (
	"context"
	"time"

	"github.com/chromedp/chromedp"
)

type Browser struct {
	ctx         context.Context
	cancel      context.CancelFunc
	allocCancel context.CancelFunc
}

func NewBrowser() (*Browser, error) {
	opts := append(
		chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", false),
		chromedp.Flag("ignore-certificate-errors", true),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(
		context.Background(),
		opts...,
	)

	ctx, cancel := chromedp.NewContext(allocCtx)

	browser := &Browser{
		ctx:         ctx,
		cancel:      cancel,
		allocCancel: allocCancel,
	}

	// Force browser allocation now.
	if _, err := chromedp.Run(ctx, chromedp.Title()); err != nil {
		browser.Close()
		return nil, err
	}

	return browser, nil
}

func (b *Browser) NewTab() (context.Context, context.CancelFunc) {
	return chromedp.NewContext(b.ctx)
}

func (wa *WebAnalyzer) BrowserTest(pageURL string) error {

	if wa.browser == nil {
		return nil
	}
	ctx, cancel := wa.browser.NewTab()
	defer cancel()
	_, err := chromedp.Run(
		ctx,
		chromedp.Navigate(pageURL),
	)

	time.Sleep(10 * time.Second)
	return err

}

func (b *Browser) Close() {

	if b.cancel != nil {
		b.cancel()
	}
	if b.allocCancel != nil {
		b.allocCancel()
	}

}
