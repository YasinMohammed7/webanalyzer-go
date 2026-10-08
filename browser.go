package webanalyze

import (
	"context"
	"encoding/json"
	"fmt"

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

func (b *Browser) GetJSProperties(
	ctx context.Context,
	paths []string,
) (map[string]JSResult, error) {

	if len(paths) == 0 {
		return map[string]JSResult{}, nil
	}

	pathsJSON, err := json.Marshal(paths)
	if err != nil {
		return nil, err
	}

	expression := fmt.Sprintf(`
		(() => {
			const paths = %s;
			const results = {};

			for (const path of paths) {
				try {
					const parts = path.split(".");
					let value = window;
					let exists = true;

					for (const part of parts) {
						if (
							value === null ||
							value === undefined ||
							!(part in Object(value))
						) {
							exists = false;
							break;
						}

						value = value[part];
					}

					if (
						!exists ||
						value === null ||
						value === undefined
					) {
						results[path] = {
							exists: false,
							value: ""
						};

						continue;
					}

					results[path] = {
						exists: true,
						value: String(value)
					};

				} catch {
					results[path] = {
						exists: false,
						value: ""
					};
				}
			}

			return results;
		})()
	`, pathsJSON)

	results, err := chromedp.Run(
		ctx,
		chromedp.Evaluate[map[string]JSResult](expression),
	)

	if err != nil {
		return nil, err
	}

	return results, nil
}

func (b *Browser) Close() {

	if b.cancel != nil {
		b.cancel()
	}
	if b.allocCancel != nil {
		b.allocCancel()
	}

}
