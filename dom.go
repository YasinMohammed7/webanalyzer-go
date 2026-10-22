package webanalyze

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/chromedp/chromedp"
)

// elementData represents raw element data pulled from the browser
type elementData struct {
	Exists     bool              `json:"exists"`
	Text       string            `json:"text"`
	Attributes map[string]string `json:"attributes"`
	Properties map[string]string `json:"properties"`
}

func (wa *WebAnalyzer) CollectDOMResults(ctx context.Context) (map[string][]elementData, error) {
	if len(wa.domSelectors) == 0 {
		return nil, nil
	}

	selectorsJSON, err := json.Marshal(wa.domSelectors)
	if err != nil {
		return nil, err
	}

	propertiesJSON, err := json.Marshal(wa.domProperties)
	if err != nil {
		return nil, err
	}

	script := fmt.Sprintf(`
		(function() {
			const selectors = %s;
			const requestedProperties = %s;
			const results = {};

			function propertyToString(value) {
				if (value === null || value === undefined) {
					return "";
				}

				if (
					typeof value === "string" ||
					typeof value === "number" ||
					typeof value === "boolean"
				) {
					return String(value);
				}

				try {
					return JSON.stringify(value);
				} catch (_) {
					return String(value);
				}
			}

			for (const sel of selectors) {
				try {
					const elements = document.querySelectorAll(sel);

					if (elements.length === 0) {
						continue;
					}

					results[sel] = [];

					for (const el of elements) {
						const data = {
							exists: true,
							text: el.textContent || "",
							attributes: {},
							properties: {}
						};

						if (el.attributes) {
							for (let i = 0; i < el.attributes.length; i++) {
								const attr = el.attributes[i];
								data.attributes[attr.name] = attr.value;
							}
						}

						const propertyNames = requestedProperties[sel] || [];

						for (const prop of propertyNames) {
							try {
								data.properties[prop] = propertyToString(el[prop]);
							} catch (_) {
								data.properties[prop] = "";
							}
						}

						results[sel].push(data);
					}
				} catch (e) {
					console.warn("Invalid CSS selector:", sel, e.message);
				}
			}

			return results;
		})()
	`, string(selectorsJSON), string(propertiesJSON))

	rawResults, err := chromedp.Run(
		ctx,
		chromedp.Evaluate[map[string][]elementData](script),
	)

	if err != nil {
		return nil, err
	}

	return rawResults, nil
}
