package webanalyze

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/bobesa/go-domain-util/domainutil"
	"github.com/chromedp/chromedp"
)

const VERSION = "0.3.9"

var (
	timeout = 8 * time.Second
)

// Result type encapsulates the result information from a given host
type Result struct {
	Host              string        `json:"host"`
	FinalURL          string        `json:"final_url"`
	Technologies      []Match       `json:"technologies"`
	TechnologiesCount int           `json:"technologies_count"`
	Duration          time.Duration `json:"duration"`
	Seconds           float64       `json:"seconds"`
	Error             error         `json:"error"`
}

type MatchCategory struct {
	ID     uint32   `json:"id"`
	Name   string   `json:"name"`
	Groups []string `json:"groups"`
}

type DetectionMatch struct {
	Type       string     `json:"type"`
	Name       string     `json:"name,omitempty"`
	Value      string     `json:"value,omitempty"`
	Matches    [][]string `json:"matches,omitempty"`
	Confidence int        `json:"confidence"`
}

// Match type encapsulates the App information from a match on a document
type Match struct {
	AppName           string `json:"app_name"`
	App               `json:"app"`
	Matches           []DetectionMatch `json:"matches"`
	Version           string           `json:"version"`
	Confidence        int              `json:"confidence"`
	Categories        []MatchCategory  `json:"categories"`
	versionConfidence int
}

// WebAnalyzer types holds an analyzation job
type WebAnalyzer struct {
	appDefs   AppsDefinition
	catDefs   CategoriesDefinition
	groupDefs GroupsDefinition
	client    *http.Client
	browser   *Browser

	jsPaths []string
}

type DNSResult map[string][]string

type JSResult struct {
	Value  string
	Exists bool
}

func (m *Match) updateVersion(version string, confidence int) {

	if version == "" {
		return
	}
	if m.Version == "" || confidence > m.versionConfidence {
		m.Version = version
		m.versionConfidence = confidence
	}

}

func (m *Match) updateConfidence(confidence int) {
	if confidence > m.Confidence {
		m.Confidence = confidence
	}
}

func (m *Match) addDetection(
	detectionType string,
	name string,
	value string,
	matches [][]string,
	version string,
	confidence int,
) {
	m.Matches = append(m.Matches, DetectionMatch{
		Type:       detectionType,
		Name:       name,
		Value:      value,
		Matches:    matches,
		Confidence: confidence,
	})

	m.updateConfidence(confidence)
	m.updateVersion(version, confidence)
}

// NewWebAnalyzer initializes webanalyzer by passing a reader of the
// app definition and an schedulerChan, which allows the scanner to
// add scan jobs on its own
func NewWebAnalyzer(apps io.Reader, categories io.Reader, groups io.Reader, client *http.Client) (*WebAnalyzer, error) {
	wa := new(WebAnalyzer)

	if err := wa.loadApps(apps); err != nil {
		return nil, err
	}

	if err := wa.loadCategories(categories); err != nil {

		return nil, err
	}

	if err := wa.loadGroups(groups); err != nil {
		return nil, err
	}

	wa.client = client

	return wa, nil
}

func (wa *WebAnalyzer) EnableBrowser() error {

	if wa.browser != nil {
		return nil
	}
	browser, err := NewBrowser()
	if err != nil {
		return err
	}
	wa.browser = browser
	return nil

}

func (wa *WebAnalyzer) CloseBrowser() {

	if wa.browser == nil {
		return
	}
	wa.browser.Close()
	wa.browser = nil

}

func (wa *WebAnalyzer) resolveCategories(app App) []MatchCategory {
	var result []MatchCategory

	for _, catID := range app.Cats {
		category, ok := wa.catDefs[strconv.Itoa(int(catID))]
		if !ok {
			continue
		}

		var groupNames []string

		for _, groupID := range category.Groups {
			group, ok := wa.groupDefs[strconv.Itoa(int(groupID))]
			if !ok {
				continue
			}

			groupNames = append(groupNames, group.Name)
		}

		result = append(result, MatchCategory{
			ID:     uint32(catID),
			Name:   category.Name,
			Groups: groupNames,
		})
	}

	return result
}

// worker loops until channel is closed. processes a single host at once
func (wa *WebAnalyzer) Process(job *Job) (Result, []string) {

	// fix missing http scheme
	u, err := url.Parse(job.URL)
	if err != nil {
		return Result{Host: job.URL, Error: err}, []string{}
	}

	if u.Scheme == "" {
		u.Scheme = "http"
	}
	job.URL = u.String()

	// measure time
	t0 := time.Now()
	result, links, finalURL, err := wa.process(job, wa.appDefs)
	t1 := time.Now()

	resultCount := len(result)

	duration := t1.Sub(t0)
	seconds := duration.Seconds()

	res := Result{
		Host:              job.URL,
		FinalURL:          finalURL,
		Technologies:      result,
		TechnologiesCount: resultCount,
		Duration:          duration,
		Seconds:           seconds,
		Error:             err,
	}
	return res, links
}

func (wa *WebAnalyzer) CategoryById(cid int) string {
	if _, ok := wa.catDefs[strconv.Itoa(cid)]; !ok {
		return ""
	}

	return wa.catDefs[strconv.Itoa(cid)].Name
}

func fetchHost(urlStr string, client *http.Client, followRedirect bool) (*http.Response, error) {
	if client == nil {
		client = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				Proxy:           http.ProxyFromEnvironment,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if !followRedirect {

					return http.ErrUseLastResponse
				}

				if len(via) >= 10 {

					return errors.New("too many redirects")

				}

				baseURL, err := url.Parse(urlStr)
				if err != nil {
					return http.ErrUseLastResponse
				}

				if !isSubdomain(baseURL, req.URL) {
					return http.ErrUseLastResponse
				}

				return nil
			},
		}
	}
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Accept", "*/*")

	resp, err := client.Do(req)

	if err != nil {
		return nil, err
	}

	fmt.Println("STATUS:", resp.StatusCode)
	fmt.Println("FINAL URL:", resp.Request.URL.String())
	fmt.Println("LOCATION:", resp.Header.Get("Location"))

	return resp, nil
}

func fetchDNS(domain string) DNSResult {
	result := make(DNSResult)

	if mxRecords, err := net.LookupMX(domain); err == nil {
		for _, mx := range mxRecords {
			result["MX"] = append(
				result["MX"],
				strings.TrimSuffix(mx.Host, "."),
			)
		}
	}

	if nsRecords, err := net.LookupNS(domain); err == nil {
		for _, ns := range nsRecords {
			result["NS"] = append(
				result["NS"],
				strings.TrimSuffix(ns.Host, "."),
			)
		}
	}

	if txtRecords, err := net.LookupTXT(domain); err == nil {
		result["TXT"] = append(
			result["TXT"],
			txtRecords...,
		)
	}

	return result
}

func unique(strSlice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range strSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func sameUrl(u1, u2 *url.URL) bool {
	return u1.Hostname() == u2.Hostname() &&
		u1.Port() == u2.Port() &&
		u1.RequestURI() == u2.RequestURI()
}

func resolveLink(base *url.URL, val string, searchSubdomain bool) string {
	u, err := url.Parse(val)
	if err != nil {
		return ""
	}

	urlResolved := base.ResolveReference(u)

	if !searchSubdomain && urlResolved.Hostname() != base.Hostname() {
		return ""
	}

	if searchSubdomain && !isSubdomain(base, urlResolved) {
		return ""
	}

	if urlResolved.RequestURI() == "" {
		urlResolved.Path = "/"
	}

	if sameUrl(base, urlResolved) {
		return ""
	}

	// only allow http/https
	if urlResolved.Scheme != "http" && urlResolved.Scheme != "https" {
		return ""
	}

	return urlResolved.String()
}

func parseLinks(doc *goquery.Document, base *url.URL, searchSubdomain bool) []string {
	var links []string

	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		val, _ := s.Attr("href")
		val = strings.TrimSpace(val)
		if val == "" {
			return
		}

		u := resolveLink(base, val, searchSubdomain)
		if u != "" {
			links = append(links, u)
		}
	})

	return unique(links)
}

func isSubdomain(base, u *url.URL) bool {
	baseDomain := domainutil.Domain(base.Hostname())
	targetDomain := domainutil.Domain(u.Hostname())

	return baseDomain != "" && targetDomain != "" && baseDomain == targetDomain
}

func (wa *WebAnalyzer) crawlBFS(job *Job) []Result {
	queue := []string{job.URL}

	seen := map[string]bool{
		job.URL: true,
	}

	var results []Result

	for len(queue) > 0 {
		currentURL := queue[0]
		queue = queue[1:]

		pageJob := NewOnlineJob(
			currentURL,
			"",
			nil,
			0, // important: Process only this page
			job.SearchSubdomain,
			job.followRedirect,
		)

		result, links := wa.Process(pageJob)

		results = append(results, result)

		if result.Error == nil {
			for _, link := range links {
				if seen[link] {
					continue
				}

				seen[link] = true
				queue = append(queue, link)
			}
		}

		if job.Crawl > 0 && len(results) >= job.Crawl {
			break
		}
	}

	return results
}

func (wa *WebAnalyzer) Crawl(job *Job) []Result {
	return wa.crawlBFS(job)
}

func fetchRobots(
	baseURL *url.URL,
	client *http.Client,
	followRedirect bool,
) string {

	u := *baseURL
	u.Path = "/robots.txt"
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""

	resp, err := fetchHost(
		u.String(),
		client,
		followRedirect,
	)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ""
	}

	body, err := io.ReadAll(
		io.LimitReader(resp.Body, 1<<20),
	)
	if err != nil {
		return ""
	}

	return string(body)
}

// do http request and analyze response
func (wa *WebAnalyzer) process(job *Job, appDefs AppsDefinition) ([]Match, []string, string, error) {
	var apps = make([]Match, 0)
	var err error

	var cookies []*http.Cookie
	var cookiesMap = make(map[string]string)
	var body []byte
	var headers http.Header
	var links []string
	var finalURL string
	var robotsText string
	var certIssuer string

	baseURL, err := url.Parse(job.URL)
	if err != nil {
		return nil, links, "", fmt.Errorf("invalid URL %q: %w", job.URL, err)
	}

	// get response from host if allowed
	if job.forceNotDownload {
		body = job.Body
		headers = job.Headers
		cookies = job.Cookies
	} else {
		resp, err := fetchHost(job.URL, wa.client, job.followRedirect)
		if err != nil {
			return nil, links, "", fmt.Errorf("Failed to retrieve: %w", err)
		}

		finalURL = resp.Request.URL.String()
		baseURL = resp.Request.URL

		if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			certIssuer = resp.TLS.PeerCertificates[0].Issuer.String()
		}

		defer resp.Body.Close()

		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, links, "", fmt.Errorf("failed to read response body: %w", err)
		}

		headers = resp.Header

		cookies = resp.Cookies()
	}

	for _, c := range cookies {
		cookiesMap[c.Name] = c.Value
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return nil, links, "", err
	}

	links = parseLinks(doc, baseURL, job.SearchSubdomain)

	textDoc := doc.Selection.Clone()

	textDoc.Find("script, style, noscript").Remove()

	pageText := strings.Join(strings.Fields(textDoc.Text()), " ")

	var scriptSources []string

	doc.Find("script[src]").Each(func(_ int, s *goquery.Selection) {
		if src, exists := s.Attr("src"); exists {
			scriptSources = append(scriptSources, src)
		}
	})

	metaTags := make(map[string][]string)

	doc.Find("meta").Each(func(_ int, s *goquery.Selection) {
		name, exists := s.Attr("name")
		if !exists {
			return
		}

		content, exists := s.Attr("content")
		if !exists {
			return
		}

		name = strings.ToLower(strings.TrimSpace(name))

		metaTags[name] = append(metaTags[name], content)
	})

	html := string(body)

	dnsDomain := domainutil.Domain(baseURL.String())
	dnsResults := fetchDNS(dnsDomain)

	if !job.forceNotDownload {
		robotsText = fetchRobots(baseURL, wa.client, job.followRedirect)
	}

	jsResults := make(map[string]JSResult)

	if wa.browser != nil && !job.forceNotDownload {

		browserCtx, browserCancel := wa.browser.NewTab()
		defer browserCancel()
		pageURL := finalURL
		if pageURL == "" {
			pageURL = job.URL
		}
		err := chromedp.Do(
			browserCtx,
			chromedp.Navigate(pageURL),
			chromedp.WaitReady(chromedp.CSS("body")),
		)
		if err == nil {
			results, err := wa.collectJSResults(browserCtx)
			if err == nil {
				jsResults = results
			}
		}

	}

	for appname, app := range appDefs {

		findings := Match{
			App:        app,
			AppName:    appname,
			Matches:    make([]DetectionMatch, 0),
			Categories: wa.resolveCategories(app),
		}

		// check raw HTML
		if m, v, c := findMatches(html, app.HTMLRegex); len(m) > 0 {
			findings.addDetection(
				"html",
				"",
				"",
				m,
				v,
				c,
			)
		}

		// check response headers
		app.FindInHeaders(headers, &findings)

		// check url
		if m, v, c := findMatches(job.URL, app.URLRegex); len(m) > 0 {
			findings.addDetection(
				"url",
				"",
				job.URL,
				m,
				v,
				c,
			)

		}

		// check text

		if m, v, c := findMatches(pageText, app.TextRegex); len(m) > 0 {
			findings.addDetection(
				"text",
				"",
				"",
				m,
				v,
				c,
			)
		}

		// check robots.txt
		if m, v, c := findMatches(robotsText, app.RobotsRegex); len(m) > 0 {
			findings.addDetection(
				"robots",
				"",
				"",
				m,
				v,
				c,
			)
		}

		// check script sources
		for _, script := range scriptSources {
			if m, v, c := findMatches(
				script,
				app.ScriptSrcRegex,
			); len(m) > 0 {
				findings.addDetection(
					"scriptSrc",
					"",
					script,
					m,
					v,
					c,
				)
			}
		}

		// check TLS certificate issuer
		if m, v, c := findMatches(certIssuer, app.CertIssuerRegex); len(m) > 0 {
			findings.addDetection(
				"certIssuer",
				"",
				certIssuer,
				m,
				v,
				c,
			)
		}

		// check meta tags
		for _, metaRegex := range app.MetaRegex {
			contents, ok := metaTags[strings.ToLower(metaRegex.Name)]
			if !ok {
				continue
			}

			for _, content := range contents {
				matches, version, confidence := findMatches(
					content,
					[]AppRegexp{metaRegex},
				)

				if len(matches) == 0 {
					continue
				}

				findings.addDetection(
					"meta",
					metaRegex.Name,
					content,
					matches,
					version,
					confidence,
				)
			}
		}

		// check cookies
		for _, cookieRegex := range app.CookieRegex {
			value, ok := cookiesMap[cookieRegex.Name]
			if !ok {
				continue
			}

			m, v, c := findMatches(
				value,
				[]AppRegexp{cookieRegex},
			)

			if len(m) == 0 {
				continue
			}

			findings.addDetection(
				"cookie",
				cookieRegex.Name,
				value,
				m,
				v,
				c,
			)
		}

		// check DNS
		for recordType, regexes := range app.DNSRegex {
			values := dnsResults[recordType]

			for _, value := range values {
				if m, v, c := findMatches(
					value,
					regexes,
				); len(m) > 0 {
					findings.addDetection(
						"dns",
						recordType,
						value,
						m,
						v,
						c,
					)
				}
			}
		}

		// check JS properties if browser is enabled

		for _, jsRegex := range app.JSRegex {
			result, ok := jsResults[jsRegex.Name]

			if !ok || !result.Exists {
				continue
			}

			if m, v, c := findMatches(
				result.Value,
				[]AppRegexp{jsRegex},
			); len(m) > 0 {
				findings.addDetection(
					"js",
					jsRegex.Name,
					result.Value,
					m,
					v,
					c,
				)
			}
		}

		if len(findings.Matches) > 0 {
			apps = append(apps, findings)

			// for _, impliedName := range app.Implies {

			// 	if impliedApp, ok := appDefs[impliedName]; ok {
			// 		f2 := Match{
			// 			App:     impliedApp,
			// 			AppName: impliedName,
			// 			Matches: make([][]string, 0),
			// 		}
			// 		apps = append(apps, f2)
			// 	}

			// }
		}
	}

	return apps, links, finalURL, nil
}

func (wa *WebAnalyzer) collectJSResults(
	ctx context.Context,
) (map[string]JSResult, error) {

	results := make(map[string]JSResult)

	checkpoints := []time.Duration{
		0,
		500 * time.Millisecond,
		1 * time.Second,
		1500 * time.Millisecond,
	}

	start := time.Now()

	for _, checkpoint := range checkpoints {
		wait := checkpoint - time.Since(start)

		if wait > 0 {
			timer := time.NewTimer(wait)

			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return results, ctx.Err()
			}
		}

		// Only check properties that haven't been found yet.
		missing := make([]string, 0)

		for _, path := range wa.jsPaths {
			result, ok := results[path]

			if !ok || !result.Exists {
				missing = append(missing, path)
			}
		}

		if len(missing) == 0 {
			break
		}

		current, err := wa.browser.GetJSProperties(
			ctx,
			missing,
		)
		if err != nil {
			return results, err
		}

		for path, result := range current {
			if result.Exists {
				results[path] = result
			}
		}
	}

	return results, nil
}

// runs a list of regexes on content
func findMatches(content string, regexes []AppRegexp) ([][]string, string, int) {
	var m [][]string
	var version string
	var confidence int

	for _, r := range regexes {
		var matches [][]string

		match, err := r.Regexp.FindStringMatch(content)
		if err != nil {
			fmt.Printf(
				"REGEX ERROR name=%q pattern=%q error=%v\n",
				r.Name,
				r.Pattern,
				err,
			)
			continue
		}

		for match != nil {
			groups := match.Groups()

			row := make([]string, 0, len(groups))

			for _, group := range groups {

				if len(group.Captures) == 0 {
					row = append(row, "")
					continue
				}

				value := group.String()

				row = append(row, value)
			}

			matches = append(matches, row)

			match, err = r.Regexp.FindNextMatch(match)
			if err != nil {
				fmt.Printf(
					"NEXT MATCH ERROR name=%q pattern=%q error=%v\n",
					r.Name,
					r.Pattern,
					err,
				)
				break
			}
		}

		if len(matches) == 0 {
			continue
		}

		m = append(m, matches...)

		if r.Version != "" {
			version = findVersion(matches, r.Version)
		}

		if r.Confidence > confidence {
			confidence = r.Confidence
		}
	}

	return m, version, confidence
}

// parses a version against matches
func findVersion(matches [][]string, version string) string {
	for _, matchPair := range matches {
		v := version

		for i := 1; i < len(matchPair); i++ {
			bt := fmt.Sprintf("\\%d", i)

			if strings.Contains(v, bt) {
				v = strings.ReplaceAll(v, bt, matchPair[i])
			}
		}

		if v != version {
			return v
		}
	}

	return ""
}
