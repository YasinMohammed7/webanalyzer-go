package webanalyze

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/bobesa/go-domain-util/domainutil"
)

const VERSION = "0.3.9"

var (
	timeout = 8 * time.Second
)

// Result type encapsulates the result information from a given host
type Result struct {
	Host     string        `json:"host"`
	Matches  []Match       `json:"matches"`
	Duration time.Duration `json:"duration"`
	Seconds  float64       `json:"seconds"`
	Error    error         `json:"error"`
}

// Match type encapsulates the App information from a match on a document
type Match struct {
	App               `json:"app"`
	AppName           string     `json:"app_name"`
	Matches           [][]string `json:"matches"`
	Version           string     `json:"version"`
	Confidence        int        `json:"confidence"`
	versionConfidence int
}

// WebAnalyzer types holds an analyzation job
type WebAnalyzer struct {
	appDefs   AppsDefinition
	catDefs   CategoriesDefinition
	scheduler chan *Job
	client    *http.Client
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

// NewWebAnalyzer initializes webanalyzer by passing a reader of the
// app definition and an schedulerChan, which allows the scanner to
// add scan jobs on its own
func NewWebAnalyzer(apps io.Reader, client *http.Client) (*WebAnalyzer, error) {
	wa := new(WebAnalyzer)

	if err := wa.loadApps(apps); err != nil {
		return nil, err
	}

	wa.client = client

	return wa, nil
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
	result, links, err := wa.process(job, wa.appDefs)
	t1 := time.Now()

	duration := t1.Sub(t0)
	seconds := duration.Seconds()

	res := Result{
		Host:     job.URL,
		Matches:  result,
		Duration: duration,
		Seconds:  seconds,
		Error:    err,
	}
	return res, links
}

func (wa *WebAnalyzer) CategoryById(cid int) string {
	if _, ok := wa.catDefs[strconv.Itoa(cid)]; !ok {
		return ""
	}

	return wa.catDefs[strconv.Itoa(cid)].Name
}

func fetchHost(urlStr string, client *http.Client) (*http.Response, error) {
	if client == nil {
		client = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				Proxy:           http.ProxyFromEnvironment,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
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
	fmt.Println("STATUS:", resp.StatusCode)
	fmt.Println("FINAL URL:", resp.Request.URL.String())
	fmt.Println("LOCATION:", resp.Header.Get("Location"))
	if err != nil {
		return nil, err
	}
	return resp, nil
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

	if searchSubdomain && !isSubdomain(base, u) {
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

	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		val, ok := s.Attr("href")
		if !ok {
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
	return domainutil.Domain(base.String()) == domainutil.Domain(u.String())
}

// do http request and analyze response
func (wa *WebAnalyzer) process(job *Job, appDefs AppsDefinition) ([]Match, []string, error) {
	var apps = make([]Match, 0)
	var err error

	var cookies []*http.Cookie
	var cookiesMap = make(map[string]string)
	var body []byte
	var headers http.Header
	var links []string

	baseURL, err := url.Parse(job.URL)
	if err != nil {
		return nil, links, fmt.Errorf("invalid URL %q: %w", job.URL, err)
	}

	// get response from host if allowed
	if job.forceNotDownload {
		body = job.Body
		headers = job.Headers
		cookies = job.Cookies
	} else {
		resp, err := fetchHost(job.URL, wa.client)
		if err != nil {
			return nil, links, fmt.Errorf("Failed to retrieve: %w", err)
		}

		defer resp.Body.Close()

		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, links, fmt.Errorf("failed to read response body: %w", err)
		}

		headers = resp.Header

		if job.followRedirect {
			if location := resp.Header.Get("Location"); location != "" {

				if u := resolveLink(baseURL, location, job.SearchSubdomain); u != "" {
					links = append(links, u)
				}
			}
		}

		cookies = resp.Cookies()
	}

	for _, c := range cookies {
		cookiesMap[c.Name] = c.Value
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return nil, links, err
	}

	// handle crawling
	if job.Crawl > 0 {

		for c, link := range parseLinks(doc, baseURL, job.SearchSubdomain) {
			if c >= job.Crawl {
				break
			}

			links = append(links, link)
		}
	}

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

	for appname, app := range appDefs {
		// TODO: Reduce complexity in this for-loop by functionalising out
		// the sub-loops and checks.

		findings := Match{
			App:     app,
			AppName: appname,
			Matches: make([][]string, 0),
		}

		html := string(body)

		// check raw html
		if m, v, c := findMatches(html, app.HTMLRegex); len(m) > 0 {
			findings.Matches = append(findings.Matches, m...)
			findings.updateConfidence(c)
			findings.updateVersion(v, c)
		}

		// check response header
		headerFindings, version, confidence := app.FindInHeaders(headers)
		findings.Matches = append(findings.Matches, headerFindings...)
		findings.updateConfidence(confidence)
		findings.updateVersion(version, confidence)

		// check url
		if m, v, c := findMatches(job.URL, app.URLRegex); len(m) > 0 {
			findings.Matches = append(findings.Matches, m...)
			findings.updateConfidence(c)
			findings.updateVersion(v, c)
		}

		// check script tags
		for _, script := range scriptSources {
			if m, v, c := findMatches(script, app.ScriptSrcRegex); len(m) > 0 {
				findings.Matches = append(findings.Matches, m...)
				findings.updateConfidence(c)
				findings.updateVersion(v, c)
			}
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

				findings.Matches = append(findings.Matches, matches...)
				findings.updateConfidence(confidence)
				findings.updateVersion(version, confidence)
			}
		}

		// check cookies
		for _, cookieRegex := range app.CookieRegex {
			if _, ok := cookiesMap[cookieRegex.Name]; ok {

				// if there is a regexp set, ensure it matches.
				// otherwise just add this as a match
				if cookieRegex.Regexp != nil {

					// only match single AppRegexp on this specific cookie
					if matches, version, confidence := findMatches(cookiesMap[cookieRegex.Name], []AppRegexp{cookieRegex}); len(matches) > 0 {
						findings.Matches = append(findings.Matches, matches...)
						findings.updateConfidence(confidence)
						findings.updateVersion(version, confidence)
					}

				} else {
					findings.Matches = append(findings.Matches, []string{cookieRegex.Name})
					findings.updateConfidence(cookieRegex.Confidence)
				}
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

	return apps, links, nil
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
			continue
		}

		for match != nil {
			groups := match.Groups()
			row := make([]string, 0, len(groups))
			for _, group := range groups {
				row = append(row, group.String())
			}
			matches = append(matches, row)
			match, err = r.Regexp.FindNextMatch(match)
			if err != nil {
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
