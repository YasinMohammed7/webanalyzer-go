package webanalyze

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dlclark/regexp2/v2"
)

const WappazlyerRoot = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src"
const githubAPI = "https://api.github.com/repos/enthec/webappanalyzer"

type App struct {
	Description      string                 `json:"description,omitempty"`
	OSS              bool                   `json:"oss,omitempty"`
	SaaS             bool                   `json:"saas,omitempty"`
	Pricing          StringArray            `json:"pricing,omitempty"`
	Cats             IntArray               `json:"cats"`
	CPE              string                 `json:"cpe,omitempty"`
	Cookies          map[string]string      `json:"cookies,omitempty"`
	JS               map[string]string      `json:"js,omitempty"`
	DOM              *DOM                   `json:"dom,omitempty"`
	DNS              map[string]StringArray `json:"dns,omitempty"`
	Headers          map[string]string      `json:"headers,omitempty"`
	HTML             StringArray            `json:"html,omitempty"`
	Text             StringArray            `json:"text,omitempty"`
	CSS              StringArray            `json:"css,omitempty"`
	Robots           StringArray            `json:"robots,omitempty"`
	Probe            map[string]string      `json:"probe,omitempty"`
	CertIssuer       string                 `json:"certIssuer,omitempty"`
	Excludes         StringArray            `json:"excludes,omitempty"`
	Implies          StringArray            `json:"implies,omitempty"`
	Requires         StringArray            `json:"requires,omitempty"`
	RequiresCategory IntArray               `json:"requiresCategory,omitempty"`
	Meta             map[string]StringArray `json:"meta,omitempty"`
	ScriptSrc        StringArray            `json:"scriptSrc,omitempty"`
	Scripts          StringArray            `json:"scripts,omitempty"`
	URL              StringArray            `json:"url,omitempty"`
	XHR              StringArray            `json:"xhr,omitempty"`
	Website          string                 `json:"website"`
	Icon             string                 `json:"icon,omitempty"`

	// Computed fields, not part of technologies JSON.
	// Runtime/computed data

	HTMLRegex       []AppRegexp            `json:"-"`
	ScriptsRegex    []AppRegexp            `json:"-"`
	ScriptSrcRegex  []AppRegexp            `json:"-"`
	TextRegex       []AppRegexp            `json:"-"`
	URLRegex        []AppRegexp            `json:"-"`
	HeaderRegex     []AppRegexp            `json:"-"`
	MetaRegex       []AppRegexp            `json:"-"`
	CookieRegex     []AppRegexp            `json:"-"`
	RobotsRegex     []AppRegexp            `json:"-"`
	ProbeRegex      []ProbeRegexp          `json:"-"`
	CertIssuerRegex []AppRegexp            `json:"-"`
	DNSRegex        map[string][]AppRegexp `json:"-"`
	JSRegex         []AppRegexp            `json:"-"`
	XHRRegex        []AppRegexp            `json:"-"`
	CSSRegex        []AppRegexp            `json:"-"`
	DOMRegex        CompiledDOM            `json:"-"`
}

type AppsIndex struct {
	Initial            []string
	RequiresByTech     map[string][]string
	RequiresByCategory map[int][]string
	ImpliesByTech      map[string][]Implication
}

type Implication struct {
	Name       string
	Version    string
	Confidence int
}

type ProbeRegexp struct {
	Path       string
	Regexp     AppRegexp
	ExistsOnly bool
}

// Category names defined by wappalyzer
type Category struct {
	Name     string   `json:"name"`
	Groups   []uint32 `json:"groups"`
	Priority uint32   `json:"priority"`
}

// AppsDefinition type encapsulates the json encoding of the whole technologies.json file
type AppsDefinition map[string]App

type CategoriesDefinition map[string]Category

type AppRegexp struct {
	Name       string
	Regexp     *regexp2.Regexp
	Pattern    string
	Version    string
	Confidence int
}

type DOMKind uint8

const (
	DOMKindNone DOMKind = iota
	DOMKindString
	DOMKindArray
	DOMKindRules
)

type DOMRule struct {
	Exists     string            `json:"exists,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
	Text       string            `json:"text,omitempty"`
}

type DOM struct {
	Kind  DOMKind
	Value string
	Array []string
	Rules map[string]DOMRule
}

// Add compiled rule structures to your package
type CompiledDOMRule struct {
	Selector   string
	Exists     *AppRegexp
	Attributes map[string]AppRegexp
	Properties map[string]AppRegexp
	Text       *AppRegexp
}

type CompiledDOM struct {
	Selectors []string
	Rules     []CompiledDOMRule
}

type Group struct {
	Name string `json:"name"`
}

type GroupsDefinition map[string]Group

type StringArray []string

type GitHubTreeResponse struct {
	Tree []struct {
		Path string `json:"path"`
		Type string `json:"type"`
		SHA  string `json:"sha"`
		Url  string `json:"url"`
	} `json:"tree"`
	Truncated bool `json:"truncated"`
}

func (d *DOM) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err == nil {
		d.Kind = DOMKindString
		d.Value = value
		return nil
	}

	var array []string
	if err := json.Unmarshal(data, &array); err == nil {
		d.Kind = DOMKindArray
		d.Array = array
		return nil
	}

	var rules map[string]DOMRule
	if err := json.Unmarshal(data, &rules); err == nil {
		d.Kind = DOMKindRules
		d.Rules = rules
		return nil
	}

	return fmt.Errorf("invalid dom value: %s", string(data))
}

func (d DOM) MarshalJSON() ([]byte, error) {

	switch d.Kind {
	case DOMKindString:
		return json.Marshal(d.Value)
	case DOMKindArray:
		return json.Marshal(d.Array)
	case DOMKindRules:
		return json.Marshal(d.Rules)
	case DOMKindNone:
		return []byte("null"), nil
	default:
		return nil, fmt.Errorf("invalid DOM kind: %d", d.Kind)
	}

}

func (t *StringArray) UnmarshalJSON(data []byte) error {
	var s string
	var sa []string

	if err := json.Unmarshal(data, &s); err == nil {
		*t = StringArray{s}
		return nil
	}
	if err := json.Unmarshal(data, &sa); err == nil {
		*t = StringArray(sa)
		return nil
	}
	return fmt.Errorf("expected string or StringArray, got: %s", string(data))

}

type IntArray []int

func (t *IntArray) UnmarshalJSON(data []byte) error {
	var n int
	var na []int

	if err := json.Unmarshal(data, &n); err == nil {
		*t = IntArray{n}
		return nil
	}
	if err := json.Unmarshal(data, &na); err == nil {
		*t = IntArray(na)
		return nil
	}
	return fmt.Errorf("expected int or []int, got %s", string(data))
}

func compileDOM(dom *DOM) CompiledDOM {
	var cDOM CompiledDOM

	switch dom.Kind {
	case DOMKindString:
		if dom.Value != "" {
			cDOM.Selectors = append(cDOM.Selectors, dom.Value)
		}

	case DOMKindArray:
		for _, selector := range dom.Array {
			if selector != "" {
				cDOM.Selectors = append(
					cDOM.Selectors,
					selector,
				)
			}
		}

	case DOMKindRules:
		for selector, rule := range dom.Rules {
			cRule := CompiledDOMRule{
				Selector: selector,
			}

			if rule.Exists != "" {
				if r, ok := compileAppRegexp("", rule.Exists); ok {
					cRule.Exists = &r
				}
			}

			cRule.Attributes = make(map[string]AppRegexp)
			for attr, pattern := range rule.Attributes {
				if r, ok := compileAppRegexp(attr, pattern); ok {
					cRule.Attributes[attr] = r
				}
			}

			cRule.Properties = make(map[string]AppRegexp)
			for prop, pattern := range rule.Properties {
				if r, ok := compileAppRegexp(prop, pattern); ok {
					cRule.Properties[prop] = r
				}
			}

			if rule.Text != "" {
				if r, ok := compileAppRegexp("", rule.Text); ok {
					cRule.Text = &r
				}
			}

			cDOM.Rules = append(cDOM.Rules, cRule)
		}
	}

	return cDOM
}

func (app *App) FindInHeaders(
	headers http.Header,
	findings *Match,
) {
	for _, headerRegex := range app.HeaderRegex {
		values := headers.Values(headerRegex.Name)

		for _, value := range values {
			if value == "" {
				continue
			}

			m, v, c := findMatches(
				value,
				[]AppRegexp{headerRegex},
			)

			if len(m) == 0 {
				continue
			}

			findings.addDetection(
				"header",
				headerRegex.Name,
				value,
				m,
				v,
				c,
			)
		}
	}
}

func downloadGroups() (map[string]Group, error) {
	url := fmt.Sprintf("%v/groups.json", WappazlyerRoot)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	m := make(map[string]Group)

	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, err
	}

	return m, nil
}

func downloadTechnologies() (map[string]App, error) {
	apps := make(map[string]App)

	files := StringArray{"_", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"}

	for _, f := range files {
		m := make(map[string]App)
		url := fmt.Sprintf("%v/technologies/%v.json", WappazlyerRoot, f)
		resp, err := http.Get(url)
		if err != nil {
			return nil, err
		}
		if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
			resp.Body.Close()
			return nil, err
		}

		maps.Copy(apps, m)
		resp.Body.Close()
	}

	return apps, nil
}

func downloadCategories() (map[string]Category, error) {

	url := fmt.Sprintf("%v/categories.json", WappazlyerRoot)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	m := make(map[string]Category)

	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, err
	}

	return m, nil
}

func getLocalIconsSHA() (string, error) {
	data, err := os.ReadFile("icons_version.txt")
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}

	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(data)), nil
}

func saveLocalIconsSHA(sha string) error {
	return os.WriteFile(
		"icons_version.txt",
		[]byte(sha+"\n"),
		0644,
	)
}

func getLatestCommitSHA(client *http.Client) (string, error) {
	url := githubAPI + "/commits/main"

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "webanalyze")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned: %s", resp.Status)
	}

	var commit struct {
		SHA string `json:"sha"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&commit); err != nil {
		return "", err
	}

	if commit.SHA == "" {
		return "", errors.New("GitHub returned an empty commit SHA")
	}

	return commit.SHA, nil
}

func getRemoteIconsSHA() (string, string, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	commitSHA, err := getLatestCommitSHA(client)
	if err != nil {
		return "", "", fmt.Errorf("get latest commit: %w", err)
	}

	url := fmt.Sprintf(
		"%s/git/trees/%s?recursive=1",
		githubAPI,
		commitSHA,
	)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", "", err
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "webanalyze")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("GitHub API returned: %s", resp.Status)
	}

	var result GitHubTreeResponse

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", err
	}

	if result.Truncated {
		return "", "", errors.New("GitHub tree response was truncated")
	}

	for _, entry := range result.Tree {
		if entry.Path == "src/images/icons" && entry.Type == "tree" {
			return entry.SHA, commitSHA, nil
		}
	}

	return "", "", errors.New("icons directory not found in GitHub repository")
}

func extractIcons(reader *zip.Reader, destination string) error {
	const iconsPath = "src/images/icons/"

	extracted := 0

	for _, file := range reader.File {
		index := strings.Index(file.Name, iconsPath)
		if index == -1 {
			continue
		}

		relativePath := file.Name[index+len(iconsPath):]
		if relativePath == "" {
			continue
		}

		cleanPath := filepath.Clean(filepath.FromSlash(relativePath))
		if !filepath.IsLocal(cleanPath) {
			return fmt.Errorf("invalid ZIP path: %s", file.Name)
		}

		target := filepath.Join(destination, cleanPath)

		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
			continue
		}

		// Skip symlinks and other non-regular files.
		if !file.Mode().IsRegular() {
			continue
		}

		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}

		if err := extractZipFile(file, target); err != nil {
			return err
		}

		extracted++
	}

	if extracted == 0 {
		return errors.New("no icons found in ZIP archive")
	}

	log.Printf("Extracted %d icons", extracted)
	return nil
}

func extractZipFile(file *zip.File, destination string) error {
	src, err := file.Open()
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.OpenFile(
		destination,
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
		0644,
	)
	if err != nil {
		return err
	}

	_, copyErr := io.Copy(dst, src)
	closeErr := dst.Close()

	if copyErr != nil {
		return copyErr
	}

	return closeErr
}

func replaceIconsDirectory(tempDir string) error {
	const iconsDir = "icons"

	backupDir, err := os.MkdirTemp(".", ".icons-backup-*")
	if err != nil {
		return err
	}

	if err := os.Remove(backupDir); err != nil {
		return err
	}

	oldIconsExist := false

	if _, err := os.Stat(iconsDir); err == nil {
		if err := os.Rename(iconsDir, backupDir); err != nil {
			return fmt.Errorf("cannot backup existing icons: %w", err)
		}
		oldIconsExist = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	if err := os.Rename(tempDir, iconsDir); err != nil {
		if oldIconsExist {
			if restoreErr := os.Rename(backupDir, iconsDir); restoreErr != nil {
				return fmt.Errorf(
					"cannot install new icons: %w; cannot restore backup: %v",
					err,
					restoreErr,
				)
			}
		}
		return err
	}

	if oldIconsExist {
		if err := os.RemoveAll(backupDir); err != nil {
			log.Printf("warning: cannot remove old icons backup: %v", err)
		}
	}

	return nil
}

func DownloadIcons() error {
	client := &http.Client{
		Timeout: 2 * time.Minute,
	}

	remoteSHA, commitSHA, err := getRemoteIconsSHA()
	if err != nil {
		return fmt.Errorf("cannot check icons version: %w", err)
	}

	localSHA, err := getLocalIconsSHA()
	if err != nil {
		return fmt.Errorf("failed to read local icons version: %w", err)
	}

	if localSHA == remoteSHA {
		if _, err := os.Stat("icons"); err == nil {
			log.Println("Icons are already up to date")
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("cannot check icons directory: %w", err)
		}
	}

	log.Println("Icons have changed. Downloading...")

	url := fmt.Sprintf(
		"%s/zipball/%s",
		githubAPI,
		commitSHA,
	)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "webanalyze")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub returned status: %s", resp.Status)
	}

	// Download ZIP to a temporary file.
	zipFile, err := os.CreateTemp("", "webanalyze-*.zip")
	if err != nil {
		return err
	}

	zipPath := zipFile.Name()
	defer os.Remove(zipPath)

	_, copyErr := io.Copy(zipFile, resp.Body)
	closeErr := zipFile.Close()

	if copyErr != nil {
		return fmt.Errorf("failed to download ZIP: %w", copyErr)
	}
	if closeErr != nil {
		return closeErr
	}

	// Open ZIP archive.
	archive, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open ZIP archive: %w", err)
	}
	defer archive.Close()

	// Extract icons into a temporary directory.
	tempDir, err := os.MkdirTemp(".", ".icons-tmp-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)

	if err := extractIcons(&archive.Reader, tempDir); err != nil {
		return fmt.Errorf("failed to extract icons: %w", err)
	}

	// Replace existing icons.
	if err := replaceIconsDirectory(tempDir); err != nil {
		return fmt.Errorf("failed to replace icons: %w", err)
	}

	// Save SHA only after successful installation.
	if err := saveLocalIconsSHA(remoteSHA); err != nil {
		return fmt.Errorf("failed to save icons version: %w", err)
	}

	log.Println("Icons successfully updated")

	return nil
}

// DownloadFile pulls the latest technologies.json file from the Wappalyzer github
func DownloadFile(categoriesPath string, technologiesPath string, groupsPath string) error {
	// Step 1: Download categories
	categories, err := downloadCategories()
	if err != nil {
		return fmt.Errorf("failed to download categories: %w", err)
	}

	// Step 2: Download technologies
	appDefs, err := downloadTechnologies()
	if err != nil {
		return fmt.Errorf("failed to download technologies: %w", err)
	}

	groups, err := downloadGroups()
	if err != nil {
		return fmt.Errorf("failed to download groups: %w", err)
	}

	// Step 3: Marshal and write groups
	groupsData, err := json.MarshalIndent(groups, "", " ")
	if err != nil {
		return fmt.Errorf("failed to marshal groups: %w", err)
	}
	if err := os.WriteFile(groupsPath, groupsData, 0644); err != nil {
		return fmt.Errorf("failed to write groups file: %w", err)
	}

	// Step 4: Marshal and write categories
	categoriesData, err := json.MarshalIndent(categories, "", " ")
	if err != nil {
		return fmt.Errorf("failed to marshal categories: %w", err)
	}
	if err := os.WriteFile(categoriesPath, categoriesData, 0644); err != nil {
		return fmt.Errorf("failed to write categories file: %w", err)
	}

	// Step 5: Marshal and write technologies
	technologiesData, err := json.MarshalIndent(appDefs, "", " ")
	if err != nil {
		return fmt.Errorf("failed to marshal technologies: %w", err)
	}
	if err := os.WriteFile(technologiesPath, technologiesData, 0644); err != nil {
		return fmt.Errorf("failed to write technologies file: %w", err)
	}

	err = DownloadIcons()
	if err != nil {
		return fmt.Errorf("failed to download icons: %w", err)
	}

	return nil
}

// load apps from io.Reader
func (wa *WebAnalyzer) loadApps(r io.Reader) error {
	dec := json.NewDecoder(r)
	if err := dec.Decode(&wa.appDefs); err != nil {
		return err
	}

	jsPaths := make(map[string]struct{})
	domSelectorsMap := make(map[string]struct{})

	wa.scriptRegexes = make(map[string][]AppRegexp)
	wa.cssRegexes = make(map[string][]AppRegexp)
	wa.domProperties = make(map[string][]string)

	wa.appsIndex = AppsIndex{
		Initial:            make([]string, 0),
		RequiresByTech:     make(map[string][]string),
		RequiresByCategory: make(map[int][]string),
		ImpliesByTech:      make(map[string][]Implication),
	}

	for key, value := range wa.appDefs {
		app := wa.appDefs[key]

		app.HTMLRegex = compileRegexes(value.HTML)
		app.ScriptsRegex = compileRegexes(value.Scripts)
		app.ScriptSrcRegex = compileRegexes(value.ScriptSrc)
		app.URLRegex = compileRegexes(value.URL)
		app.TextRegex = compileRegexes(value.Text)
		app.RobotsRegex = compileRegexes(value.Robots)
		app.ProbeRegex = compileProbeRegexes(value.Probe)
		app.XHRRegex = compileRegexes(value.XHR)
		app.CSSRegex = compileRegexes(value.CSS)

		if value.CertIssuer != "" {
			if r, ok := compileAppRegexp("", value.CertIssuer); ok {
				app.CertIssuerRegex = []AppRegexp{r}
			}
		}

		app.HeaderRegex = compileNamedRegexes(app.Headers)
		app.CookieRegex = compileNamedRegexes(app.Cookies)
		app.JSRegex = compileNamedRegexes(app.JS)

		app.MetaRegex = compileNamedRegexArrays(app.Meta)

		app.DNSRegex = make(map[string][]AppRegexp)

		for recordType, patterns := range value.DNS {
			app.DNSRegex[recordType] = compileRegexes(patterns)
		}

		// collect unique JavaScript paths
		for _, jsRegex := range app.JSRegex {
			jsPaths[jsRegex.Name] = struct{}{}
		}

		if len(app.ScriptsRegex) > 0 {
			wa.scriptRegexes[key] = app.ScriptsRegex
		}

		if len(app.CSSRegex) > 0 {
			wa.cssRegexes[key] = app.CSSRegex
		}

		if value.DOM != nil {
			app.DOMRegex = compileDOM(value.DOM)
			// Collect simple selectors
			for _, selector := range app.DOMRegex.Selectors {
				domSelectorsMap[selector] = struct{}{}
			}
			// Collect rule-based selectors
			for _, rule := range app.DOMRegex.Rules {
				domSelectorsMap[rule.Selector] = struct{}{}

				for propertyName := range rule.Properties {

					if !slices.Contains(wa.domProperties[rule.Selector], propertyName) {
						wa.domProperties[rule.Selector] = append(
							wa.domProperties[rule.Selector],
							propertyName,
						)
					}
				}
			}
		}

		wa.appDefs[key] = app

		// Build the indexes.
		if len(app.Requires) == 0 && len(app.RequiresCategory) == 0 {
			wa.appsIndex.Initial = append(wa.appsIndex.Initial, key)
		}

		for _, requiredTech := range app.Requires {
			wa.appsIndex.RequiresByTech[requiredTech] =
				append(wa.appsIndex.RequiresByTech[requiredTech], key)
		}

		for _, categoryID := range app.RequiresCategory {
			wa.appsIndex.RequiresByCategory[categoryID] =
				append(wa.appsIndex.RequiresByCategory[categoryID], key)
		}

		for _, impliedTech := range app.Implies {
			parts := strings.Split(impliedTech, `\;`)
			implied := Implication{
				Name:       strings.TrimSpace(parts[0]),
				Confidence: 100,
			}
			for _, attribute := range parts[1:] {
				if version, ok := strings.CutPrefix(attribute, "version:"); ok {
					implied.Version = version
				} else if value, ok := strings.CutPrefix(attribute, "confidence:"); ok {
					if confidence, err := strconv.Atoi(value); err == nil {
						implied.Confidence = max(0, min(100, confidence))
					}
				}
			}
			wa.appsIndex.ImpliesByTech[key] =
				append(wa.appsIndex.ImpliesByTech[key], implied)
		}

	}

	wa.jsPaths = make([]string, 0, len(jsPaths))
	for path := range jsPaths {
		wa.jsPaths = append(wa.jsPaths, path)
	}

	// POPULATE WA.DOMSELECTORS:
	wa.domSelectors = make([]string, 0, len(domSelectorsMap))
	for sel := range domSelectorsMap {
		wa.domSelectors = append(wa.domSelectors, sel)
	}

	return nil
}

func (wa *WebAnalyzer) loadCategories(r io.Reader) error {
	return json.NewDecoder(r).Decode(&wa.catDefs)
}

func (wa *WebAnalyzer) loadGroups(r io.Reader) error {
	return json.NewDecoder(r).Decode(&wa.groupDefs)
}

func compileNamedRegexes(from map[string]string) []AppRegexp {
	var list []AppRegexp

	for key, value := range from {
		appRegexp, ok := compileAppRegexp(key, value)
		if !ok {
			continue
		}

		list = append(list, appRegexp)
	}

	return list
}

func compileRegexes(values StringArray) []AppRegexp {
	var list []AppRegexp

	for _, value := range values {

		appRegexp, ok := compileAppRegexp("", value)
		if !ok {
			continue
		}

		list = append(list, appRegexp)
	}

	return list
}

func compileNamedRegexArrays(from map[string]StringArray) []AppRegexp {
	var list []AppRegexp

	for key, values := range from {
		for _, value := range values {
			appRegexp, ok := compileAppRegexp(key, value)
			if !ok {
				continue
			}

			list = append(list, appRegexp)
		}
	}

	return list
}

func normalizeRegex(pattern string) string {
	pattern = strings.ReplaceAll(pattern, `\_`, `_`)
	return pattern
}

// helper regex function to find matches in a string and return the version and confidence if applicable
func compileAppRegexp(name, value string) (AppRegexp, bool) {
	if value == "" {
		value = "^.*$"
	}

	parts := strings.Split(value, "\\;")

	pattern := normalizeRegex(parts[0])

	r, err := regexp2.Compile(pattern, regexp2.IgnoreCase)
	if err != nil {
		log.Printf("warning: failed to compile regex %q: %v", value, err)
		return AppRegexp{}, false
	}

	appRegexp := AppRegexp{
		Name:       name,
		Regexp:     r,
		Confidence: 100,
		Pattern:    pattern,
	}

	for _, attr := range parts[1:] {
		switch {
		case strings.HasPrefix(attr, "version:"):
			appRegexp.Version = strings.TrimPrefix(attr, "version:")

		case strings.HasPrefix(attr, "confidence:"):
			confidence, err := strconv.Atoi(
				strings.TrimPrefix(attr, "confidence:"),
			)
			if err == nil {
				appRegexp.Confidence = confidence
			}
		}
	}

	return appRegexp, true
}

func compileProbeRegexes(probes map[string]string) []ProbeRegexp {
	compiled := make([]ProbeRegexp, 0, len(probes))

	for path, value := range probes {
		if value == "" {
			compiled = append(compiled, ProbeRegexp{
				Path:       path,
				ExistsOnly: true,
			})

			continue
		}

		r, ok := compileAppRegexp(path, value)
		if !ok {
			continue
		}

		compiled = append(compiled, ProbeRegexp{
			Path:   path,
			Regexp: r,
		})
	}

	return compiled
}
