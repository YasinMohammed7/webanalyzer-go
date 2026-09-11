package webanalyze

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
)

const WappazlyerRoot = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src"

type App struct {
	Description      string                 `json:"description,omitempty"`
	OSS              bool                   `json:"oss,omitempty"`
	SaaS             bool                   `json:"saas,omitempty"`
	Pricing          StringArray            `json:"pricing,omitempty"`
	Cats             IntArray               `json:"cats"`
	CPE              string                 `json:"cpe,omitempty"`
	Cookies          map[string]string      `json:"cookies,omitempty"`
	JS               map[string]string      `json:"js,omitempty"`
	DOM              DOM                    `json:"dom,omitempty"`
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

	CatNames       []string    `json:"-"`
	HTMLRegex      []AppRegexp `json:"-"`
	ScriptRegex    []AppRegexp `json:"-"`
	ScriptSrcRegex []AppRegexp `json:"-"`
	URLRegex       []AppRegexp `json:"-"`
	HeaderRegex    []AppRegexp `json:"-"`
	MetaRegex      []AppRegexp `json:"-"`
	CookieRegex    []AppRegexp `json:"-"`
}

// Category names defined by wappalyzer
type Category struct {
	Name     string   `json:"name"`
	Groups   []uint32 `json:"groups"`
	Priority uint32   `json:"priority"`
}

// AppsDefinition type encapsulates the json encoding of the whole technologies.json file
type AppsDefinition struct {
	Apps map[string]App      `json:"technologies"`
	Cats map[string]Category `json:"categories"`
}

type AppRegexp struct {
	Name    string
	Regexp  *regexp.Regexp
	Version string
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
	Array StringArray
	Rules map[string]DOMRule
}

type Group struct {
	Name string `json:"name"`
}

type StringArray []string

func (d *DOM) UnmarshalJSON(data []byte) error {

	var value string
	if err := json.Unmarshal(data, &value); err == nil {
		d.Kind = DOMKindString
		d.Value = value
		return nil
	}
	var array StringArray
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
	return fmt.Errorf("invalid dom value")

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

func (app *App) FindInHeaders(headers http.Header) (matches [][]string, version string) {
	var v string

	for _, hre := range app.HeaderRegex {
		if headers.Get(hre.Name) == "" {
			continue
		}
		hk := http.CanonicalHeaderKey(hre.Name)
		for _, headerValue := range headers[hk] {
			if headerValue == "" {
				continue
			}
			if m, version := findMatches(headerValue, []AppRegexp{hre}); len(m) > 0 {
				matches = append(matches, m...)
				v = version
			}
		}
	}
	return matches, v
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

// func downloadTechnologiesLocal() (map[string]App, error) {
// 	apps := make(map[string]App)

// 	files, err := os.ReadDir("technologies1")
// 	if err != nil {
// 		return nil, err
// 	}
// 	for _, file := range files {
// 		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
// 			continue
// 		}
// 		path := filepath.Join("technologies1", file.Name())
// 		f, err := os.Open(path)
// 		if err != nil {
// 			return nil, err
// 		}
// 		m := make(map[string]App)
// 		if err := json.NewDecoder(f).Decode(&m); err != nil {
// 			f.Close()
// 			return nil, err
// 		}
// 		maps.Copy(apps, m)
// 		f.Close()
// 	}
// 	return apps, nil
// }

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

// func downloadCategoriesLocal() (map[string]Category, error) {
// 	file, err := os.Open("categoriesSample.json")

// 	if err != nil {
// 		return nil, err
// 	}
// 	defer file.Close()

// 	m := make(map[string]Category)

// 	if err := json.NewDecoder(file).Decode(&m); err != nil {
// 		return nil, err
// 	}

// 	return m, nil
// }

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

	return nil
}

// load apps from io.Reader
func (wa *WebAnalyzer) loadApps(r io.Reader) error {
	dec := json.NewDecoder(r)
	if err := dec.Decode(&wa.appDefs); err != nil {
		return err
	}

	for key, value := range wa.appDefs.Apps {

		app := wa.appDefs.Apps[key]

		app.HTMLRegex = compileRegexes(value.HTML)
		app.ScriptRegex = compileRegexes(value.Scripts)
		app.URLRegex = compileRegexes(value.URL)

		app.HeaderRegex = compileNamedRegexes(app.Headers)
		app.CookieRegex = compileNamedRegexes(app.Cookies)
		// app.MetaRegex = compileNamedRegexes(app.Meta)

		app.CatNames = make(StringArray, 0)

		for _, cid := range app.Cats {
			if category, ok := wa.appDefs.Cats[strconv.Itoa(cid)]; ok && category.Name != "" {
				app.CatNames = append(app.CatNames, category.Name)
			}
		}

		wa.appDefs.Apps[key] = app

	}

	return nil
}

func compileNamedRegexes(from map[string]string) []AppRegexp {

	var list []AppRegexp

	for key, value := range from {

		h := AppRegexp{
			Name: key,
		}

		if value == "" {
			value = ".*"
		}

		// Filter out webapplyzer attributes from regular expression
		splitted := strings.Split(value, "\\;")

		r, err := regexp.Compile("(?i)" + splitted[0])
		if err != nil {
			continue
		}

		if len(splitted) > 1 && strings.HasPrefix(splitted[1], "version:") {
			h.Version = splitted[1][8:]
		}

		h.Regexp = r
		list = append(list, h)
	}

	return list
}

func compileRegexes(s StringArray) []AppRegexp {
	var list []AppRegexp

	for _, regexString := range s {

		if regexString == "" {
			continue
		}

		// Split version detection
		splitted := strings.Split(regexString, "\\;")

		regex, err := regexp.Compile("(?i)" + splitted[0])
		if err != nil {
			log.Printf("warning: failed to compile regex %q: %v", regexString, err)
			continue
		} else {
			rv := AppRegexp{
				Regexp: regex,
			}

			if len(splitted) > 1 && strings.HasPrefix(splitted[0], "version") {
				rv.Version = splitted[1][8:]
			}

			list = append(list, rv)
		}
	}

	return list
}
