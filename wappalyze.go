package webanalyze

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
)

const WappazlyerRoot = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src"

// StringArray type is a wrapper for []string for use in unmarshalling the technologies.json
type StringArray []string

// App type encapsulates all the data about an App from technologies.json
type App struct {
	Cats     StringArray            `json:"cats"`
	CatNames []string               `json:"category_names"`
	Cookies  map[string]string      `json:"cookies"`
	Headers  map[string]string      `json:"headers"`
	Meta     map[string]StringArray `json:"meta"`
	HTML     StringArray            `json:"html"`
	Script   StringArray            `json:"scripts"`
	URL      StringArray            `json:"url"`
	Website  string                 `json:"website"`
	Implies  StringArray            `json:"implies"`

	HTMLRegex   []AppRegexp `json:"-"`
	ScriptRegex []AppRegexp `json:"-"`
	URLRegex    []AppRegexp `json:"-"`
	HeaderRegex []AppRegexp `json:"-"`
	MetaRegex   []AppRegexp `json:"-"`
	CookieRegex []AppRegexp `json:"-"`
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

// UnmarshalJSON is a custom unmarshaler for handling bogus technologies.json types from wappalyzer
func (t *StringArray) UnmarshalJSON(data []byte) error {
	var s string
	var sa []string
	var na []int

	if err := json.Unmarshal(data, &s); err != nil {
		if err := json.Unmarshal(data, &na); err == nil {
			// not a string, so maybe []int?
			*t = make(StringArray, len(na))

			for i, number := range na {
				(*t)[i] = fmt.Sprintf("%d", number)
			}

			return nil
		} else if err := json.Unmarshal(data, &sa); err == nil {
			// not a string, so maybe []string?
			*t = sa
			return nil
		}
		fmt.Println(string(data))
		return err
	}
	*t = StringArray{s}
	return nil
}

func downloadTechnologies() (map[string]App, error) {
	apps := make(map[string]App)

	files := []string{"_", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"}

	count := 0
	for _, f := range files {
		m := make(map[string]App)
		url := fmt.Sprintf("%v/technologies/%v.json", WappazlyerRoot, f)
		resp, err := http.Get(url)
		if err != nil {
			return nil, err
		}
		if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
			return nil, err
		}

		for key := range m {
			apps[key] = m[key]
			count = count + 1
		}
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

// DownloadFile pulls the latest technologies.json file from the Wappalyzer github
func DownloadFile(categoriesPath string, technologiesPath string) error {
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

	// Step 3: Marshal and write categories
	categoriesData, err := json.MarshalIndent(categories, "", " ")
	if err != nil {
		return fmt.Errorf("failed to marshal categories: %w", err)
	}
	if err := os.WriteFile(categoriesPath, categoriesData, 0644); err != nil {
		return fmt.Errorf("failed to write categories file: %w", err)
	}

	// Step 4: Marshal and write technologies
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
		app.ScriptRegex = compileRegexes(value.Script)
		app.URLRegex = compileRegexes(value.URL)

		app.HeaderRegex = compileNamedRegexes(app.Headers)
		app.CookieRegex = compileNamedRegexes(app.Cookies)

		// handle special meta field where value can be a list
		// of strings. we join them as a simple regex here
		metaRegex := make(map[string]string)
		for k, v := range app.Meta {
			metaRegex[k] = strings.Join(v, "|")
		}
		app.MetaRegex = compileNamedRegexes(metaRegex)

		app.CatNames = make([]string, 0)

		for _, cid := range app.Cats {
			if category, ok := wa.appDefs.Cats[string(cid)]; ok && category.Name != "" {
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
			// ignore failed compiling for now
			// log.Printf("warning: compiling regexp for failed: %v", regexString, err)
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
