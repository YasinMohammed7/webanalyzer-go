package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/rverton/webanalyze"
)

var (
	update          bool
	outputMethod    string
	workers         int
	techsFilename   string
	host            string
	hosts           string
	crawlCount      int
	searchSubdomain bool
	silent          bool
	redirect        bool
	browser         bool
)

func init() {
	flag.StringVar(&outputMethod, "output", "stdout", "output format (stdout|csv|json|jsonfile)")
	flag.BoolVar(&update, "update", false, "update technologies file to current dir")
	flag.StringVar(&techsFilename, "apps", "technologies.json", "technologies definition file")
	flag.IntVar(&workers, "worker", 0, "number of workers (0 = automatic)")
	flag.StringVar(&host, "host", "", "single host to test")
	flag.StringVar(&hosts, "hosts", "", "filename with hosts, one host per line.")
	flag.IntVar(&crawlCount, "crawl", 0, "links to follow from the root page (default 0)")
	flag.BoolVar(&searchSubdomain, "search", false, "searches all urls with same base domain (i.e. example.com and sub.example.com)")
	flag.BoolVar(&silent, "silent", false, "avoid printing header (default false)")
	flag.BoolVar(&redirect, "redirect", true, "follow http redirects (default true)")
	flag.BoolVar(&browser, "browser", true, "enable browser automation (default true)")
}

func main() {
	var (
		file     io.ReadCloser
		err      error
		wa       *webanalyze.WebAnalyzer
		jsonFile *os.File

		outWriter     *csv.Writer
		outJsonWriter *json.Encoder
	)

	flag.Parse()

	if workers == 0 {

		if browser {
			workers = runtime.NumCPU()
		} else {
			workers = runtime.NumCPU() * 2
		}

	}

	if !update && host == "" && hosts == "" {
		flag.Usage()
		return
	}

	if update {
		err = webanalyze.DownloadFile("categories.json", "technologies.json", "groups.json")
		if err != nil {
			log.Fatalf("error: can not update apps file: %v", err)
		}

		if !silent {
			log.Println("app definition file updated")
		}

		if host == "" && hosts == "" {
			return
		}

	}

	// lookup technologies.json file
	techsFilename, err = lookupFolders(techsFilename)
	if err != nil {
		log.Fatalf("error: can not open apps file %s: %s", techsFilename, err)
	}

	// add header if output mode is csv
	switch outputMethod {
	case "csv":
		outWriter = csv.NewWriter(os.Stdout)
		outWriter.Write([]string{"Host", "Category", "App", "Version"})

		defer outWriter.Flush()

	case "jsonfile":
		file, err := os.Create("results.json")
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		jsonFile = file

		outJsonWriter = json.NewEncoder(jsonFile)
		outJsonWriter.SetIndent("", "  ")
	}

	// check single host or hosts file
	if host != "" {
		file = io.NopCloser(strings.NewReader(host))
	} else {
		file, err = os.Open(hosts)

		if err != nil {
			log.Fatalf("error: can not open host file %s: %s", hosts, err)
		}
	}
	defer file.Close()

	var wg sync.WaitGroup
	var collectorWG sync.WaitGroup
	hosts := make(chan string)
	resultCh := make(chan webanalyze.Result)

	techsFile, err := os.Open(techsFilename)
	if err != nil {
		log.Fatalf("error: can not open apps file %s: %s", techsFilename, err)
	}
	defer techsFile.Close()

	categoriesFile, err := os.Open("categories.json")

	if err != nil {
		log.Fatal(err)
	}

	defer categoriesFile.Close()

	groupsFile, err := os.Open("groups.json")

	if err != nil {
		log.Fatal(err)
	}

	defer groupsFile.Close()

	if wa, err = webanalyze.NewWebAnalyzer(techsFile, categoriesFile, groupsFile, nil); err != nil {
		log.Fatalf("initialization failed: %v", err)
	}

	if browser {

		if err := wa.EnableBrowser(); err != nil {
			log.Fatalf("failed to initialize browser: %v", err)
		}

		defer wa.CloseBrowser()
	}

	if !silent {
		printHeader()
	}

	appsInfo, err := os.Stat(techsFilename)
	if err != nil {
		log.Fatalf("cannot stat %v: %v", techsFilename, err)
	}

	if appsInfo.ModTime().Before(time.Now().Add(24 * time.Hour * 7 * -1)) {
		log.Printf("warning: %v is older than a week", techsFilename)
	}

	technologyCount := make(map[string]int)

	collectorWG.Go(func() {
		for result := range resultCh {

			output(result, wa, outWriter, outJsonWriter)

			// deduplicate inside this result first
			seen := make(map[string]struct{})

			for _, tech := range result.Technologies {
				seen[tech.AppName] = struct{}{}
			}

			for name := range seen {
				technologyCount[name]++
			}
		}
	})

	for i := 0; i < workers; i++ {
		wg.Go(func() {

			for host := range hosts {
				job := webanalyze.NewOnlineJob(host, "", nil, crawlCount, searchSubdomain, redirect)

				if crawlCount > 0 {
					results := wa.Crawl(job)

					for _, result := range results {
						resultCh <- result
					}
				} else {
					result, _ := wa.Process(job)
					resultCh <- result
				}
			}

		})
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		hosts <- scanner.Text()
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	close(hosts)
	wg.Wait()
	close(resultCh)
	collectorWG.Wait()

	fmt.Printf("\nTotal unique technologies: %d\n", len(technologyCount))

	for name, count := range technologyCount {

		fmt.Printf("%s: %d\n", name, count)

	}

}

func output(result webanalyze.Result, wa *webanalyze.WebAnalyzer, outWriter *csv.Writer, outJsonWriter *json.Encoder) {
	if result.Error != nil {
		fmt.Fprintf(os.Stderr, "%v error: %v\n", result.Host, result.Error)
		return
	}

	switch outputMethod {
	case "stdout":
		fmt.Printf("%v (%.1fs):\n", result.Host, result.Seconds)
		for _, a := range result.Technologies {

			var categories []string

			for _, cid := range a.App.Cats {
				categories = append(categories, wa.CategoryById(cid))
			}

			fmt.Printf("    %v, %v (%v)\n", a.AppName, a.Version, strings.Join(categories, ", "))
		}
		if len(result.Technologies) <= 0 {
			fmt.Printf("    <no results>\n")
		}

	case "csv":
		for _, m := range result.Technologies {
			outWriter.Write(
				[]string{
					result.Host,
					m.AppName,
					m.Version,
				},
			)
		}
		outWriter.Flush()
	case "json":

		b, err := json.Marshal(result)
		if err != nil {
			log.Printf("cannot marshal output: %v\n", err)
		}

		b = append(b, ',', '\n')

		os.Stdout.Write(b)
	case "jsonfile":

		if err := outJsonWriter.Encode(&result); err != nil {
			log.Println(err)
		}

	}
}

func printHeader() {
	printOption("webanalyze", "v"+webanalyze.VERSION)
	printOption("workers", workers)
	printOption("technologies", techsFilename)
	printOption("crawl count", crawlCount)
	printOption("search subdomains", searchSubdomain)
	printOption("follow redirects", redirect)
	printOption("browser", browser)
	fmt.Printf("\n")
}

func printOption(name string, value any) {
	fmt.Fprintf(os.Stderr, " :: %-17s : %v\n", name, value)
}

func lookupFolders(filename string) (string, error) {
	if filepath.IsAbs(filename) {
		return filename, nil
	}

	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	executableDir := filepath.Dir(executable)

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	folders := []string{"./", executableDir, home}

	for _, folder := range folders {
		path := filepath.Join(folder, filename)

		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", errors.New("could not find the technologies file: " + filename)
}
