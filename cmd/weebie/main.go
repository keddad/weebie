package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var config Configuration

var rules []Rule

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func riskToString(a int) string {
	switch a {
	case port:
		return "Port"
	case service:
		return "Service"
	case vuln:
		return "Vulnerable"
	}

	return "?"
}

func returnHandler(w http.ResponseWriter, req *http.Request, rul *Rule) {
	ip := req.Header.Get(config.IpHeader)

	message := ""
	if ip == "" {
		message = fmt.Sprintf("%s - %s - %s - <No IP>\n", time.Now().Format(time.RFC3339), rul.ID, riskToString(rul.Risk))
	} else {
		message = fmt.Sprintf("%s - %s - %s - %s\n", time.Now().Format(time.RFC3339), rul.ID, riskToString(rul.Risk), ip)
	}

	if config.WriteLogs {
		fmt.Print(message)
	}

	if config.WriteResponse {
		_, err := fmt.Fprint(w, message)
		check(err)
	}
}

// all URI processed here
//TODO
func rootHandler(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	buf := new(strings.Builder)
	_, err := io.Copy(buf, r.Body)
	check(err)

	isDebug := false
	if queryParams.Get(config.DebugSecret) == config.DebugSecret {
		isDebug = true
	}

	if isDebug {
		fmt.Printf("%s - %s - %s - %s - DEBUG\n", time.Now().Format(time.RFC3339), r.URL, r.Method, r.Header)
	}

	var triggeredRule *Rule = nil

	for i, rule := range rules {
		if rule.Match(r) {
			if triggeredRule == nil {
				triggeredRule = &rules[i]
			} else if triggeredRule.Risk < rule.Risk {
				triggeredRule = &rules[i]
			}
		}
	}

	if triggeredRule != nil {
		returnHandler(w, r, triggeredRule)
	}
}

// handles 40x errors from nginx (error_page have to redirect here)
//TODO
func errorHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "%s\n", r.URL.Path[1:])
}

func loadFile(path string) {
	bs, err := ioutil.ReadFile(path)

	if err != nil {
		fmt.Printf("Couldn't read rule file %s: %e\n", path, err)
		panic(err)
	}

	fileRules := make([]Rule, 0)

	err = json.Unmarshal(bs, &fileRules)

	if err != nil {
		fmt.Printf("Couldn't decode rule file %s: %e\n", path, err)
		panic(err)
	}

	rules = append(rules, fileRules...)
}

func main() {
	bs, err := ioutil.ReadFile("config.json")
	check(err)

	check(json.Unmarshal(bs, &config))

	if config.RulesFile != "" {
		loadFile(config.RulesFile)
	}

	if config.RulesFolder != "" {
		e := filepath.Walk(config.RulesFolder, func(path string, f os.FileInfo, err error) error {
			if !f.IsDir() {
				loadFile(path)
			}
			return err
		})

		if e != nil {
			fmt.Printf("Couldn't load fules from folder: %e\n", e)
			panic(e)
		}
	}

	for i := 0; i < len(rules); i++ {
		rules[i].regexPath = regexp.MustCompile(rules[i].RegexPath)
		rules[i].regexBody = regexp.MustCompile(rules[i].RegexBody)
	}

	fmt.Printf("Loaded %d rules\n", len(rules))

	http.HandleFunc("/.well-known/weebie", errorHandler)
	http.HandleFunc("/", rootHandler)
	check(http.ListenAndServe(config.ListenAddr, nil))
}
