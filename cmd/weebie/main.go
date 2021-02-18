package main

import (
	"fmt"
	"io/ioutil"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"io"
)

type Configuration struct {
	ListenAddr	string	`json:"listen_addr"`
	DebugSecret	string	`json:"debug_secret"`
	RulesFile	string	`json:"rules_file"`
}
var config Configuration

type Rule struct {
	CaseSensPath	bool			`json:"path_case_sensetive"`
	RegexPath	string			`json:"regex_path"`
	regexPath	*regexp.Regexp
	CaseSensQuery	bool			`json:"query_case_sensetive"`
	QueryParams	map[string]string	`json:"query_params"`
	CaseSensBody	bool			`json:"body_case_sensetive"`
	RegexBody	string			`json:"regex_body"`
	regexBody	*regexp.Regexp
	Risk		float64			// 1 - port, 2 - service, 3 - vulnerability
	Comment		string
}
var rules []Rule


func check(e error) {
	if e != nil {
		panic(e)
	}
}

// all URI processed here
//TODO
func rootHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	queryParams := r.URL.Query()
	buf := new(strings.Builder)
	_, err := io.Copy(buf, r.Body)
	check(err)
	body := buf.String()

	isDebug := false
	if queryParams.Get(config.DebugSecret) == config.DebugSecret {
		isDebug = true
	}
	if isDebug {
		//debug mode enabled message
	}

	for _, rule := range rules {
		processedPath := path
		processedBody := body
		if !rule.CaseSensPath {
			processedPath = strings.ToLower(processedPath)
		}
		if !rule.CaseSensBody {
			processedPath = strings.ToLower(processedPath)
		}
		if rule.regexPath != nil && rule.regexBody != nil {
			if rule.regexPath.MatchString(processedPath) && rule.regexBody.MatchString(processedBody) {
				fmt.Fprintln(w, rule.Comment)
				break
			}
		}
		if rule.regexPath != nil && rule.regexBody == nil {
			if rule.regexPath.MatchString(processedPath) {
				fmt.Fprintln(w, rule.Comment)
				break
			}
		}
	}
}

// handles 40x errors from nginx (error_page have to redirect here)
//TODO
func errorHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "%s\n", r.URL.Path[1:])
}

func main() {
	// read config
	bs, err := ioutil.ReadFile("config.json")
	check(err)

	check(json.Unmarshal(bs, &config))


	// read rules
	bs, err = ioutil.ReadFile(config.RulesFile)
	check(err)

	check(json.Unmarshal(bs, &rules))
	for i := 0; i < len(rules); i++ {
		rules[i].regexPath = regexp.MustCompile(rules[i].RegexPath)
		rules[i].regexBody = regexp.MustCompile(rules[i].RegexBody)
	}


	http.HandleFunc("/.well-known/weebie", errorHandler)
	http.HandleFunc("/", rootHandler)
	check(http.ListenAndServe(config.ListenAddr, nil))

}
