package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
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
		return "Vuln"
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
		fmt.Fprint(w, message)
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
		fmt.Printf("%s - %s - %s - %s - DEBUG\n", time.Now().Format(time.RFC3339), r.URL, r.Method, r.Header)
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
				returnHandler(w, r, &rule)
				break
			}
		}
		if rule.regexPath != nil && rule.regexBody == nil {
			if rule.regexPath.MatchString(processedPath) {
				returnHandler(w, r, &rule)
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
