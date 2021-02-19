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

func main() {
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
