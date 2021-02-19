package main

import (
	"io"
	"net/http"
	"regexp"
	"strings"
)

const (
	port = iota + 1
	service
	vuln
)

type Configuration struct {
	ListenAddr    string `json:"listen_addr"`
	DebugSecret   string `json:"debug_secret"`
	RulesFile     string `json:"rules_file"`
	RulesFolder   string `json:"rules_folder"`
	IpHeader      string `json:"ip_header"`
	WriteLogs     bool   `json:"write_logs"`
	WriteResponse bool   `json:"write_response"`
}

type Rule struct {
	CaseSensPath  bool   `json:"path_case_sensitive"`
	RegexPath     string `json:"regex_path"`
	regexPath     *regexp.Regexp
	CaseSensQuery bool              `json:"query_case_sensitive"`
	QueryParams   map[string]string `json:"query_params"`
	CaseSensBody  bool              `json:"body_case_sensitive"`
	RegexBody     string            `json:"regex_body"`
	regexBody     *regexp.Regexp
	Risk          int // 1 - port, 2 - service, 3 - vulnerability
	Comment       string
	ID            string
}

func (r *Rule) Match(req *http.Request) bool {
	var processedPath string
	var processedBody string

	if r.RegexBody != "" {
		body := make([]byte, 0)
		_, err := req.Body.Read(body)

		if err != io.EOF {
			check(err)
		}

		if r.CaseSensBody {
			processedBody = string(body)
		} else {
			processedBody = strings.ToLower(string(body))
		}

		if !r.regexBody.MatchString(processedBody) {
			return false
		}
	}

	if r.RegexPath != "" {
		if r.CaseSensPath {
			processedPath = req.URL.Path
		} else {
			processedPath = strings.ToLower(req.URL.Path)
		}

		if !r.regexPath.MatchString(processedPath) {
			return false
		}
	}

	for key, value := range r.QueryParams {
		if r.CaseSensQuery {
			if req.URL.Query().Get(key) != value {
				return false
			}
		} else {
			if strings.ToLower(req.URL.Query().Get(key)) != strings.ToLower(value) {
				return false
			}
		}
	}

	return true
}
