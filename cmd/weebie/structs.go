package main

import "regexp"

const (
	port = iota + 1
	service
	vuln
)

type Configuration struct {
	ListenAddr    string `json:"listen_addr"`
	DebugSecret   string `json:"debug_secret"`
	RulesFile     string `json:"rules_file"`
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
