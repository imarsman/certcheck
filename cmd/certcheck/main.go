package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/alexflint/go-arg"
)

type certValsSet struct {
	vals []CertVals
}

// CertVals values for TLS certificate
type CertVals struct {
	Expired     bool   `json:"expired" yaml:"expired"`
	DomainError bool   `json:"domainerror" yaml:"domainerror"`
	Message     string `json:"message" yaml:"message"`
	Domain      string `json:"domain" yaml:"domain"`
	Port        string `json:"port" yaml:"port"`
	NotAfter    string `json:"notafter" yaml:"notafter"`
	NotBefore   string `json:"notbefore" yaml:"notbefore"`
}

func getCertVals(domain, port string, warnAtDays int) CertVals {
	certVals := CertVals{}
	certVals.Domain = domain
	certVals.Port = port
	certVals.DomainError = false

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%s", domain, port), nil)
	if err != nil {
		certVals.Message = fmt.Sprintf("Server doesn't support SSL certificate err: %s" + err.Error())
		return certVals
	}

	err = conn.VerifyHostname(domain)
	if err != nil {
		certVals.Message = fmt.Sprintf("Hostname doesn't match with certificate: %s" + err.Error())
		return certVals
	}
	certVals.DomainError = false

	notBefore := conn.ConnectionState().PeerCertificates[0].NotBefore
	certVals.NotBefore = notBefore.Format(time.RFC3339)

	notAfter := conn.ConnectionState().PeerCertificates[0].NotAfter
	certVals.NotAfter = notAfter.Format(time.RFC3339)
	certVals.Message = "OK"
	certVals.Expired = false // Fix this

	return certVals
}

func getParts(input string) (domain string, port string, err error) {
	if strings.Contains(input, ":") {
		parts := strings.Split(input, ":")
		if len(parts) == 1 {
			domain = parts[0]
			port = "443"
		} else {
			if len(parts) == 2 {
				domain = parts[0]
				port = parts[1]
			}
		}
	} else {
		domain = input
		port = "443"
	}
	var matched bool
	matched, err = regexp.MatchString(`\d+`, port)
	if err != nil {
		return
	}
	if !matched {
		err = fmt.Errorf("Port is not an integer %s", port)
		return
	}
	return
}

type args struct {
	Domains    []string `arg:"-d" help:"list of domains to check with ports"`
	WarnAtDays int      `arg:"-w" default:"30" help:"warn if expiry before days"`
	YAML       bool     `arg:"-y" help:"display output as YAML"`
	JSON       bool     `arg:"-j" help:"display output as JSON"`
}

func main() {
	var args args

	arg.MustParse(&args)

	warnAtDays := 30
	if args.WarnAtDays != warnAtDays {
		warnAtDays = args.WarnAtDays
	}

	cvs := new(certValsSet)

	// Use stdin if it is available. Path will be ignored.
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {

		var scanner = bufio.NewScanner(os.Stdin)
		// Tell scanner to scan by lines.
		scanner.Split(bufio.ScanLines)

		for scanner.Scan() {
			domain, port, err := getParts(scanner.Text())
			if err != nil {
				continue
			}
			certVals := getCertVals(domain, port, warnAtDays)
			cvs.vals = append(cvs.vals, certVals)
		}
	} else {
		for _, domain := range args.Domains {
			domain, port, err := getParts(domain)
			if err != nil {
				continue
			}

			certVals := getCertVals(domain, port, warnAtDays)
			cvs.vals = append(cvs.vals, certVals)
		}
	}
	if len(cvs.vals) > 0 {
		if args.YAML {
			bytes, err := yaml.Marshal(&cvs.vals)
			if err != nil {

			}
			fmt.Print(string(bytes))
			return
		}
		bytes, err := json.Marshal(&cvs.vals)
		if err != nil {

		}
		fmt.Print(string(bytes))
		return
	}

	fmt.Fprintln(os.Stderr, "No valid domains found")
}
