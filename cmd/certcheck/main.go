package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/alexflint/go-arg"
)

const timeFormat = "2006-01-02T15:04:05Z"

type certValsSet struct {
	vals []CertVals
}

// CertVals values for TLS certificate
type CertVals struct {
	ExpiryWarning bool   `json:"expirywarning" yaml:"expirywarning"`
	HostError     bool   `json:"hosterror" yaml:"hosterror"`
	Message       string `json:"message" yaml:"message"`
	Host          string `json:"host" yaml:"host"`
	Port          string `json:"port" yaml:"port"`
	WarnAtDays    int    `json:"warnatdays" yaml:"warnatdays"`
	CheckTime     string `json:"checktime" yaml:"checktime"`
	NotBefore     string `json:"notbefore" yaml:"notbefore"`
	NotAfter      string `json:"notafter" yaml:"notafter"`
}

func getCertVals(host, port string, warnAtDays int, timeout int) CertVals {
	certVals := CertVals{}
	certVals.Host = host
	certVals.Port = port
	certVals.HostError = false
	certVals.WarnAtDays = warnAtDays
	hostAndPort := host + ":" + port

	warnIf := warnAtDays * 24 * int(time.Hour)

	dialer := &net.Dialer{Timeout: time.Duration(timeout) * time.Second}

	conn, err := tls.DialWithDialer(
		dialer,
		"tcp",
		hostAndPort, nil)
	if err != nil {
		certVals.HostError = true
		certVals.Message = fmt.Sprintf("Server doesn't support TLS certificate err: %s" + err.Error())

		return certVals
	}

	err = conn.VerifyHostname(host)
	if err != nil {
		certVals.HostError = true
		certVals.Message = fmt.Sprintf("Hostname doesn't match with certificate: %s" + err.Error())

		return certVals
	}
	certVals.HostError = false

	notBefore := conn.ConnectionState().PeerCertificates[0].NotBefore
	certVals.NotBefore = notBefore.Format(timeFormat)

	notAfter := conn.ConnectionState().PeerCertificates[0].NotAfter
	certVals.NotAfter = notAfter.Format(timeFormat)

	certVals.Message = "OK"
	certVals.CheckTime = time.Now().Format(timeFormat)

	expired := (time.Now().Add(time.Duration(warnIf)).UnixNano() > notAfter.UnixNano())
	certVals.ExpiryWarning = expired // Fix this

	return certVals
}

func getParts(input string) (host string, port string, err error) {
	if strings.Contains(input, ":") {
		parts := strings.Split(input, ":")
		if len(parts) == 1 {
			host = parts[0]
			port = "443"
		} else {
			if len(parts) == 2 {
				host = parts[0]
				port = parts[1]
			}
		}
	} else {
		host = input
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
	Hosts      []string `arg:"-H" help:"host:port list to check"`
	Timeout    int      `arg:"-t" default:"10" help:"connection timeout seconds"`
	WarnAtDays int      `arg:"-w" placeholder:"WARNAT" default:"30" help:"warn if expiry before days"`
	YAML       bool     `arg:"-y" help:"display output as YAML"`
	JSON       bool     `arg:"-j" help:"display output as JSON (default)"`
}

func main() {
	var callArgs args
	var cvs = new(certValsSet)

	addCertValsSet := func(items []string) {
		for _, item := range items {
			host, port, err := getParts(item)
			if err != nil {
				continue
			}

			certVals := getCertVals(host, port, callArgs.WarnAtDays, callArgs.Timeout)
			cvs.vals = append(cvs.vals, certVals)
		}
	}

	arg.MustParse(&callArgs)

	// Use stdin if it is available. Path will be ignored.
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {

		var scanner = bufio.NewScanner(os.Stdin)
		// Tell scanner to scan by lines.
		scanner.Split(bufio.ScanLines)

		var hosts []string
		for scanner.Scan() {
			line := scanner.Text()

			// If hosts are space separated
			if strings.Contains(line, " ") {
				// Get rid of duplicates
				line = strings.ReplaceAll(line, "  ", " ")
				// Split on space
				parts := strings.Split(line, " ")
				// Add host
				for _, part := range parts {
					part = strings.TrimSpace(part)
					hosts = append(hosts, part)
				}
			} else {
				// If one per line
				hosts = append(hosts, strings.TrimSpace(line))
			}
		}
		// Take hosts found and do lookup and check
		addCertValsSet(hosts)
	} else {
		// Do lookups for arg hosts
		addCertValsSet(callArgs.Hosts)
	}
	if len(cvs.vals) > 0 {
		if callArgs.YAML {
			bytes, err := yaml.Marshal(&cvs.vals)
			if err != nil {

			}
			fmt.Print(string(bytes))

			return
		}
		bytes, err := json.MarshalIndent(&cvs.vals, "", "  ")
		if err != nil {

		}
		fmt.Println(string(bytes))

		return
	}

	fmt.Fprintln(os.Stderr, "No valid hosts found")
}
