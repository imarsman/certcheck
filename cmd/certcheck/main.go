// Package main parses command line arguments and uses the hosts package to do
// TLS lookups.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/alexflint/go-arg"
	"github.com/imarsman/certcheck/pkg/hosts"
	"github.com/posener/complete/v2"
	"github.com/posener/complete/v2/predict"
)

var GitCommit string
var GitLastTag string
var GitExactTag string
var Date string

// Args CLI Args
type Args struct {
	Hosts      []string `arg:"-H,--hosts" help:"host:port list to check"`
	CertFile   string   `arg:"-c,--certfile" help:"certificate file to parse"`
	Timeout    int      `arg:"-t,--timeout" default:"10" help:"connection timeout seconds"`
	WarnAtDays int      `arg:"-w,--warn-at-days" placeholder:"WARNAT" default:"30" help:"warn if expiry before days"`
	YAML       bool     `arg:"-y,--yaml" help:"display output as YAML"`
	JSON       bool     `arg:"-j,--json" help:"display output as JSON (default)"`
}

// Version get version information
func (Args) Version() string {
	var buf = new(bytes.Buffer)

	msg := os.Args[0]
	buf.WriteString(fmt.Sprintln(msg))
	buf.WriteString(fmt.Sprintln(strings.Repeat("-", len(msg))))

	if GitCommit != "" {
		buf.WriteString(fmt.Sprintf("Commit: %8s\n", GitCommit))
	}
	if Date != "" {
		buf.WriteString(fmt.Sprintf("Date: %23s\n", Date))
	}
	if GitExactTag != "" {
		buf.WriteString(fmt.Sprintf("Tag: %10s\n", GitExactTag))
	}
	buf.WriteString(fmt.Sprintf("OS: %11s\n", runtime.GOOS))
	buf.WriteString(fmt.Sprintf("ARCH: %8s\n", runtime.GOARCH))

	return buf.String()
}

var callArgs Args

// Entry point for app
func main() {
	cmd := &complete.Command{
		Flags: map[string]complete.Predictor{
			"hosts":        predict.Nothing,
			"certfile":     predict.Files("*"),
			"timeout":      predict.Nothing,
			"warn-at-days": predict.Nothing,
			"yaml":         predict.Nothing,
			"json":         predict.Nothing,
		},
	}

	cmd.Complete("certcheck")

	// var callArgs args // initialize call args structure
	arg.MustParse(&callArgs)

	// Make a cert value set that will hold the output data
	var certDataSet = hosts.NewCertDataSet()

	// Use stdin if it is available. Path will be ignored.
	stat, _ := os.Stdin.Stat()
	// var hostsToCheck []string

	var hostSet = hosts.NewHostSet()

	if (stat.Mode() & os.ModeCharDevice) == 0 {

		var scanner = bufio.NewScanner(os.Stdin)
		// Tell scanner to scan by lines.
		scanner.Split(bufio.ScanLines)

		for scanner.Scan() {
			host := scanner.Text()
			host = strings.TrimSpace(host)

			if strings.TrimSpace(host) == "" {
				continue
			}

			// If hosts are space separated
			if strings.Contains(host, " ") {
				re := regexp.MustCompile(`\s+`)
				// Split on space
				stdinHosts := re.Split(host, -1)
				for _, part := range stdinHosts {
					part = strings.TrimSpace(part)
					if part == "" {
						continue
					}
					hostSet.Add(part)
				}
			} else {
				hostSet.Add(strings.TrimSpace(host))
			}
		}
	} else {
		hostSet.Add(callArgs.Hosts...)
	}

	// Set minimum if below threshold
	if callArgs.WarnAtDays < 1 {
		callArgs.WarnAtDays = 30
	}
	// Set minimum if below threshold
	if callArgs.Timeout < 1 {
		callArgs.Timeout = 5
	}

	if callArgs.CertFile != "" {
		file, err := os.Open(callArgs.CertFile)
		if err != nil {
			fmt.Println(fmt.Errorf("error %v", err))
			os.Exit(1)
		}
		// Limit to max PEM file size. Found in Cisco document about changes
		// to max.
		limitReader := io.LimitReader(file, 8192)
		contents, err := io.ReadAll(limitReader)
		if err != nil {
			fmt.Println(fmt.Errorf("error %v", err))
			os.Exit(1)
		}
		certDataSet = hosts.NewHostSet().ProcessCertFile(contents, callArgs.WarnAtDays, time.Duration(callArgs.Timeout*int(time.Second)))
	} else {
		certDataSet = hostSet.Process(callArgs.WarnAtDays, time.Duration(callArgs.Timeout*int(time.Second)))
	}

	var bytes []byte
	var err error

	// Handle YAML output
	if callArgs.YAML {
		bytes, err = certDataSet.YAML()
		if err != nil {
			panic(err)
		}
		// Handle JSON output
	} else {
		bytes, err = certDataSet.JSON()
		if err != nil {
			panic(err)
		}
	}
	fmt.Println(string(bytes))

	return
}
