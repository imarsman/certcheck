// Package main parses command line arguments and uses the hosts package to do
// TLS lookups.
package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/alexflint/go-arg"
	"github.com/imarsman/certcheck/pkg/hosts"
	"github.com/posener/complete/v2"
	"github.com/posener/complete/v2/predict"
)

// args CLI args
type args struct {
	Hosts      []string `arg:"-H,--hosts" help:"host:port list to check"`
	Timeout    int      `arg:"-t,--timeout" default:"10" help:"connection timeout seconds"`
	WarnAtDays int      `arg:"-w,--warn-at-days" placeholder:"WARNAT" default:"30" help:"warn if expiry before days"`
	YAML       bool     `arg:"-y,--yaml" help:"display output as YAML"`
	JSON       bool     `arg:"-j,--json" help:"display output as JSON (default)"`
}

// Entry point for app
func main() {
	cmd := &complete.Command{
		Flags: map[string]complete.Predictor{
			"hosts":        predict.Nothing,
			"timeout":      predict.Nothing,
			"warn-at-days": predict.Nothing,
			"yaml":         predict.Nothing,
			"json":         predict.Nothing,
		},
	}

	cmd.Complete("certcheck")

	var callArgs args // initialize call args structure
	arg.MustParse(&callArgs)

	// Make a cert value set that will hold the output data
	var certDataSet = hosts.NewCertDataSet()

	// Use stdin if it is available. Path will be ignored.
	stat, _ := os.Stdin.Stat()
	// var hostsToCheck []string

	var hostDataSet = hosts.NewHostSet()
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
					hostDataSet.AddHosts(part)
				}
			} else {
				hostDataSet.AddHosts(strings.TrimSpace(host))
			}
		}
	} else {
		hostDataSet.AddHosts(callArgs.Hosts...)
	}

	// Set minimum if below threshold
	if callArgs.WarnAtDays < 1 {
		callArgs.WarnAtDays = 30
	}
	// Set minimum if below threshold
	if callArgs.Timeout < 1 {
		callArgs.Timeout = 5
	}
	certDataSet = hostDataSet.Process(callArgs.WarnAtDays, callArgs.Timeout)

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
