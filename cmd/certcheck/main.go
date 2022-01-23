package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/alexflint/go-arg"
	"github.com/imarsman/certcheck/cmd/certcheck/hosts"
)

const (
	timeFormat     = "2006-01-02T15:04:05Z"
	tlsDefaultPort = "443"
)

// CLI args
type args struct {
	Hosts      []string `arg:"positional" help:"host:port list to check"`
	Timeout    int      `arg:"-t" default:"10" help:"connection timeout seconds"`
	WarnAtDays int      `arg:"-w" placeholder:"WARNAT" default:"30" help:"warn if expiry before days"`
	YAML       bool     `arg:"-y" help:"display output as YAML"`
	JSON       bool     `arg:"-j" help:"display output as JSON (default)"`
}

func main() {
	var callArgs args // initialize call args structure
	err := arg.Parse(&callArgs)
	if err != nil {
		panic(err)
	}

	// Make a cert value set that will hold the output data
	var certValSet = new(hosts.CertValsSet)

	// Use stdin if it is available. Path will be ignored.
	stat, _ := os.Stdin.Stat()
	// var hostsToCheck []string

	var hosts = hosts.NewHosts()
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
					hosts.Hosts = append(hosts.Hosts, part)
				}
			} else {
				// Just one so add delta of 1 to waitgroup since there is just
				// one to run
				// wg.Add(1)
				// If one per line
				hosts.Hosts = append(hosts.Hosts, strings.TrimSpace(host))
			}
		}
	} else {
		hosts.Hosts = callArgs.Hosts
	}

	certValSet = hosts.ProcessHosts(callArgs.WarnAtDays, callArgs.Timeout)

	// Handle YAML output
	if callArgs.YAML {
		bytes, err := yaml.Marshal(&certValSet)
		if err != nil {
			os.Exit(1)
		}
		fmt.Print(string(bytes))

		return
	}

	// Do JSON output by default
	bytes, err := json.MarshalIndent(&certValSet, "", "  ")
	if err != nil {
		os.Exit(1)
	}
	fmt.Println(string(bytes))

	return
}
