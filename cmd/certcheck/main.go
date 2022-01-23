package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/alexflint/go-arg"
	"github.com/imarsman/certcheck/pkg/hosts"
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
	var certDataSet = hosts.NewCertDataSet()

	// Use stdin if it is available. Path will be ignored.
	stat, _ := os.Stdin.Stat()
	// var hostsToCheck []string

	var hostDataSet = hosts.NewHostDataSet()
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

	certDataSet = hostDataSet.Process(callArgs.WarnAtDays, callArgs.Timeout)

	var bytes []byte

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
