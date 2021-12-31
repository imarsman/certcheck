package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"

	"gopkg.in/yaml.v2"

	"github.com/alexflint/go-arg"
)

const timeFormat = "2006-01-02T15:04:05Z"

var (
	wg          sync.WaitGroup                    // waitgroup to wait for work completion
	certValChan = make(chan CertVals)             // channel for certificate values
	sem         = semaphore.NewWeighted(int64(6)) // Set semaphore with capacity
	ctx         = context.Background()            // ctx for semaphore
)

type certValsSet struct {
	Total          int        `json:"total" yaml:"total"`
	HostErrorTotal int        `json:"hosterrortotal" yaml:"hosterrortotal"`
	ExpiredTotal   int        `json:"expiredtotal" yaml:"expiredtotal"`
	Vals           []CertVals `json:"certvals" yaml:"certvals"`
}

func (cvs *certValsSet) finalize() {
	for _, v := range cvs.Vals {
		cvs.Total++
		if v.HostError {
			cvs.HostErrorTotal++
		}
		if v.ExpiryWarning == true {
			cvs.ExpiredTotal++
		}
	}
}

// CertVals values for TLS certificate
type CertVals struct {
	ExpiryWarning bool   `json:"expirywarning" yaml:"expirywarning"`
	HostError     bool   `json:"hosterror" yaml:"hosterror"`
	Message       string `json:"message" yaml:"message"`
	Host          string `json:"host" yaml:"host"`
	Issuer        string `json:"issuer" yaml:"issuer"`
	Port          string `json:"port" yaml:"port"`
	DaysLeft      int    `json:"daysleft" yaml:"daysleft"`
	WarnAtDays    int    `json:"warnatdays" yaml:"warnatdays"`
	CheckTime     string `json:"checktime" yaml:"checktime"`
	NotBefore     string `json:"notbefore" yaml:"notbefore"`
	NotAfter      string `json:"notafter" yaml:"notafter"`
	FetchTime     string `json:"fetchtime" yaml:"fetchtime"`
}

// Get new Certvals instance with default values
func newCertVals() CertVals {
	certVals := CertVals{}
	certVals.CheckTime = time.Now().Format(timeFormat)
	certVals.FetchTime = time.Since(time.Now()).Round(time.Millisecond).String()

	return certVals
}

// Do check of cert from remote host and populate CertVals
func getCertVals(host, port string, warnAtDays int, timeout int) CertVals {
	tRun := time.Now()

	certVals := newCertVals()
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
		certVals.FetchTime = time.Since(tRun).String()

		return certVals
	}

	err = conn.VerifyHostname(host)
	if err != nil {
		certVals.HostError = true
		certVals.Message = fmt.Sprintf("Hostname doesn't match with certificate: %s" + err.Error())
		certVals.FetchTime = time.Since(tRun).String()

		return certVals
	}
	certVals.HostError = false

	certVals.Issuer = conn.ConnectionState().PeerCertificates[0].Issuer.String()

	notBefore := conn.ConnectionState().PeerCertificates[0].NotBefore
	certVals.NotBefore = notBefore.Format(timeFormat)

	notAfter := conn.ConnectionState().PeerCertificates[0].NotAfter
	certVals.NotAfter = notAfter.Format(timeFormat)

	now := time.Now()
	daysLeft := 0
	// nanoseconds to expiry of certificate
	nanosToExpiry := notAfter.UnixNano() - now.UnixNano()

	// If > one day left report that integer
	if nanosToExpiry > int64(time.Hour+24) {
		daysLeft = int((notAfter.UnixNano() - now.UnixNano()) / int64(time.Hour*24))
	}
	certVals.DaysLeft = daysLeft

	certVals.Message = "OK"
	certVals.CheckTime = time.Now().Format(timeFormat)

	expired := (time.Now().Add(time.Duration(warnIf)).UnixNano() > notAfter.UnixNano())
	certVals.ExpiryWarning = expired
	certVals.FetchTime = time.Since(tRun).Round(time.Millisecond).String()

	return certVals
}

// Extract host and port from incoming host string
func getParts(input string) (host string, port string, err error) {
	if strings.Contains(input, ":") {
		parts := strings.Split(input, ":")
		if len(parts) == 1 {
			host = parts[0]
			port = "443"
		} else if len(parts) == 2 {
			host = parts[0]
			port = parts[1]
		} else {
			err = errors.New("invalid host string " + input)
			return
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

// CLI args
type args struct {
	Hosts      []string `arg:"positional" help:"host:port list to check"`
	Timeout    int      `arg:"-t" default:"10" help:"connection timeout seconds"`
	WarnAtDays int      `arg:"-w" placeholder:"WARNAT" default:"30" help:"warn if expiry before days"`
	YAML       bool     `arg:"-y" help:"display output as YAML"`
	JSON       bool     `arg:"-j" help:"display output as JSON (default)"`
}

func main() {
	var callArgs args
	var cvs = new(certValsSet)
	cvs.Vals = make([]CertVals, 0, 0)

	addCertValsSet := func(items []string) {
		for _, item := range items {
			host, port, err := getParts(item)
			if err != nil {
				wg.Add(1)

				go func(err error) {
					defer wg.Done()
					// Handle semaphore capacity limiting

					certVals := newCertVals()
					certVals.HostError = true
					certVals.Message = err.Error()
					certValChan <- certVals
				}(err)
			} else {
				wg.Add(1)

				go func(host, port string) {
					defer wg.Done()
					// Handle semaphore capacity limiting
					sem.Acquire(ctx, 1)
					defer sem.Release(1)

					certValChan <- getCertVals(host, port, callArgs.WarnAtDays, callArgs.Timeout)
				}(host, port)
			}
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
			line = strings.TrimSpace(line)

			if strings.TrimSpace(line) == "" {
				continue
			}

			// If hosts are space separated
			if strings.Contains(line, " ") {
				re := regexp.MustCompile(`\s+`)
				// Split on space
				parts := re.Split(line, -1)
				// Add host
				for _, part := range parts {
					part = strings.TrimSpace(part)
					if part == "" {
						continue
					}
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

	// Wait for WaitGroup to finish then close channel to allow range below to
	// complete.
	go func() {
		// https://stackoverflow.com/questions/46010836/using-goroutines-to-process-values-and-gather-results-into-a-slice
		// https://dev.to/sophiedebenedetto/synchronizing-go-routines-with-channels-and-waitgroups-3ke2
		wg.Wait()
		// Close channel when done
		close(certValChan)
	}()

	// Add all cert values from channel to output list
	// Range will block until the channel is closed.
	for certVals := range certValChan {
		cvs.Vals = append(cvs.Vals, certVals)
	}

	cvs.finalize() // Produce summary values

	// sort vals slice by host
	sort.Slice(cvs.Vals, func(i, j int) bool {
		return cvs.Vals[i].Host < cvs.Vals[j].Host
	})

	// Handle YAML output
	if callArgs.YAML {
		bytes, err := yaml.Marshal(&cvs)
		if err != nil {
			os.Exit(1)
		}
		fmt.Print(string(bytes))

		return
	}

	// Do JSON output by default
	bytes, err := json.MarshalIndent(&cvs, "", "  ")
	if err != nil {
		os.Exit(1)
	}
	fmt.Println(string(bytes))

	return
}
