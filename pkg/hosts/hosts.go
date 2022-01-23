package hosts

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
	"gopkg.in/yaml.v2"
)

const (
	timeFormat     = "2006-01-02T15:04:05Z"
	tlsDefaultPort = "443"
)

// CertData values for TLS certificate
type CertData struct {
	ExpiryWarning bool   `json:"expirywarning" yaml:"expirywarning"`
	HostError     bool   `json:"hosterror" yaml:"hosterror"`
	Message       string `json:"message" yaml:"message"`
	Host          string `json:"host" yaml:"host"`
	Issuer        string `json:"issuer" yaml:"issuer"`
	Port          string `json:"port" yaml:"port"`
	TotalDays     int    `json:"totaldays" yaml:"totaldays"`
	DaysToExpiry  int    `json:"daystoexpiry" yaml:"daystoexpiry"`
	WarnAtDays    int    `json:"warnatdays" yaml:"warnatdays"`
	CheckTime     string `json:"checktime" yaml:"checktime"`
	NotBefore     string `json:"notbefore" yaml:"notbefore"`
	NotAfter      string `json:"notafter" yaml:"notafter"`
	FetchTime     string `json:"fetchtime" yaml:"fetchtime"`
}

// Get new Certvals instance with default values
func newCertData() CertData {
	certVals := CertData{}
	tRun := time.Now()
	certVals.CheckTime = tRun.Format(timeFormat)
	certVals.FetchTime = time.Since(tRun).Round(time.Millisecond).String()

	return certVals
}

// CertValsSet a set of certificate value data
type CertValsSet struct {
	Total           int        `json:"total" yaml:"total"`
	HostErrors      int        `json:"hosterrors" yaml:"hosterrors"`
	ExpiredWarnings int        `json:"expirywarnings" yaml:"expirywarnings"`
	CertData        []CertData `json:"certdata" yaml:"certdata"`
}

// NewCertValSet make a new cert val set
func NewCertValSet() *CertValsSet {
	certValSet := new(CertValsSet)
	certValSet.CertData = make([]CertData, 0, 0)

	return certValSet
}

// finalize metadata about the cert data set and sort
func (certValSet *CertValsSet) finalize() {
	for _, v := range certValSet.CertData {
		certValSet.Total++
		if v.HostError {
			certValSet.HostErrors++
		}
		if v.ExpiryWarning == true {
			certValSet.ExpiredWarnings++
		}
	}
	sort.Slice(certValSet.CertData, func(i, j int) bool {
		return certValSet.CertData[i].Host < certValSet.CertData[j].Host
	})
}

// JSON get JSON representation of cert value set
func (certValSet *CertValsSet) JSON() (bytes []byte, err error) {
	// Do JSON output by default
	bytes, err = json.MarshalIndent(&certValSet, "", "  ")
	if err != nil {
		return
	}
	return
}

// YAML get YAML representation of cert value set
func (certValSet *CertValsSet) YAML() (bytes []byte, err error) {
	bytes, err = yaml.Marshal(&certValSet)
	if err != nil {
		return
	}
	return
}

// HostDataSet hosts to process into cert value set
type HostDataSet struct {
	Hosts []string
}

// Add new hosts
func (hosts *HostDataSet) Add(items ...string) {
	hosts.Hosts = append(hosts.Hosts, items...)
}

// NewHostDataSet hosts struct containing a list of hosts
func NewHostDataSet() *HostDataSet {
	hosts := new(HostDataSet)

	return hosts
}

// Process process list of hosts and for each get back cert values
func (hosts *HostDataSet) Process(warnAtDays, timeout int) *CertValsSet {
	var (
		wg           sync.WaitGroup                    // waitgroup to wait for work completion
		certDataChan = make(chan CertData)             // channel for certificate values
		sem          = semaphore.NewWeighted(int64(6)) // Set semaphore with capacity
		semCtx       = context.Background()            // ctx for semaphore
		certValSet   = NewCertValSet()
		hostMap      = make(map[string]bool) // map of hosts to avoid duplicates
	)

	wg.Add(len(hosts.Hosts))

	// function to handle adding cert value data to the channel
	processHosts := func(items []string) {
		for _, item := range items {
			host, port, err := getDomainAndPort(item)
			hostAndPort := fmt.Sprintf("%s:%s", host, port)

			// Skip if this is the same host/port combination
			if hostMap[hostAndPort] {
				// Decrement waitgroup if we are skipping goroutines
				wg.Done()
				continue
			} else {
				// Track that this host has come through
				hostMap[hostAndPort] = true
			}

			if err != nil {
				// Make an empty struct
				go func(err error) {
					// Decrement waitgroup at end of goroutine
					defer wg.Done()
					// This is fast so no need to use semaphore
					certVals := newCertData()
					certVals.HostError = true
					certVals.Message = err.Error()
					certDataChan <- certVals
				}(err)
			} else {
				// Handle getting certdata and adding it to channel
				go func(host, port string) {
					// Decrement waitgroup at end of goroutine
					defer wg.Done()
					// Handle semaphore capacity limiting
					sem.Acquire(semCtx, 1)
					defer sem.Release(1)

					// Add cert data for host to channel
					certDataChan <- getCertData(host, port, warnAtDays, timeout)
				}(host, port)
			}
		}
	}
	processHosts(hosts.Hosts)

	// Wait for WaitGroup to finish then close channel to allow range below to
	// complete.
	go func() {
		wg.Wait()
		// Close channel when done
		close(certDataChan)
	}()

	// Add all cert values from channel to output list
	// Range will block until the channel is closed.
	for certVals := range certDataChan {
		certValSet.CertData = append(certValSet.CertData, certVals)
	}

	certValSet.finalize() // Produce summary values and sort

	return certValSet
}

// Extract host and port from incoming host string
func getDomainAndPort(input string) (host string, port string, err error) {
	if strings.Contains(input, ":") {
		parts := strings.Split(input, ":")
		if len(parts) == 1 {
			host = parts[0]
			port = tlsDefaultPort
		} else if len(parts) == 2 {
			host = parts[0]
			port = parts[1]
		} else {
			err = errors.New("invalid host string " + input)
			return
		}
	} else {
		host = input
		port = tlsDefaultPort
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

// Do check of cert from remote host and populate CertVals
func getCertData(host, port string, warnAtDays int, timeout int) CertData {
	tRun := time.Now()

	certVals := newCertData()
	certVals.Host = host
	certVals.Port = port
	certVals.HostError = false
	certVals.WarnAtDays = warnAtDays
	hostAndPort := fmt.Sprintf("%s:%s", host, port)

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

	// Set issuer
	certVals.Issuer = conn.ConnectionState().PeerCertificates[0].Issuer.String()

	// Set cert not before date
	notBefore := conn.ConnectionState().PeerCertificates[0].NotBefore
	certVals.NotBefore = notBefore.Format(timeFormat)

	// Set cert not after date
	notAfter := conn.ConnectionState().PeerCertificates[0].NotAfter
	certVals.NotAfter = notAfter.Format(timeFormat)

	now := time.Now()
	// nanoseconds to expiry of certificate
	nanosToExpiry := notAfter.UnixNano() - now.UnixNano()

	daysLeft := 0

	// If > one day left report that integer
	if nanosToExpiry > int64(time.Hour+24) {
		daysLeft = int((notAfter.UnixNano() - now.UnixNano()) / int64(time.Hour*24))
	}
	certVals.DaysToExpiry = daysLeft // set days left to expiry

	certVals.TotalDays = int((notAfter.UnixNano() - notBefore.UnixNano()) / int64(time.Hour*24))

	certVals.Message = "OK"
	certVals.CheckTime = time.Now().Format(timeFormat) // set time cert was checked

	// Set expiry flag and fetch time
	expired := (time.Now().Add(time.Duration(warnIf)).UnixNano() > notAfter.UnixNano())
	certVals.ExpiryWarning = expired
	certVals.FetchTime = time.Since(tRun).Round(time.Millisecond).String()

	return certVals
}
