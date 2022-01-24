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

// Get new CertData instance with default values
func newCertData() CertData {
	certData := CertData{}
	tRun := time.Now()
	certData.CheckTime = tRun.Format(timeFormat)
	certData.FetchTime = time.Since(tRun).Round(time.Millisecond).String()

	return certData
}

// CertDataSet a set of certificate value data
type CertDataSet struct {
	Total           int        `json:"total" yaml:"total"`
	HostErrors      int        `json:"hosterrors" yaml:"hosterrors"`
	ExpiredWarnings int        `json:"expirywarnings" yaml:"expirywarnings"`
	CertData        []CertData `json:"certdata" yaml:"certdata"`
}

// NewCertDataSet make a new cert val set
func NewCertDataSet() *CertDataSet {
	certDataSet := new(CertDataSet)
	certDataSet.CertData = make([]CertData, 0, 0)

	return certDataSet
}

// finalize metadata about the cert data set and sort
func (certDataSet *CertDataSet) finalize() {
	for _, v := range certDataSet.CertData {
		certDataSet.Total++
		if v.HostError {
			certDataSet.HostErrors++
		}
		if v.ExpiryWarning == true {
			certDataSet.ExpiredWarnings++
		}
	}
	sort.Slice(certDataSet.CertData, func(i, j int) bool {
		return certDataSet.CertData[i].Host < certDataSet.CertData[j].Host
	})
}

// JSON get JSON representation of cert value set
func (certDataSet *CertDataSet) JSON() (bytes []byte, err error) {
	// Do JSON output by default
	bytes, err = json.MarshalIndent(&certDataSet, "", "  ")
	if err != nil {
		return
	}
	return
}

// YAML get YAML representation of cert value set
func (certDataSet *CertDataSet) YAML() (bytes []byte, err error) {
	bytes, err = yaml.Marshal(&certDataSet)
	if err != nil {
		return
	}
	return
}

// HostDataSet hosts to process into cert value set
type HostDataSet struct {
	Hosts []string
}

// AddHosts new hosts
func (hosts *HostDataSet) AddHosts(items ...string) {
	hosts.Hosts = append(hosts.Hosts, items...)
}

// NewHostDataSet hosts struct containing a list of hosts
func NewHostDataSet() *HostDataSet {
	hosts := new(HostDataSet)

	return hosts
}

// Semaphore is for all requests to Process
var (
	sem    = semaphore.NewWeighted(int64(6)) // Set semaphore with capacity
	semCtx = context.Background()            // ctx for semaphore
)

// Process process list of hosts and for each get back cert values
func (hosts *HostDataSet) Process(warnAtDays, timeout int) *CertDataSet {
	var (
		wg           sync.WaitGroup        // waitgroup to wait for work completion
		certDataChan = make(chan CertData) // channel for certificate values
		certDataSet  = NewCertDataSet()
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
					sem.Acquire(semCtx, 1)
					defer sem.Release(1)
					// Decrement waitgroup at end of goroutine
					defer wg.Done()
					// This is fast so no need to use semaphore
					certData := newCertData()
					certData.HostError = true
					certData.Message = err.Error()
					certDataChan <- certData
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
	for certData := range certDataChan {
		certDataSet.CertData = append(certDataSet.CertData, certData)
	}

	certDataSet.finalize() // Produce summary values and sort

	return certDataSet
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

// Do check of cert from remote host and populate CertData
func getCertData(host, port string, warnAtDays int, timeout int) CertData {
	tRun := time.Now()

	certData := newCertData()
	certData.Host = host
	certData.Port = port
	certData.HostError = false
	certData.WarnAtDays = warnAtDays
	hostAndPort := fmt.Sprintf("%s:%s", host, port)

	warnIf := warnAtDays * 24 * int(time.Hour)

	dialer := &net.Dialer{Timeout: time.Duration(timeout) * time.Second}

	conn, err := tls.DialWithDialer(
		dialer,
		"tcp",
		hostAndPort, nil)
	if err != nil {
		certData.HostError = true
		certData.Message = fmt.Sprintf("Server doesn't support TLS certificate err: %s" + err.Error())
		certData.FetchTime = time.Since(tRun).String()

		return certData
	}

	err = conn.VerifyHostname(host)
	if err != nil {
		certData.HostError = true
		certData.Message = fmt.Sprintf("Hostname doesn't match with certificate: %s" + err.Error())
		certData.FetchTime = time.Since(tRun).String()

		return certData
	}
	certData.HostError = false

	// Set issuer
	certData.Issuer = conn.ConnectionState().PeerCertificates[0].Issuer.String()

	// Set cert not before date
	notBefore := conn.ConnectionState().PeerCertificates[0].NotBefore
	certData.NotBefore = notBefore.Format(timeFormat)

	// Set cert not after date
	notAfter := conn.ConnectionState().PeerCertificates[0].NotAfter
	certData.NotAfter = notAfter.Format(timeFormat)

	now := time.Now()
	// nanoseconds to expiry of certificate
	nanosToExpiry := notAfter.UnixNano() - now.UnixNano()

	daysLeft := 0

	// If > one day left report that integer
	if nanosToExpiry > int64(time.Hour+24) {
		daysLeft = int((notAfter.UnixNano() - now.UnixNano()) / int64(time.Hour*24))
	}
	certData.DaysToExpiry = daysLeft // set days left to expiry

	certData.TotalDays = int((notAfter.UnixNano() - notBefore.UnixNano()) / int64(time.Hour*24))

	certData.Message = "OK"
	certData.CheckTime = time.Now().Format(timeFormat) // set time cert was checked

	// Set expiry flag and fetch time
	expired := (time.Now().Add(time.Duration(warnIf)).UnixNano() > notAfter.UnixNano())
	certData.ExpiryWarning = expired
	certData.FetchTime = time.Since(tRun).Round(time.Millisecond).String()

	return certData
}
