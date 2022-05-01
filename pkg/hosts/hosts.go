// Package hosts is standalone and as such allows hosts to be looked up separate
// from the main package.

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

	"github.com/imarsman/gcon"
	"golang.org/x/sync/semaphore"
	"gopkg.in/yaml.v2"
)

const (
	timeFormat     = "2006-01-02T15:04:05Z"
	tlsDefaultPort = "443"
)

// func check() {
// 	const rootPEM = `
// -----BEGIN CERTIFICATE-----
// MIIEBDCCAuygAwIBAgIDAjppMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT
// MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
// YWwgQ0EwHhcNMTMwNDA1MTUxNTU1WhcNMTUwNDA0MTUxNTU1WjBJMQswCQYDVQQG
// EwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzElMCMGA1UEAxMcR29vZ2xlIEludGVy
// bmV0IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
// AJwqBHdc2FCROgajguDYUEi8iT/xGXAaiEZ+4I/F8YnOIe5a/mENtzJEiaB0C1NP
// VaTOgmKV7utZX8bhBYASxF6UP7xbSDj0U/ck5vuR6RXEz/RTDfRK/J9U3n2+oGtv
// h8DQUB8oMANA2ghzUWx//zo8pzcGjr1LEQTrfSTe5vn8MXH7lNVg8y5Kr0LSy+rE
// ahqyzFPdFUuLH8gZYR/Nnag+YyuENWllhMgZxUYi+FOVvuOAShDGKuy6lyARxzmZ
// EASg8GF6lSWMTlJ14rbtCMoU/M4iarNOz0YDl5cDfsCx3nuvRTPPuj5xt970JSXC
// DTWJnZ37DhF5iR43xa+OcmkCAwEAAaOB+zCB+DAfBgNVHSMEGDAWgBTAephojYn7
// qwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUSt0GFhu89mi1dvWBtrtiGrpagS8wEgYD
// VR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwOgYDVR0fBDMwMTAvoC2g
// K4YpaHR0cDovL2NybC5nZW90cnVzdC5jb20vY3Jscy9ndGdsb2JhbC5jcmwwPQYI
// KwYBBQUHAQEEMTAvMC0GCCsGAQUFBzABhiFodHRwOi8vZ3RnbG9iYWwtb2NzcC5n
// ZW90cnVzdC5jb20wFwYDVR0gBBAwDjAMBgorBgEEAdZ5AgUBMA0GCSqGSIb3DQEB
// BQUAA4IBAQA21waAESetKhSbOHezI6B1WLuxfoNCunLaHtiONgaX4PCVOzf9G0JY
// /iLIa704XtE7JW4S615ndkZAkNoUyHgN7ZVm2o6Gb4ChulYylYbc3GrKBIxbf/a/
// zG+FA1jDaFETzf3I93k9mTXwVqO94FntT0QJo544evZG0R0SnU++0ED8Vf4GXjza
// HFa9llF7b1cq26KqltyMdMKVvvBulRP/F/A8rLIQjcxz++iPAsbw+zOzlTvjwsto
// WHPbqCRiOwY1nQ2pM714A5AuTHhdUDqB1O6gyHA43LL5Z/qHQF1hwFGPa4NrzQU6
// yuGnBXj8ytqU0CwIPX4WecigUCAkVDNx
// -----END CERTIFICATE-----`

// 	block, _ := pem.Decode([]byte(rootPEM))
// 	var cert *x509.Certificate
// 	cert, _ = x509.ParseCertificate(block.Bytes)
// 	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)
// 	fmt.Println(rsaPublicKey.N)
// 	fmt.Println(rsaPublicKey.E)
// }

// CertData values for a TLS certificate
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

// CertDataSet a set of TLS certificate data for a list of hosts plus summary
type CertDataSet struct {
	Total           int        `json:"total" yaml:"total"`
	HostErrors      int        `json:"hosterrors" yaml:"hosterrors"`
	ExpiredWarnings int        `json:"expirywarnings" yaml:"expirywarnings"`
	CertData        []CertData `json:"certdata" yaml:"certdata"`
}

// NewCertDataSet new cert data set
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

// JSON get JSON representation of data for a host certificate
func (certData *CertData) JSON() (bytes []byte, err error) {
	// Do JSON output by default
	bytes, err = json.MarshalIndent(&certData, "", "  ")
	if err != nil {
		return
	}
	return
}

// YAML get YAML representation of data for a host certificate
func (certData *CertData) YAML() (bytes []byte, err error) {
	bytes, err = yaml.Marshal(&certData)
	if err != nil {
		return
	}
	return
}

// JSON get JSON representation of data for a set of host certificates
func (certDataSet *CertDataSet) JSON() (bytes []byte, err error) {
	// Do JSON output by default
	bytes, err = json.MarshalIndent(&certDataSet, "", "  ")
	if err != nil {
		return
	}
	return
}

// YAML get YAML representation of data for a set of host certificates
func (certDataSet *CertDataSet) YAML() (bytes []byte, err error) {
	bytes, err = yaml.Marshal(&certDataSet)
	if err != nil {
		return
	}
	return
}

// HostSet hosts to process into cert value set
type HostSet struct {
	Hosts []string
}

// AddHosts add hosts to HostDataSet
func (hostSet *HostSet) AddHosts(items ...string) {
	hostSet.Hosts = append(hostSet.Hosts, items...)
}

// NewHostSet hosts struct containing a list of hosts
func NewHostSet() *HostSet {
	hosts := new(HostSet)

	return hosts
}

// Semaphore is for all requests to Process
var (
	sem    = semaphore.NewWeighted(int64(6)) // Set semaphore with capacity
	semCtx = context.Background()            // ctx for semaphore
)

var mu = new(sync.Mutex)

// Process2 process list of hosts and for each get back cert values
func (hostSet *HostSet) Process2(warnAtDays, timeout int) *CertDataSet {
	var (
		certDataSet = NewCertDataSet()
		hostMap     = make(map[string]bool) // map of hosts to avoid duplicates
	)

	processHost := func(ctx context.Context, item string) (certData CertData, err error) {
		host, port, err := getDomainAndPort(item)
		hostAndPort := fmt.Sprintf("%s:%s", host, port)

		var foundHostAndPort = func(string) (found bool) {
			mu.Lock()
			defer mu.Unlock()

			if hostMap[hostAndPort] {
				found = true
				return
			}
			hostMap[hostAndPort] = true

			return
		}

		if foundHostAndPort(hostAndPort) {
			return
		}

		if err != nil {
			certData = newCertData()
			certData.HostError = true
			certData.Message = err.Error()
		} else {
			// Add cert data for host to channel
			certData = getCertData(host, port, warnAtDays, timeout)
		}

		return
	}

	ctx := context.Background()

	var runList = []*gcon.Promise[CertData]{}
	for _, v := range hostSet.Hosts {
		runList = append(runList, gcon.Run(ctx, v, processHost))
	}

	// Go through the Run list, waiting for any that are not finished
	for _, p := range runList {
		v, err := p.Get()
		if err != nil {
			fmt.Println(err)
		}
		certDataSet.CertData = append(certDataSet.CertData, v)
	}

	certDataSet.finalize() // Produce summary values and sort

	return certDataSet
}

// Process process list of hosts and for each get back cert values
func (hostSet *HostSet) Process(warnAtDays, timeout int) *CertDataSet {
	var (
		wg           sync.WaitGroup        // waitgroup to wait for work completion
		certDataChan = make(chan CertData) // channel for certificate values
		certDataSet  = NewCertDataSet()
		hostMap      = make(map[string]bool) // map of hosts to avoid duplicates
	)

	wg.Add(len(hostSet.Hosts))

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
	processHosts(hostSet.Hosts)

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
