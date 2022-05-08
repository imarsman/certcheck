package hosts

// Package hosts is standalone and as such allows hosts to be looked up separate
// from the main package.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/imarsman/certcheck/pkg/gcon"
	"golang.org/x/sync/semaphore"
	"gopkg.in/yaml.v2"
)

const (
	timeFormat     = "2006-01-02T15:04:05Z"
	tlsDefaultPort = "443"
)

type hostSkipError struct {
	msg string
}

func newHostSkipError(msg string) error {
	hostSkipError := hostSkipError{msg: msg}

	return &hostSkipError
}

func (e *hostSkipError) Error() string {
	return e.msg
}

// For if file-based check makes sense
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
	Host          string `json:"host" yaml:"host"`
	HostError     bool   `json:"hosterror" yaml:"hosterror"`
	Message       string `json:"message" yaml:"message"`
	ExpiryWarning bool   `json:"expirywarning" yaml:"expirywarning"`
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

// Add add hosts to HostDataSet
func (hostSet *HostSet) Add(items ...string) {
	hostSet.Hosts = append(hostSet.Hosts, items...)
}

// NewHostSet hosts struct containing a list of hosts
func NewHostSet() *HostSet {
	hostSet := new(HostSet)

	return hostSet
}

// Extract host and port from incoming host string
func domainAndPort(input string) (host string, port string, err error) {
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
func lookupCertData(host, port string, warnAtDays int, timeout time.Duration) (certData CertData, err error) {
	tRun := time.Now()

	certData.Host = host
	certData.Port = port
	certData.WarnAtDays = warnAtDays

	hostAndPort := fmt.Sprintf("%s:%s", host, port)

	warnAt := warnAtDays * 24 * int(time.Hour)

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(
		dialer,
		"tcp",
		hostAndPort, nil)
	if err != nil {
		certData.FetchTime = time.Since(tRun).Round(time.Millisecond).String()
		return
	}

	err = conn.VerifyHostname(host)
	if err != nil {
		certData.FetchTime = time.Since(tRun).Round(time.Millisecond).String()
		return
	}

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
	certData.CheckTime = now.Format(timeFormat) // set time cert was checked

	// Set expiry flag and fetch time
	isExpired := (time.Now().Add(time.Duration(warnAt)).UnixNano() > notAfter.UnixNano())
	certData.ExpiryWarning = isExpired
	certData.FetchTime = time.Since(tRun).Round(time.Millisecond).String()

	return
}

var mu = new(sync.Mutex)

// Process process list of hosts and for each get back cert values
func (hostSet *HostSet) Process(warnAtDays int, timeout time.Duration) *CertDataSet {
	var (
		certDataSet = NewCertDataSet()
		hostMap     = make(map[string]bool)                          // map of hosts to avoid duplicates
		sem         = semaphore.NewWeighted(int64(runtime.NumCPU())) // Set semaphore with capacity
	)

	processHost := func(ctx context.Context, item string) (certData CertData, err error) {
		sem.Acquire(context.Background(), 1)
		defer sem.Release(1)
		host, port, err := domainAndPort(item)
		if err != nil {
			certData.Host = item

			return
		}
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

		// Set skipError for duplicate host
		if foundHostAndPort(hostAndPort) {
			// Later code will skip adding this to output
			err = newHostSkipError("already processed")

			return
		}

		certData.Host = host

		// Add cert data for host to channel
		certData, err = lookupCertData(host, port, warnAtDays, timeout)
		if err != nil {
			return
		}

		return
	}

	// Make a list of promises and let them start running
	// var runList = []*gcon.Promise[CertData]{}
	var promiseSet = gcon.NewPromiseSet[CertData]()

	for _, host := range hostSet.Hosts {
		ctx := context.Background()
		// Set timeout for run of host TLS information gathering
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		promise := gcon.Run(ctx, host, processHost)
		promiseSet.Add(promise)
	}

	// Wait for all to be done
	promiseSet.Wait()

	// Go through the Run list, waiting for all that are not finished
	for _, p := range promiseSet.Promises {
		certData, err := p.Get()
		// If there is an error make a minimal error result
		if err != nil {
			var skipError *hostSkipError
			if errors.As(err, &skipError) {
				continue
			}
			certData.HostError = true
			certData.Message = err.Error()
		}
		certDataSet.CertData = append(certDataSet.CertData, certData)
	}

	certDataSet.finalize() // Produce summary values and sort

	return certDataSet
}
