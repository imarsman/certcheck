# TLS certificate check utility

One can use the `openssl` or `curl` utilities to get a TLS certificate expiry
information for a domain. This utility allows the same retrieval of validity of
TLS certificate for a domain, a check of a certificate belonging to the domain
being investigated, and the added ability to specify a cutoff number of days
from the current date before a certificate is considered to be at risk of
expiry.

Go looks up root certificats in OS specific code at `go/src/crypto/x509/` in
files `root_[OS].go`. I am not positive currently how much checking is done when
verifying a certificate.

This app has been optimized to run checks against multiple hosts in parallel
with maximum concurrency controlled by a semaphore. The Tasfile test task runs
11 host checks which, because they are running in parallel, takes on average
under 110 ms for each to run, using a semaphore with a capacity of 6. 

The semaphore library used is Golang's x/sync/semaphore package, which is in the
Golang sub-repository collection. Golang core libraries have a strong promise
not to change API, but sub-repository libraries are not so strict. The semaphore
library provides a weighted semaphore, and the code uses a weight value of 1 for
each reservation, which makes it act like a standard semaphore.

## Help output

`% certcheck -h`
```
Usage: certcheck [--timeout TIMEOUT] [--warnatdays WARNAT] [--yaml] [--json] [HOSTS [HOSTS ...]]

Positional arguments:
  HOSTS                  host:port list to check

Options:
  --timeout TIMEOUT, -t TIMEOUT
                         connection timeout seconds [default: 10]
  --warnatdays WARNAT, -w WARNAT
                         warn if expiry before days [default: 30]
  --yaml, -y             display output as YAML
  --json, -j             display output as JSON (default)
  --help, -h             display this help and exit
```

## Examples

### YAML output

`% certcheck google.com -w 54 -y`
```yaml
total: 1
hosterrors: 0
expirywarnings: 1
certdata:
- expirywarning: true
  hosterror: false
  message: OK
  host: google.com
  issuer: CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
  port: "443"
  daystoexpiry: 51
  warnatdays: 54
  checktime: "2021-12-31T16:03:54Z"
  notbefore: "2021-11-29T02:22:33Z"
  notafter: "2022-02-21T02:22:32Z"
  fetchtime: 247ms
```

### JSON output

`% certcheck google.com -w 54 -j`
```json
{
  "total": 1,
  "hosterrors": 0,
  "expirywarnings": 1,
  "certdata": [
    {
      "expirywarning": true,
      "hosterror": false,
      "message": "OK",
      "host": "google.com",
      "issuer": "CN=GTS CA 1C3,O=Google Trust Services LLC,C=US",
      "port": "443",
      "daystoexpiry": 51,
      "warnatdays": 54,
      "checktime": "2021-12-31T16:04:13Z",
      "notbefore": "2021-11-29T02:22:33Z",
      "notafter": "2022-02-21T02:22:32Z",
      "fetchtime": "206ms"
    }
  ]
}
```

## Stdin to app for host list

You can also send stdin to the app. If you send space separated domains they
will be split out. If you send newline delimited domains they will be split out
and will have lines with more than one domain split.

`% echo "google.com:443 cisco.com:443" | certcheck`
```json
{
  "total": 2,
  "hosterrors": 0,
  "expirywarnings": 0,
  "certdata": [
    {
      "expirywarning": false,
      "hosterror": false,
      "message": "OK",
      "host": "cisco.com",
      "issuer": "CN=HydrantID SSL CA G3,O=HydrantID (Avalanche Cloud Corporation),C=US",
      "port": "443",
      "daystoexpiry": 66,
      "warnatdays": 30,
      "checktime": "2021-12-31T16:04:37Z",
      "notbefore": "2021-03-08T15:57:58Z",
      "notafter": "2022-03-08T16:07:00Z",
      "fetchtime": "288ms"
    },
    {
      "expirywarning": false,
      "hosterror": false,
      "message": "OK",
      "host": "google.com",
      "issuer": "CN=GTS CA 1C3,O=Google Trust Services LLC,C=US",
      "port": "443",
      "daystoexpiry": 51,
      "warnatdays": 30,
      "checktime": "2021-12-31T16:04:37Z",
      "notbefore": "2021-11-29T02:22:33Z",
      "notafter": "2022-02-21T02:22:32Z",
      "fetchtime": "221ms"
    }
  ]
}
```

## Errors

Here is output from a call with a port with no TLS. Note the usefulness of
having a minimal timeout value in case of errors.

`% certcheck google.com:43 -t 1 -y`
```YAML
total: 1
hosterrors: 1
expirywarnings: 0
certdata:
- expirywarning: false
  hosterror: true
  message: 'Server doesn''t support TLS certificate err: %!s(MISSING)dial tcp 142.251.32.78:43:
    i/o timeout'
  host: google.com
  issuer: ""
  port: "43"
  daystoexpiry: 0
  warnatdays: 30
  checktime: "2021-12-31T16:05:09Z"
  notbefore: ""
  notafter: ""
  fetchtime: 1.001580167s
```