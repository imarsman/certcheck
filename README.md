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

This app has been optimized to run checks against all hosts in parallel with
some rate limiting.

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
- expirywarning: true
  hosterror: false
  message: OK
  host: google.com
  port: "443"
  daysleft: 51
  warnatdays: 54
  checktime: "2021-12-31T12:16:33Z"
  notbefore: "2021-11-29T02:22:33Z"
  notafter: "2022-02-21T02:22:32Z"
  fetchtime: 290ms
```

### JSON output

`% certcheck google.com -w 54 -j`
```json
[
  {
    "expirywarning": true,
    "hosterror": false,
    "message": "OK",
    "host": "google.com",
    "port": "443",
    "daysleft": 51,
    "warnatdays": 54,
    "checktime": "2021-12-31T12:16:52Z",
    "notbefore": "2021-11-29T02:22:33Z",
    "notafter": "2022-02-21T02:22:32Z",
    "fetchtime": "218ms"
  }
]
```

## Stdin to app for host list

You can also send stdin to the app. If you send space separated domains they
will be split out. If you send newline delimited domains they will be split out
and will have lines with more than one domain split.

`% echo "google.com:443 cisco.com:443" | certcheck`
```json
[
  {
    "expirywarning": false,
    "hosterror": false,
    "message": "OK",
    "host": "google.com",
    "port": "443",
    "daysleft": 51,
    "warnatdays": 30,
    "checktime": "2021-12-31T12:17:32Z",
    "notbefore": "2021-11-29T02:22:33Z",
    "notafter": "2022-02-21T02:22:32Z",
    "fetchtime": "208ms"
  },
  {
    "expirywarning": false,
    "hosterror": false,
    "message": "OK",
    "host": "cisco.com",
    "port": "443",
    "daysleft": 66,
    "warnatdays": 30,
    "checktime": "2021-12-31T12:17:32Z",
    "notbefore": "2021-03-08T15:57:58Z",
    "notafter": "2022-03-08T16:07:00Z",
    "fetchtime": "325ms"
  }
]
```

## Errors

Here is output from a call with a port with no TLS. Note the usefulness of
having a minimal timeout value in case of errors.

`% certcheck google.com:43 -t 1 -y`
```YAML
- expirywarning: false
  hosterror: true
  message: 'Server doesn''t support TLS certificate err: %!s(MISSING)dial tcp 142.251.32.78:43:
    i/o timeout'
  host: google.com
  port: "43"
  daysleft: 0
  warnatdays: 30
  checktime: "2021-12-31T12:17:53Z"
  notbefore: ""
  notafter: ""
  fetchtime: 1.000876542s
```