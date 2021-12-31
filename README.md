# TLS certificate check utility

One can use the openssl or curl utilities to get a TLS certificate expiry
information for a domain. This utility allows the same retrieval of validity of
TLS certificate for a domain, a check of a certificate belonging to the domain
being checked, and the added ability to specify a cutoff number of days from the
current date before a certificate is considered to be at risk of expiry.

As far as I can tell Go uses the OS's System TLS certificates to verify that a
called domain matches the domain being checked. The check should be similar to
what a browser carries out.

Help output

`% certcheck -h`
```
Usage: certcheck [--hosts HOSTS] [--timeout TIMEOUT] [--warnatdays WARNATDAYS] [--yaml] [--json]

Options:
  --hosts HOSTS, -H HOSTS
                         host:port list to check
  --timeout TIMEOUT, -t TIMEOUT
                         connection timeout seconds [default: 10]
  --warnatdays WARNAT -w WARNAT
                         warn if expiry before days [default: 30]
  --yaml, -y             display output as YAML
  --json, -j             display output as JSON (default)
  --help, -h             display this help and exit
```

Examples

YAML output

`% certcheck -H google.com -w 54 -y`
```yaml
- expirywarning: true
  hosterror: false
  message: OK
  host: google.com
  port: "443"
  warnatdays: 54
  checktime: "2021-12-30T20:31:32Z"
  notbefore: "2021-11-29T02:22:33Z"
  notafter: "2022-02-21T02:22:32Z"
```

JSON output

`% certcheck -H google.com -w 54 -j`
```json
[
  {
    "expirywarning": true,
    "hosterror": false,
    "message": "OK",
    "host": "google.com",
    "port": "443",
    "warnatdays": 54,
    "checktime": "2021-12-30T20:32:38Z",
    "notbefore": "2021-11-29T02:22:33Z",
    "notafter": "2022-02-21T02:22:32Z"
  }
]
```

You can also send stdin to the app. If you send space separated domains they
will be split out. If you send newline delimited domains they will be split out
and will have lines with more than one domain split.

`% echo "google.com:443 cisco.com:443" | ./certcheck`
```json
[
  {
    "expirywarning": false,
    "hosterror": false,
    "message": "OK",
    "host": "google.com",
    "port": "443",
    "warnatdays": 30,
    "checktime": "2021-12-30T20:34:15Z",
    "notbefore": "2021-11-29T02:22:33Z",
    "notafter": "2022-02-21T02:22:32Z"
  },
  {
    "expirywarning": false,
    "hosterror": false,
    "message": "OK",
    "host": "cisco.com",
    "port": "443",
    "warnatdays": 30,
    "checktime": "2021-12-30T20:34:15Z",
    "notbefore": "2021-03-08T15:57:58Z",
    "notafter": "2022-03-08T16:07:00Z"
  }
]
```