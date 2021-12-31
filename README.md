# TLS certificate check utility

One can use the openssl or curl utilities to get a TLS certificate expiry
information for a domain. This utility allows the same retrieval of validity of
TLS certificate for a domain, a check of a certificate belonging to the domain
being checked, and the added ability to specify a cutoff number of days from the
current date before a certificate is considered to be at risk of expiry.

As far as I can tell Go uses the OS's System TLS certificates to verify that a
called domain matches the domain being checked. The check should be similar to
what a browser carries out.

Examples

YAML output

`% go run . -H google.com:443 cisco.com:443  -y -w 600`

```yaml
- expirywarning: true
  domainerror: false
  message: OK
  domain: google.com
  port: "443"
  warnatdays: 600
  notbefore: "2021-11-29T02:22:33Z"
  notafter: "2022-02-21T02:22:32Z"
- expirywarning: true
  domainerror: false
  message: OK
  domain: cisco.com
  port: "443"
  warnatdays: 600
  notbefore: "2021-03-08T15:57:58Z"
  notafter: "2022-03-08T16:07:00Z"
```

JSON output

`% go run . -H google.com:443 cisco.com:443  -j -w 600`
```json
[
  {
    "expirywarning": true,
    "domainerror": false,
    "message": "OK",
    "domain": "google.com",
    "port": "443",
    "warnatdays": 600,
    "notbefore": "2021-11-29T02:22:33Z",
    "notafter": "2022-02-21T02:22:32Z"
  },
  {
    "expirywarning": true,
    "domainerror": false,
    "message": "OK",
    "domain": "cisco.com",
    "port": "443",
    "warnatdays": 600,
    "notbefore": "2021-03-08T15:57:58Z",
    "notafter": "2022-03-08T16:07:00Z"
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
    "notbefore": "2021-03-08T15:57:58Z",
    "notafter": "2022-03-08T16:07:00Z"
  }
]
```