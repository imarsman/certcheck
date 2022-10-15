# TLS certificate check utility

One can use the `openssl` or `curl` utilities to get a TLS certificate expiry information for a domain. This utility
allows the same retrieval of validity of TLS certificate for a domain, a check of a certificate belonging to the domain
being investigated, and the added ability to specify a cutoff number of days from the current date before a certificate
is considered to be at risk of expiry.

Go looks up root certificats in OS specific code at `go/src/crypto/x509/` in files `root_[OS].go`. I am not positive
currently how much checking is done when verifying a certificate.

This app has been optimized to run checks against multiple hosts in parallel with maximum concurrency controlled by a
semaphore. The Tasfile test task runs 11 host checks which, because they are running in parallel, takes on average about
100 ms for each to run, using a semaphore with a capacity of the number of cores.

The semaphore library used is Golang's `x/sync/semaphore` package, which is in the Golang sub-repository collection.
Golang core libraries have a strong promise not to change API, but sub-repository libraries are not so strict. The
semaphore library provides a weighted semaphore, and the code uses a weight value of 1 for each reservation, which makes
it act like a standard semaphore.

This code uses a small generic promise package, `gcon`. It works as well as the previous code, which used a waitgroup
and a channel. Both methods work fine. The promise pattern would be more useful if things like `then` were to be used to
process data in steps in a deterministic way. As it stands each certificate is checked independently.

Earlier commits included lots of duplicate setting of the host data structure. That has been cleaned up. Errors for host
lookups are reported unless the host error is of type hostSkipError (for duplicates). The goal was to report every host
in the output whether that host's lookup succeeded or not.

In case it was ever useful to use just the host checking code outside of the main package, that code has been put in its
own package at pkg/hosts.

## Help output

```
$ certcheck -h
certcheck
---------
Commit:  20d55a5
Date:    2022-10-15T02:48:39Z
Tag:     v0.1.0
OS:      darwin
ARCH:    arm64

Usage: certcheck [--hosts HOSTS] [--timeout TIMEOUT] [--warn-at-days WARNAT] [--yaml] [--json]

Options:
  --hosts HOSTS, -H HOSTS
                         host:port list to check
  --timeout TIMEOUT, -t TIMEOUT
                         connection timeout seconds [default: 10]
  --warn-at-days WARNAT, -w WARNAT
                         warn if expiry before days [default: 30]
  --yaml, -y             display output as YAML
  --json, -j             display output as JSON (default)
  --help, -h             display this help and exit
  --version              display version and exit
```

## Completion

`certcheck` uses completion using the [posener](https://github.com/posener/complete/tree/master) library. To activate
it, once `certcheck` is in your path, type `COMP_INSTALL=1 certcheck`. You will be asked to confirm that you wish to
have completion support added to your shell config. After running this you will need to refresh your terminal session or
start a new one. If you use `zsh` your `.zshrc` fill will contain `complete -o nospace -C /path/to/certcheck certcheck`.

## Examples

### YAML output

`% certcheck google.com -warn-at-days 54 -yaml`
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

`% certcheck google.com -warn-at-days 54 -json`
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

`$ certcheck -hosts google.com:43 -t 1 -yaml`
```YAML
total: 1
hosterrors: 1
expirywarnings: 0
certdata:
- host: google.com
  hosterror: true
  message: 'dial tcp 142.251.41.78:43: i/o timeout'
  expirywarning: false
  issuer: ""
  port: "43"
  totaldays: 0
  daystoexpiry: 0
  warnatdays: 30
  checktime: ""
  notbefore: ""
  notafter: ""
  fetchtime: 1.001s
```

## Lines of code

```
$ gocloc cmd pkg README.md
-------------------------------------------------------------------------------
Language                     files          blank        comment           code
-------------------------------------------------------------------------------
Go                               5            173            170            851
Markdown                         3             98              0            326
-------------------------------------------------------------------------------
TOTAL                            8            271            170           1177
-------------------------------------------------------------------------------
```