<!-- Code generated by gomarkdoc. DO NOT EDIT -->

# hosts

```go
import "github.com/imarsman/certcheck/pkg/hosts"
```

## Index

- [type CertData](<#type-certdata>)
- [type CertValsSet](<#type-certvalsset>)
  - [func NewCertValSet() *CertValsSet](<#func-newcertvalset>)
  - [func (certValSet *CertValsSet) JSON() (bytes []byte, err error)](<#func-certvalsset-json>)
  - [func (certValSet *CertValsSet) YAML() (bytes []byte, err error)](<#func-certvalsset-yaml>)
- [type Hosts](<#type-hosts>)
  - [func NewHosts() *Hosts](<#func-newhosts>)
  - [func (hosts *Hosts) Add(items ...string)](<#func-hosts-add>)
  - [func (hosts *Hosts) ProcessHosts(warnAtDays, timeout int) *CertValsSet](<#func-hosts-processhosts>)


## type [CertData](<https://github.com/imarsman/certcheck/blob/main/pkg/hosts/hosts.go#L26-L40>)

CertData values for TLS certificate

```go
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
```

## type [CertValsSet](<https://github.com/imarsman/certcheck/blob/main/pkg/hosts/hosts.go#L53-L58>)

CertValsSet a set of certificate value data

```go
type CertValsSet struct {
    Total           int        `json:"total" yaml:"total"`
    HostErrors      int        `json:"hosterrors" yaml:"hosterrors"`
    ExpiredWarnings int        `json:"expirywarnings" yaml:"expirywarnings"`
    CertData        []CertData `json:"certdata" yaml:"certdata"`
}
```

### func [NewCertValSet](<https://github.com/imarsman/certcheck/blob/main/pkg/hosts/hosts.go#L61>)

```go
func NewCertValSet() *CertValsSet
```

NewCertValSet make a new cert val set

### func \(\*CertValsSet\) [JSON](<https://github.com/imarsman/certcheck/blob/main/pkg/hosts/hosts.go#L85>)

```go
func (certValSet *CertValsSet) JSON() (bytes []byte, err error)
```

JSON get JSON representation of cert value set

### func \(\*CertValsSet\) [YAML](<https://github.com/imarsman/certcheck/blob/main/pkg/hosts/hosts.go#L95>)

```go
func (certValSet *CertValsSet) YAML() (bytes []byte, err error)
```

YAML get YAML representation of cert value set

## type [Hosts](<https://github.com/imarsman/certcheck/blob/main/pkg/hosts/hosts.go#L104-L106>)

Hosts hosts to process into cert value set

```go
type Hosts struct {
    Hosts []string
}
```

### func [NewHosts](<https://github.com/imarsman/certcheck/blob/main/pkg/hosts/hosts.go#L114>)

```go
func NewHosts() *Hosts
```

NewHosts hosts struct containing a list of hosts

### func \(\*Hosts\) [Add](<https://github.com/imarsman/certcheck/blob/main/pkg/hosts/hosts.go#L109>)

```go
func (hosts *Hosts) Add(items ...string)
```

Add new hosts

### func \(\*Hosts\) [ProcessHosts](<https://github.com/imarsman/certcheck/blob/main/pkg/hosts/hosts.go#L121>)

```go
func (hosts *Hosts) ProcessHosts(warnAtDays, timeout int) *CertValsSet
```

ProcessHosts process list of hosts and for each get back cert values



Generated by [gomarkdoc](<https://github.com/princjef/gomarkdoc>)