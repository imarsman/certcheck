package hosts

import (
	"strings"
	"testing"

	"github.com/matryer/is"
)

func TestParseHost(t *testing.T) {
	is := is.New(t)

	host, port, err := domainAndPort("google.com:443")
	is.NoErr(err)
	is.True(port == "443")

	host, port, err = domainAndPort("cisco.com")
	is.NoErr(err)
	is.True(port == "443")

	t.Log("host", host, "port", port)
}

func TestGetCertData(t *testing.T) {
	is := is.New(t)
	host, port, err := domainAndPort("google.com:443")
	is.NoErr(err)
	is.True(port == "443")

	certData, err := getCertData(host, port, 30, 2)
	is.NoErr(err)

	t.Logf("%+v", certData)

	certData, err = getCertData("goobbble.com", port, 30, 2)
	is.True(err == nil)
	t.Logf("%+v", certData)
	is.True(certData.HostError == true)

	certData, err = getCertData("google.com", "27", 30, 1)
	is.NoErr(err)

	t.Logf("%+v", certData)
	is.True(certData.HostError == true)
	is.True(1 == 1)
}

func TestGetHostDataSet(t *testing.T) {
	is := is.New(t)

	var hosts = NewHostSet()
	hosts.Add("ibm.com")
	certDataSet := hosts.Process(30, 10)

	json, err := certDataSet.YAML()
	is.NoErr(err)

	t.Log(string(json))
}

func TestLoop(t *testing.T) {
	is := is.New(t)

	hosts := strings.Split("ibm.com bbc.com amazon.com microsoft.com cisco.com workday.com o.canada.com www.thespec.com www.thestar.com www.parliament.gov.za www.gov.za oracle.com:27", " ")

	var hostSet = NewHostSet()
	for _, host := range hosts {
		hostSet.Add(host)
	}
	var certDataSet = hostSet.Process(30, 30)

	count := len(certDataSet.CertData)
	for i := 0; i < 20; i++ {
		certDataSet = hostSet.Process(30, 5)
		newCount := len(certDataSet.CertData)
		t.Log(count, newCount)
		is.True(count == newCount)
	}
}
