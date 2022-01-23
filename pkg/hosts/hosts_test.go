package hosts

import (
	"testing"

	"github.com/matryer/is"
)

func TestParseHost(t *testing.T) {
	is := is.New(t)

	host, port, err := getDomainAndPort("google.com:443")
	is.NoErr(err)
	is.True(port == "443")

	host, port, err = getDomainAndPort("cisco.com")
	is.NoErr(err)
	is.True(port == "443")

	t.Log("host", host, "port", port)
}

func TestGetCertData(t *testing.T) {
	is := is.New(t)
	host, port, err := getDomainAndPort("google.com:443")
	is.NoErr(err)
	is.True(port == "443")

	certData := getCertData(host, port, 30, 2)

	t.Logf("%+v", certData)

	certData = getCertData("gooble.com", port, 30, 2)
	t.Logf("%+v", certData)
	is.True(certData.HostError == true)

	certData = getCertData("google.com", "27", 30, 1)
	t.Logf("%+v", certData)
	is.True(certData.HostError == true)
	is.True(1 == 1)
}

func TestGetHostDataSet(t *testing.T) {
	is := is.New(t)

	var hosts = NewHostDataSet()
	hosts.AddHosts("ibm.com")
	certDataSet := hosts.Process(30, 10)

	json, err := certDataSet.YAML()
	is.NoErr(err)

	t.Log(string(json))
}
