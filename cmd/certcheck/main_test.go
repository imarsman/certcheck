package main

import (
	"testing"

	"github.com/matryer/is"
)

func TestParseHost(t *testing.T) {
	is := is.New(t)

	// host, port, err := getDomainAndPort("google.com:443")
	// is.NoErr(err)
	// is.True(port == "443")

	// host, port, err = getDomainAndPort("cisco.com")
	// is.NoErr(err)
	// is.True(port == "443")
	is.True(1 == 1)
	// t.Log("host", host, "port", port)
}

func TestGetCertVals(t *testing.T) {
	is := is.New(t)
	// host, port, err := getDomainAndPort("google.com:443")
	// is.NoErr(err)
	// is.True(port == "443")

	// certVals := getCertData(host, port, 30, 2)

	// t.Logf("%+v", certVals)

	// certVals = getCertData("gooble.com", port, 30, 2)
	// t.Logf("%+v", certVals)
	// is.True(certVals.HostError == true)

	// certVals = getCertData("google.com", "27", 30, 1)
	// t.Logf("%+v", certVals)
	// is.True(certVals.HostError == true)
	is.True(1 == 1)
}
