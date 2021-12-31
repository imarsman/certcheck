package main

import (
	"testing"

	"github.com/matryer/is"
)

func TestParseHost(t *testing.T) {
	is := is.New(t)

	host, port, err := getParts("google.com:443")
	is.NoErr(err)
	is.True(port == "443")

	host, port, err = getParts("cisco.com")
	is.NoErr(err)
	is.True(port == "443")

	t.Log("host", host, "port", port)
}

func TestGetCertVals(t *testing.T) {
	is := is.New(t)
	host, port, err := getParts("google.com:443")
	is.NoErr(err)
	is.True(port == "443")

	certVals := getCertVals(host, port, 30, 2)

	t.Logf("%+v", certVals)

	certVals = getCertVals("gooble.com", port, 30, 2)
	t.Logf("%+v", certVals)
	is.True(certVals.HostError == true)

	certVals = getCertVals("google.com", "27", 30, 1)
	t.Logf("%+v", certVals)
	is.True(certVals.HostError == true)
}
