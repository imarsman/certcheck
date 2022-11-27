package cert

import (
	"crypto/x509"
	"encoding/pem"
)

func ReadCert(bytes []byte) (cert *x509.Certificate, err error) {
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(bytes)
	if !ok {
		panic("failed to parse root certificate")
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	return
}
