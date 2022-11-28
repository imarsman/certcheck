package cert

import (
	"crypto/x509"
	"encoding/pem"
)

// pemFirstCertificate get first certificate in PEM
// https://fale.io/blog/2017/12/21/walkthrough-a-pem-file-in-go
func pemFirstCertificate(PEMRest []byte) *pem.Block {
	for {
		block, rest := pem.Decode(PEMRest)
		if block == nil {
			break
		}
		// Type is a simple extration of the word in a block after BEGIN
		// e.g. -----BEGIN CERTIFICATE-----
		if block.Type == `CERTIFICATE` {
			return block
		}
		if len(rest) == 0 {
			break
		}
		PEMRest = rest
	}
	return nil
}

// ReadCert read a PEM encoded X509 certificate file
func ReadCert(bytes []byte) (cert *x509.Certificate, err error) {
	block := pemFirstCertificate(bytes)
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	return
}
