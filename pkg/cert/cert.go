package cert

import (
	"crypto/x509"
	"encoding/pem"
)

// pemFirstCertificate get first certificate in PEM
func pemFirstCertificate(PEMRest []byte) *pem.Block {
	for {
		block, rest := pem.Decode(PEMRest)
		if block == nil {
			break
		}
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
