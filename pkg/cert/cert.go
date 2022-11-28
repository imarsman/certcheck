package cert

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// pemCertificateBlocks get first certificate in PEM
// https://fale.io/blog/2017/12/21/walkthrough-a-pem-file-in-go
func pemCertificateBlocks(PEMRest []byte) (blocks []*pem.Block) {
	for {
		block, rest := pem.Decode(PEMRest)
		if block == nil {
			break
		}
		// Type is a simple extration of the word in a block after BEGIN
		// e.g. -----BEGIN CERTIFICATE-----
		if block.Type == `CERTIFICATE` {
			blocks = append(blocks, block)
		}
		if len(rest) == 0 {
			break
		}
		PEMRest = rest
	}
	return blocks
}

// ReadCert read a PEM encoded X509 certificate file
func ReadCert(input []byte) (cert *x509.Certificate, err error) {
	blocks := pemCertificateBlocks(input)

	// Bad input file
	if len(blocks) == 0 {
		err = errors.New("no pem blocks found")
		return
	}
	for _, block := range blocks {
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic("failed to parse certificate: " + err.Error())
		}
		// Server certificate should have 1 or more DNS names
		// There may be > 1 of these in a PEM file but currently we are stopping
		// at the first found
		if len(cert.DNSNames) > 0 {
			break
		}
	}

	return
}
