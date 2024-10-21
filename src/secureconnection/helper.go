package secureconnection

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

func checkPath(p string) error {
	if p == "" {
		return nil
	}
	if _, err := os.Stat(p); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("file %s does not exist (%s)", p, err)
		}
		return fmt.Errorf("error file %s (%s)", p, err)
	}
	return nil
}

func getPemCertificate(path string) (*x509.CertPool, error) {
	cert, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rootCAs := x509.NewCertPool()
	if ok := rootCAs.AppendCertsFromPEM(cert); !ok {
		return nil, fmt.Errorf("failed to append PEM certificate %s", path)
	}
	return rootCAs, nil
}
