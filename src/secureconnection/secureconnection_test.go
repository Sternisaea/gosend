package secureconnection

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Sternisaea/gosend/src/cmdflags"
	"github.com/Sternisaea/gosend/src/types"
)

type check struct {
	name               string
	settings           *cmdflags.Settings
	expectedConnection SecureConnection
	expectedErrors     *[]error
}

const NoSecurity = "No Security"

func Test_GetSecureConnection(t *testing.T) {
	validCert, validKey, err := createCertificate("Domain Local", "mail.domain.local")
	if err != nil {
		t.Errorf("Error creating certificate %s", err)
	}
	defer os.Remove(validKey)
	defer os.Remove(validCert)

	checklist := make([]check, 0, 100)

	addCheckOk(t, &checklist, NoSecurity+" regular", &cmdflags.Settings{Security: types.NoSecurity, SmtpHost: "mail.domain.local", SmtpPort: 587}, &ConnectNone{hostname: "mail.domain.local", port: 587})
	addCheckErr(t, &checklist, NoSecurity+" no domain", &cmdflags.Settings{Security: types.NoSecurity, SmtpHost: "", SmtpPort: 587}, &[]error{ErrNoHostname})
	addCheckErr(t, &checklist, NoSecurity+" no port", &cmdflags.Settings{Security: types.NoSecurity, SmtpHost: "mail.domain.local", SmtpPort: 0}, &[]error{ErrNoPort})

	addCheckOk(t, &checklist, types.StartTlsSec.String()+" regular", &cmdflags.Settings{Security: types.StartTlsSec, SmtpHost: "mail.domain.local", SmtpPort: 587}, &ConnectStarttls{hostname: "mail.domain.local", port: 587})
	addCheckOk(t, &checklist, types.StartTlsSec.String()+" certificate", &cmdflags.Settings{Security: types.StartTlsSec, SmtpHost: "mail.domain.local", SmtpPort: 587, RootCA: types.FilePath(validCert)}, &ConnectStarttls{hostname: "mail.domain.local", port: 587, rootCaPath: validCert})
	addCheckErr(t, &checklist, types.StartTlsSec.String()+" no domain", &cmdflags.Settings{Security: types.StartTlsSec, SmtpHost: "", SmtpPort: 587}, &[]error{ErrNoHostname})
	addCheckErr(t, &checklist, types.StartTlsSec.String()+" no port", &cmdflags.Settings{Security: types.StartTlsSec, SmtpHost: "mail.domain.local", SmtpPort: 0}, &[]error{ErrNoPort})

	addCheckOk(t, &checklist, types.SslTlsSec.String()+" regular", &cmdflags.Settings{Security: types.SslTlsSec, SmtpHost: "mail.domain.local", SmtpPort: 587}, &ConnectSslTls{hostname: "mail.domain.local", port: 587})
	addCheckErr(t, &checklist, types.SslTlsSec.String()+" no domain", &cmdflags.Settings{Security: types.SslTlsSec, SmtpHost: "", SmtpPort: 587}, &[]error{ErrNoHostname})
	addCheckErr(t, &checklist, types.SslTlsSec.String()+" no port", &cmdflags.Settings{Security: types.SslTlsSec, SmtpHost: "mail.domain.local", SmtpPort: 0}, &[]error{ErrNoPort})

	addCheckErr(t, &checklist, "unkknown protocol", &cmdflags.Settings{Security: "UNKNOWN", SmtpHost: "mail.domain.local", SmtpPort: 586}, &[]error{ErrUnknownProtocol})

	for _, c := range checklist {
		t.Run(c.name, func(t *testing.T) {

			sc, err := GetSecureConnection(c.settings)
			if err == nil {
				err = sc.Check()
			}

			if c.expectedErrors == nil || len(*c.expectedErrors) == 0 {
				if err != nil {
					t.Fatalf("Expected no error, got %s", err)
				}
			} else {
				if err == nil {
					if len(*c.expectedErrors) == 1 {
						t.Fatalf("Expected error %s, but got no error", (*c.expectedErrors)[0])
					} else {
						t.Fatalf("Expected errors %s, but got no error", errors.Join(*c.expectedErrors...))
					}
				} else {
					for _, e := range *c.expectedErrors {
						// Cannot use 'errors.Is' because flag package does not wrap errors (as for go1.23.2)
						if !strings.Contains(err.Error(), e.Error()) {
							t.Errorf("Expected error %s, got %s", e, err.Error())
						}
					}
					return
				}

			}

			if !reflect.DeepEqual(sc, c.expectedConnection) {
				t.Errorf("Expected %v, got %v", c.expectedConnection, sc)
			}

			// if sc != c.expectedConnection {
			// 	t.Errorf("Expected %v, got %v", c.expectedConnection, sc)
			// }
		})
	}

}

func addCheckOk(t testing.TB, checklist *[]check, name string, settings *cmdflags.Settings, expectedConnection SecureConnection) {
	t.Helper()
	addCheck(checklist, name, settings, expectedConnection, nil)
}

func addCheckErr(t testing.TB, checklist *[]check, name string, settings *cmdflags.Settings, expectedErrors *[]error) {
	t.Helper()
	addCheck(checklist, name, settings, nil, expectedErrors)
}

func addCheck(checklist *[]check, name string, settings *cmdflags.Settings, expectedConnection SecureConnection, expectedErrors *[]error) {
	*checklist = append(*checklist, check{name: name, settings: settings, expectedConnection: expectedConnection, expectedErrors: expectedErrors})

}

func createCertificate(organisation, hostname string) (string, string, error) {
	// Generate a private key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	// Create a certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Local Domain for Testing"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
	}

	// Create a self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}

	// Encode the certificate to PEM format
	certOut, err := os.CreateTemp(os.TempDir(), "cert.pem")
	if err != nil {
		return "", "", err
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Encode the private key to PEM format
	keyOut, err := os.CreateTemp(os.TempDir(), "key.pem")
	if err != nil {
		return "", "", err
	}
	defer keyOut.Close()
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return certOut.Name(), keyOut.Name(), nil
}
