package secureconnection

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
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
	name                    string
	settings                *cmdflags.Settings
	expectedConnection      SecureConnection
	expectedConstructErrors *[]error
	expectedSecurityType    types.Security
	expectedHostName        string
	expectedCheckErrors     *[]error
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

	addCheck(t, &checklist, NoSecurity+" regular", &cmdflags.Settings{Security: types.NoSecurity, SmtpHost: "mail.domain.local", SmtpPort: 587}, &ConnectNone{hostname: "mail.domain.local", port: 587}, nil, types.NoSecurity, "mail.domain.local", nil)
	addCheck(t, &checklist, NoSecurity+" no domain", &cmdflags.Settings{Security: types.NoSecurity, SmtpHost: "", SmtpPort: 587}, &ConnectNone{port: 587}, nil, types.NoSecurity, "", &[]error{ErrNoHostname})
	addCheck(t, &checklist, NoSecurity+" no port", &cmdflags.Settings{Security: types.NoSecurity, SmtpHost: "mail.domain.local", SmtpPort: 0}, &ConnectNone{hostname: "mail.domain.local"}, nil, types.NoSecurity, "mail.domain.local", &[]error{ErrNoPort})

	addCheck(t, &checklist, types.StartTlsSec.String()+" regular", &cmdflags.Settings{Security: types.StartTlsSec, SmtpHost: "mail.domain.local", SmtpPort: 587}, &ConnectStarttls{hostname: "mail.domain.local", port: 587}, nil, types.StartTlsSec, "mail.domain.local", nil)
	addCheck(t, &checklist, types.StartTlsSec.String()+" certificate", &cmdflags.Settings{Security: types.StartTlsSec, SmtpHost: "mail.domain.local", SmtpPort: 587, RootCA: types.FilePath(validCert)}, &ConnectStarttls{hostname: "mail.domain.local", port: 587, rootCaPath: validCert}, nil, types.StartTlsSec, "mail.domain.local", nil)
	addCheck(t, &checklist, types.StartTlsSec.String()+" no domain", &cmdflags.Settings{Security: types.StartTlsSec, SmtpHost: "", SmtpPort: 587}, &ConnectStarttls{port: 587}, nil, types.StartTlsSec, "", &[]error{ErrNoHostname})
	addCheck(t, &checklist, types.StartTlsSec.String()+" no port", &cmdflags.Settings{Security: types.StartTlsSec, SmtpHost: "mail.domain.local", SmtpPort: 0}, &ConnectStarttls{hostname: "mail.domain.local"}, nil, types.StartTlsSec, "mail.domain.local", &[]error{ErrNoPort})

	addCheck(t, &checklist, types.SslTlsSec.String()+" regular", &cmdflags.Settings{Security: types.SslTlsSec, SmtpHost: "mail.domain.local", SmtpPort: 587}, &ConnectSslTls{hostname: "mail.domain.local", port: 587}, nil, types.SslTlsSec, "mail.domain.local", nil)
	addCheck(t, &checklist, types.SslTlsSec.String()+" no domain", &cmdflags.Settings{Security: types.SslTlsSec, SmtpHost: "", SmtpPort: 587}, &ConnectSslTls{port: 587}, nil, types.SslTlsSec, "", &[]error{ErrNoHostname})
	addCheck(t, &checklist, types.SslTlsSec.String()+" no port", &cmdflags.Settings{Security: types.SslTlsSec, SmtpHost: "mail.domain.local", SmtpPort: 0}, &ConnectSslTls{hostname: "mail.domain.local"}, nil, types.SslTlsSec, "mail.domain.local", &[]error{ErrNoPort})

	addCheck(t, &checklist, "unkknown protocol", &cmdflags.Settings{Security: "UNKNOWN", SmtpHost: "mail.domain.local", SmtpPort: 586}, nil, &[]error{ErrUnknownProtocol}, types.NoSecurity, "", nil)

	for _, c := range checklist {
		// Test GetSecureConnection Constructor
		t.Run(c.name, func(t *testing.T) {

			sc, err := GetSecureConnection(c.settings)

			if cont, err := checkError(err, c.expectedConstructErrors); !cont || err != nil {
				if err != nil {
					t.Fatal(err)
				}
				return
			}

			if !reflect.DeepEqual(sc, c.expectedConnection) {
				t.Fatalf("Expected %v, got %v", c.expectedConnection, sc)
			}

			// Test GetType
			t.Run(c.name+" Type", func(t *testing.T) {
				secType := sc.GetType()
				if c.expectedSecurityType != secType {
					t.Errorf("Expected SecurityType %s, got %s", c.expectedSecurityType, secType)
				}
			})

			// Test HostName
			t.Run(c.name+" Host", func(t *testing.T) {
				hostName := sc.GetHostName()
				if c.expectedHostName != hostName {
					t.Errorf("Expected hostname %s, got %s", c.expectedHostName, hostName)
				}
			})

			// Test Check
			t.Run(c.name+" Check", func(t *testing.T) {
				err := sc.Check()

				if cont, err := checkError(err, c.expectedCheckErrors); !cont || err != nil {
					if err != nil {
						t.Fatal(err)
					}
				}
			})

			// Test ClientConnect
			// Todo: test ClientConnect

		})
	}
}

func addCheck(t testing.TB, checklist *[]check, name string, settings *cmdflags.Settings, expectedConnection SecureConnection, expectedConstructErrors *[]error, expectedSecurityType types.Security, expectedHostName string, expectedCheckErrors *[]error) {
	t.Helper()
	*checklist = append(*checklist, check{name: name, settings: settings, expectedConnection: expectedConnection, expectedConstructErrors: expectedConstructErrors, expectedSecurityType: expectedSecurityType, expectedHostName: expectedHostName, expectedCheckErrors: expectedCheckErrors})
}

func checkError(occuredErr error, expectedErr *[]error) (bool, error) {
	if expectedErr == nil || len(*expectedErr) == 0 {
		if occuredErr != nil {
			return false, fmt.Errorf("Expected no error, got %s", occuredErr)
		}
	} else {
		if occuredErr == nil {
			if len(*expectedErr) == 1 {
				return false, fmt.Errorf("Expected error %s, got no error", (*expectedErr)[0])
			} else {
				return false, fmt.Errorf("Expected errors %s, got no error", errors.Join(*expectedErr...))
			}
		} else {
			for _, exp := range *expectedErr {
				if !strings.Contains(occuredErr.Error(), exp.Error()) {
					return false, fmt.Errorf("Expected error %s, got %s", exp, occuredErr)
				}
			}
			return false, nil
		}
	}
	return true, nil
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
			Organization: []string{organisation},
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
