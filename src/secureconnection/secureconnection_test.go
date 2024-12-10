package secureconnection

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Sternisaea/dnsservermock/src/dnsconst"
	"github.com/Sternisaea/dnsservermock/src/dnsservermock"
	"github.com/Sternisaea/dnsservermock/src/dnsstorage/dnsstoragememory"
	"github.com/Sternisaea/gosend/src/certificates"
	"github.com/Sternisaea/gosend/src/cmdflags"
	"github.com/Sternisaea/gosend/src/types"
	"github.com/Sternisaea/smtpservermock/src/smtpservermock"
)

var (
	MaxLineLength = 78
	dnsIP         = "127.0.0.1"
	dnsPort       = types.TCPPort(5355)

	smtpNoSecurityPort = types.TCPPort(40971)
	smtpStartTlsPort   = types.TCPPort(40972)
	smtpTlsPort        = types.TCPPort(40973)

	ErrX509UnknownAuthority = errors.New("x509: certificate signed by unknown authority")
)

type check struct {
	name                    string
	settings                *cmdflags.Settings
	expectedConnection      SecureConnection
	expectedConstructErrors *[]error
	expectedSecurityType    types.Security
	expectedHostName        string
	expectedCheckErrors     *[]error
	expectedConnectErrors   *[]error
}

const NoSecurity = "No Security"

func Test_GetSecureConnection(t *testing.T) {
	cancelDns, err := startDns(net.ParseIP(dnsIP), int(dnsPort))
	if err != nil {
		t.Fatalf("Cannot start DNS server: %s", err)
	}
	defer cancelDns()

	setDefaultResolver(fmt.Sprintf("%s:%d", dnsIP, dnsPort))

	validCert, validKey, err := certificates.CreateCertificate("Domain Local", "mail.domain.local")
	if err != nil {
		t.Fatalf("Error creating certificate: %s", err)
	}
	defer os.Remove(validKey)
	defer os.Remove(validCert)

	mockSmtpNoSecurity, err := smtpservermock.NewSmtpServer(
		smtpservermock.NoSecurity,
		"Mock SMTP Server without security",
		getAddress("localhost", smtpNoSecurityPort),
		"",
		"")
	if err != nil {
		t.Fatalf("Cannot initialise SMTP server without security: %s", err)
	}
	if err := mockSmtpNoSecurity.ListenAndServe(); err != nil {
		t.Fatalf("Cannot start SMTP server without security: %s", err)
	}
	defer mockSmtpNoSecurity.Shutdown()

	mockSmtpStarttls, err := smtpservermock.NewSmtpServer(
		smtpservermock.StartTlsSec,
		"Mock SMTP Server with STARTTLS",
		getAddress("localhost", smtpStartTlsPort),
		validCert,
		validKey)
	if err != nil {
		t.Fatalf("Cannot initialise SMTP server with STARTTLS: %s", err)
	}
	if err := mockSmtpStarttls.ListenAndServe(); err != nil {
		t.Fatalf("Cannot start SMTP server with STARTTLS: %s", err)
	}
	defer mockSmtpStarttls.Shutdown()

	mockSmtpTls, err := smtpservermock.NewSmtpServer(
		smtpservermock.SslTlsSec,
		"Mock SMTP Server with TLS",
		getAddress("localhost", smtpTlsPort),
		validCert,
		validKey)
	if err != nil {
		t.Fatalf("Cannot initialise SMTP server with TLS: %s", err)
	}
	if err := mockSmtpTls.ListenAndServe(); err != nil {
		t.Fatalf("Cannot start SMTP server with TLS: %s", err)
	}
	defer mockSmtpTls.Shutdown()

	checklist := make([]check, 0, 100)

	addCheck(t, &checklist, NoSecurity+" LOCALHOST", &cmdflags.Settings{Security: types.NoSecurity, SmtpHost: "localhost", SmtpPort: smtpNoSecurityPort}, &ConnectNone{hostname: "localhost", port: int(smtpNoSecurityPort)}, nil, types.NoSecurity, "localhost", nil, nil)

	addCheck(t, &checklist, NoSecurity+" regular", &cmdflags.Settings{Security: types.NoSecurity, SmtpHost: "mail.domain.local", SmtpPort: smtpNoSecurityPort}, &ConnectNone{hostname: "mail.domain.local", port: int(smtpNoSecurityPort)}, nil, types.NoSecurity, "mail.domain.local", nil, nil)
	addCheck(t, &checklist, NoSecurity+" no domain", &cmdflags.Settings{Security: types.NoSecurity, SmtpHost: "", SmtpPort: smtpNoSecurityPort}, &ConnectNone{port: int(smtpNoSecurityPort)}, nil, types.NoSecurity, "", &[]error{ErrNoHostname}, &[]error{ErrNoHostname})
	addCheck(t, &checklist, NoSecurity+" no port", &cmdflags.Settings{Security: types.NoSecurity, SmtpHost: "mail.domain.local", SmtpPort: 0}, &ConnectNone{hostname: "mail.domain.local"}, nil, types.NoSecurity, "mail.domain.local", &[]error{ErrNoPort}, &[]error{ErrNoPort})

	addCheck(t, &checklist, types.StartTlsSec.String()+" regular", &cmdflags.Settings{Security: types.StartTlsSec, SmtpHost: "mail.domain.local", SmtpPort: smtpStartTlsPort}, &ConnectStarttls{hostname: "mail.domain.local", port: int(smtpStartTlsPort)}, nil, types.StartTlsSec, "mail.domain.local", nil, &[]error{ErrX509UnknownAuthority})
	addCheck(t, &checklist, types.StartTlsSec.String()+" certificate", &cmdflags.Settings{Security: types.StartTlsSec, SmtpHost: "mail.domain.local", SmtpPort: smtpStartTlsPort, RootCA: types.FilePath(validCert)}, &ConnectStarttls{hostname: "mail.domain.local", port: int(smtpStartTlsPort), rootCaPath: validCert}, nil, types.StartTlsSec, "mail.domain.local", nil, nil)
	addCheck(t, &checklist, types.StartTlsSec.String()+" no domain", &cmdflags.Settings{Security: types.StartTlsSec, SmtpHost: "", SmtpPort: smtpStartTlsPort}, &ConnectStarttls{port: int(smtpStartTlsPort)}, nil, types.StartTlsSec, "", &[]error{ErrNoHostname}, &[]error{ErrNoHostname})
	addCheck(t, &checklist, types.StartTlsSec.String()+" no port", &cmdflags.Settings{Security: types.StartTlsSec, SmtpHost: "mail.domain.local", SmtpPort: 0}, &ConnectStarttls{hostname: "mail.domain.local"}, nil, types.StartTlsSec, "mail.domain.local", &[]error{ErrNoPort}, &[]error{ErrNoPort})

	addCheck(t, &checklist, types.SslTlsSec.String()+" regular", &cmdflags.Settings{Security: types.SslTlsSec, SmtpHost: "mail.domain.local", SmtpPort: smtpTlsPort, RootCA: types.FilePath(validCert)}, &ConnectSslTls{hostname: "mail.domain.local", port: int(smtpTlsPort), rootCaPath: validCert}, nil, types.SslTlsSec, "mail.domain.local", nil, nil)
	addCheck(t, &checklist, types.SslTlsSec.String()+" no domain", &cmdflags.Settings{Security: types.SslTlsSec, SmtpHost: "", SmtpPort: smtpTlsPort, RootCA: types.FilePath(validCert)}, &ConnectSslTls{port: int(smtpTlsPort), rootCaPath: validCert}, nil, types.SslTlsSec, "", &[]error{ErrNoHostname}, &[]error{ErrNoHostname})
	addCheck(t, &checklist, types.SslTlsSec.String()+" no port", &cmdflags.Settings{Security: types.SslTlsSec, SmtpHost: "mail.domain.local", SmtpPort: 0, RootCA: types.FilePath(validCert)}, &ConnectSslTls{hostname: "mail.domain.local", rootCaPath: validCert}, nil, types.SslTlsSec, "mail.domain.local", &[]error{ErrNoPort}, &[]error{ErrNoPort})

	addCheck(t, &checklist, "unkknown protocol", &cmdflags.Settings{Security: "UNKNOWN", SmtpHost: "mail.domain.local", SmtpPort: smtpNoSecurityPort}, nil, &[]error{ErrUnknownProtocol}, types.NoSecurity, "", nil, nil)

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
			t.Run(c.name+" ClientConnect", func(t *testing.T) {
				_, close, _, err := sc.ClientConnect()
				if err == nil {
					defer close()
				}

				if cont, err := checkError(err, c.expectedConnectErrors); !cont || err != nil {
					if err != nil {
						t.Fatal(err)
					}
					return
				}
			})
		})
	}
}

func addCheck(t testing.TB, checklist *[]check, name string, settings *cmdflags.Settings, expectedConnection SecureConnection, expectedConstructErrors *[]error, expectedSecurityType types.Security, expectedHostName string, expectedCheckErrors *[]error, expectedConnectErrors *[]error) {
	t.Helper()
	*checklist = append(*checklist, check{name: name, settings: settings, expectedConnection: expectedConnection, expectedConstructErrors: expectedConstructErrors, expectedSecurityType: expectedSecurityType, expectedHostName: expectedHostName, expectedCheckErrors: expectedCheckErrors, expectedConnectErrors: expectedConnectErrors})
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

func startDns(ip net.IP, port int) (func() error, error) {
	store := dnsstoragememory.NewMemoryStore()
	(*store).Set("domain.local", dnsconst.Type_A, "127.0.0.1")
	(*store).Set("mail.domain.local", dnsconst.Type_A, "127.0.0.1")
	(*store).Set("domain.local", dnsconst.Type_AAAA, "::1")
	(*store).Set("mail.domain.local", dnsconst.Type_AAAA, "::1")
	(*store).Set("domain.local", dnsconst.Type_MX, "mail.domain.local")

	ds := dnsservermock.NewDnsServer(ip, port, store)
	if err := (*ds).Start(); err != nil {
		return nil, err
	}
	return (*ds).Stop, nil
}

func setDefaultResolver(dnsAddress string) {
	cr := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Second,
			}
			return d.DialContext(ctx, "udp", dnsAddress)
		},
	}
	net.DefaultResolver = cr
}

func getAddress(host string, port types.TCPPort) string {
	return fmt.Sprintf("%s:%d", host, port)
}
