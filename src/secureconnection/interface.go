package secureconnection

import (
	"errors"
	"fmt"
	"net/smtp"

	"github.com/Sternisaea/gosend/src/cmdflags"
	"github.com/Sternisaea/gosend/src/types"
)

var (
	ErrNoHostname              = errors.New("no hostname provided")
	ErrNoPort                  = errors.New("no tcp-port provided")
	ErrFileDoesNotExist        = errors.New("file does not exist")
	ErrFile                    = errors.New("error file")
	ErrFailedAppendCertificate = errors.New("failed to append PEM certificate")
	ErrStarttlsNotSupported    = errors.New("server does not support STARTTLS")
	ErrSslTlsNotSupported      = errors.New("server does not support SSL/TLS")
	ErrUnknownProtocol         = errors.New("unkown security protocol")
)

type SecureConnection interface {
	Check() error
	ClientConnect() (*smtp.Client, func() error, string, error)
	GetType() types.Security
	GetHostName() string
}

func GetSecureConnection(st *cmdflags.Settings) (SecureConnection, error) {
	switch st.Security {
	case types.NoSecurity:
		return NewConnectNone(st.SmtpHost.String(), int(st.SmtpPort)), nil
	case types.StartTlsSec:
		return NewConnectStarttls(st.SmtpHost.String(), int(st.SmtpPort), st.RootCA.String()), nil
	case types.SslTlsSec:
		return NewConnectSslTls(st.SmtpHost.String(), int(st.SmtpPort), st.RootCA.String()), nil
	default:
		return nil, fmt.Errorf("%w : %s", ErrUnknownProtocol, st.Security)
	}
}
