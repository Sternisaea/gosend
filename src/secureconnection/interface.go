package secureconnection

import (
	"fmt"
	"net/smtp"

	"github.com/Sternisaea/gosend/src/cmdflags"
	"github.com/Sternisaea/gosend/src/types"
)

type SecureConnection interface {
	Check() error
	ClientConnect() (*smtp.Client, func() error, error)
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
		return nil, fmt.Errorf("unkown security protocol: %s", st.Security)
	}
}
