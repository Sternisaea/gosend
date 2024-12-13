package authentication

import (
	"fmt"
	"net/smtp"

	"github.com/Sternisaea/gosend/src/cmdflags"
	"github.com/Sternisaea/gosend/src/types"
)

type SmtpAuthentication interface {
	Check() error
	Authenticate(client *smtp.Client) error
	GetType() types.AuthenticationMethod
}

func GetAuthentication(st *cmdflags.Settings) (SmtpAuthentication, error) {
	switch st.Authentication {
	case types.NoAuthentication:
		return NewAuthNone(), nil
	case types.PlainAuth:
		return NewAuthPlain(st.SmtpHost.String(), st.Login, st.Password), nil
	case types.CramMd5Auth:
		return NewAuthCramMd5(st.Login, st.Password), nil
	default:
		return nil, fmt.Errorf("unknown authentication method: %s", st.Authentication)
	}
}
