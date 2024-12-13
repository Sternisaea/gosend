package authentication

import (
	"errors"
	"fmt"
	"net/smtp"

	"github.com/Sternisaea/gosend/src/types"
)

type AuthCramMd5 struct {
	user     string
	password string
}

func NewAuthCramMd5(user string, password string) *AuthCramMd5 {
	return &AuthCramMd5{user: user, password: password}
}

func (a *AuthCramMd5) Check() error {
	var errMsgs []error
	if (*a).user == "" {
		errMsgs = append(errMsgs, fmt.Errorf("no login user provided"))
	}
	if (*a).password == "" {
		errMsgs = append(errMsgs, fmt.Errorf("no password provided"))
	}
	return errors.Join(errMsgs...)
}

func (a *AuthCramMd5) GetType() types.AuthenticationMethod {
	return types.CramMd5Auth
}

func (a *AuthCramMd5) Authenticate(client *smtp.Client) error {
	if err := a.Check(); err != nil {
		return err
	}

	auth := smtp.CRAMMD5Auth((*a).user, (*a).password)
	if err := client.Auth(auth); err != nil {
		return err
	}
	return nil
}
