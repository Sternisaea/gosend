package authentication

import (
	"errors"
	"fmt"
	"net/smtp"

	"github.com/Sternisaea/gosend/src/types"
)

type AuthPlain struct {
	hostname string
	user     string
	password string
}

func NewAuthPlain(hostname string, user string, password string) *AuthPlain {
	return &AuthPlain{hostname: hostname, user: user, password: password}
}

func (a *AuthPlain) Check() error {
	var errMsgs []error
	if (*a).hostname == "" {
		errMsgs = append(errMsgs, fmt.Errorf("no hostname provided"))
	}
	if (*a).user == "" {
		errMsgs = append(errMsgs, fmt.Errorf("no login user provided"))
	}
	if (*a).password == "" {
		errMsgs = append(errMsgs, fmt.Errorf("no password provided"))
	}
	return errors.Join(errMsgs...)
}

func (a *AuthPlain) GetType() types.AuthenticationMethod {
	return types.PlainAuth
}

func (a *AuthPlain) Authenticate(client *smtp.Client) error {
	if err := a.Check(); err != nil {
		return err
	}

	auth := smtp.PlainAuth("", (*a).user, (*a).password, (*a).hostname)
	if err := client.Auth(auth); err != nil {
		return err
	}
	return nil
}
