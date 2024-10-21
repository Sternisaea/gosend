package authentication

import "net/smtp"

type AuthNone struct {
}

func NewAuthNone() *AuthNone {
	return &AuthNone{}
}

func (a *AuthNone) Check() error {
	return nil
}

func (a *AuthNone) Authenticate(client *smtp.Client) error {
	if err := a.Check(); err != nil {
		return err
	}
	return nil
}
