package authentication

import "net/smtp"

type SmtpAuthentication interface {
	Check() error
	Authenticate(client *smtp.Client) error
}
