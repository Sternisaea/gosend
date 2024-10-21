package secureconnection

import (
	"net/smtp"
)

type SecureConnection interface {
	Check() error
	ClientConnect() (*smtp.Client, func() error, error)
}
