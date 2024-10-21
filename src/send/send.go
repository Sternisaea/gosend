package send

import (
	"github.com/Sternisaea/gosend/src/authentication"
	"github.com/Sternisaea/gosend/src/message"
	"github.com/Sternisaea/gosend/src/secureconnection"
)

type SmtpSend struct {
	connection     secureconnection.SecureConnection
	authentication authentication.SmtpAuthentication
	message        *message.Message
}

func NewSmtpSend(conn secureconnection.SecureConnection, auth authentication.SmtpAuthentication, msg *message.Message) *SmtpSend {
	return &SmtpSend{connection: conn, authentication: auth, message: msg}
}

func (s *SmtpSend) SendMail() error {
	client, close, err := (*s).connection.ClientConnect()
	if err != nil {
		return err
	}
	defer close()

	if err := (*s).authentication.Authenticate(client); err != nil {
		return err
	}

	if err := (*s).message.SendContent(client); err != nil {
		return err
	}
	return nil
}
