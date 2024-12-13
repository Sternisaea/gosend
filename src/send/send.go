package send

import (
	"errors"
	"fmt"

	"github.com/Sternisaea/gosend/src/authentication"
	"github.com/Sternisaea/gosend/src/cmdflags"
	"github.com/Sternisaea/gosend/src/message"
	"github.com/Sternisaea/gosend/src/secureconnection"
	"github.com/Sternisaea/gosend/src/types"
)

type SmtpSend struct {
	connection     secureconnection.SecureConnection
	authentication authentication.SmtpAuthentication
	message        *message.Message
	localAddress   string
}

func NewSmtpSend(conn secureconnection.SecureConnection, auth authentication.SmtpAuthentication) *SmtpSend {
	return &SmtpSend{connection: conn, authentication: auth, message: nil}
}

func (s *SmtpSend) CreateMessage(st *cmdflags.Settings) error {
	msg := message.NewMessage()
	msg.SetSender(st.Sender.GetMailAddress())
	msg.SetRecipientTo(st.RecipientsTo.GetMailAddresses())
	msg.SetRecipientCC(st.RecipientsCC.GetMailAddresses())
	msg.SetRecipientBCC(st.RecipientsBCC.GetMailAddresses())
	msg.SetReplyTo(st.ReplyTo.GetMailAddresses())
	msg.SetSubject(st.Subject)
	msg.SetMessageId(st.MessageID)
	for _, h := range st.Headers {
		msg.AddCustomHeader(h.String())
	}
	msg.SetBodyPlainText(st.BodyText)
	msg.SetBodyHtml(st.BodyHtml)
	for _, a := range st.Attachments {
		if _, err := msg.AddAttachment(a.String()); err != nil {
			return err
		}
	}
	(*s).message = msg
	return nil
}

func (s *SmtpSend) CheckMessage() error {
	var errMsgs []error
	errMsgs = append(errMsgs, (*s).connection.Check())
	errMsgs = append(errMsgs, (*s).authentication.Check())

	// Check combinations for Security Protocol and Authentication Method
	if (*s).connection.GetType() == types.NoSecurity {
		if (*s).authentication.GetType() == types.PlainAuth && (*s).connection.GetHostName() != "localhost" {
			errMsgs = append(errMsgs, fmt.Errorf("authentication method '%s' is only allowed on an secure connection", types.PlainAuth.String()))
		}
	} else {
		if (*s).authentication.GetType() == types.NoAuthentication {
			errMsgs = append(errMsgs, fmt.Errorf("authentication is required for security protocol '%s'", (*s).connection.GetType()))
		}
	}

	errMsgs = append(errMsgs, (*s).message.CheckMessage())
	return errors.Join(errMsgs...)
}

func (s *SmtpSend) SendMail() error {
	if err := s.CheckMessage(); err != nil {
		return err
	}

	client, close, addr, err := (*s).connection.ClientConnect()
	if err != nil {
		return err
	}
	defer close()
	(*s).localAddress = addr

	if err := (*s).authentication.Authenticate(client); err != nil {
		return err
	}

	if err := (*s).message.SendContent(client); err != nil {
		return err
	}
	return nil
}

func (s *SmtpSend) GetLocalAddress() string {
	return (*s).localAddress
}
