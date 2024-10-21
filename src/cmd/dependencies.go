package main

import (
	"errors"
	"fmt"

	"github.com/Sternisaea/gosend/src/authentication"
	"github.com/Sternisaea/gosend/src/cmdflags"
	"github.com/Sternisaea/gosend/src/message"
	"github.com/Sternisaea/gosend/src/secureconnection"
	"github.com/Sternisaea/gosend/src/types"
)

func getSecureConnection(st *cmdflags.Settings) (secureconnection.SecureConnection, error) {
	switch st.Security {
	case types.NoSecurity:
		return secureconnection.NewConnectNone(st.SmtpHost.String(), int(st.SmtpPort)), nil
	case types.StartTlsSec:
		return secureconnection.NewConnectStarttls(st.SmtpHost.String(), int(st.SmtpPort), st.RootCA.String()), nil
	case types.SslTlsSec:
		return secureconnection.NewConnectSslTls(st.SmtpHost.String(), int(st.SmtpPort), st.RootCA.String()), nil
	default:
		return nil, fmt.Errorf("unkown security protocol: %s", st.Security)
	}
}

func getAuthentication(st *cmdflags.Settings) (authentication.SmtpAuthentication, error) {
	switch st.Authentication {
	case types.NoAuthentication:
		return authentication.NewAuthNone(), nil
	case types.PlainAuth:
		return authentication.NewAuthPlain(st.SmtpHost.String(), st.Login, st.Password), nil
	case types.CramMd5Auth:
		return authentication.NewAuthCramMd5(st.Login, st.Password), nil
	default:
		return nil, fmt.Errorf("unknown authentication method: %s", st.Authentication)
	}
}

func getMessage(st *cmdflags.Settings) (*message.Message, error) {
	msg := message.NewMessage()
	msg.SetSender(st.Sender.GetMailAddress())
	msg.SetRecipientTo(st.RecipientsTo.GetMailAddresses())
	msg.SetRecipientCC(st.RecipientsCC.GetMailAddresses())
	msg.SetRecipientBCC(st.RecipientsBCC.GetMailAddresses())
	msg.SetReplyTo(st.ReplyTo.GetMailAddresses())
	msg.SetSubject(st.Subject)
	msg.SetMessageId(st.MessageID)
	for _, h := range st.Headers {
		msg.AddCustomHeader(h)
	}
	msg.SetBodyPlainText(st.BodyText)
	msg.SetBodyHtml(st.BodyHtml)
	for _, a := range st.Attachments {
		msg.AddAttachment(a.String())
	}
	return msg, nil
}

func checkSettings(st *cmdflags.Settings, conn secureconnection.SecureConnection, auth authentication.SmtpAuthentication, msg *message.Message) error {
	var errMsgs []error
	errMsgs = append(errMsgs, conn.Check())
	errMsgs = append(errMsgs, auth.Check())

	// Check combinations for Security Protocol and Authentication Method
	if (*st).Security == types.NoSecurity {
		if (*st).Authentication == types.PlainAuth && (*st).SmtpHost != "localhost" {
			errMsgs = append(errMsgs, fmt.Errorf("authentication method '%s' is only allowed on an secure connection", types.PlainAuth.String()))
		}
	} else {
		if (*st).Authentication == types.NoAuthentication {
			errMsgs = append(errMsgs, fmt.Errorf("authentication is required for security protocol '%s'", (*st).Security.String()))
		}
	}

	errMsgs = append(errMsgs, msg.CheckMessage())

	return errors.Join(errMsgs...)
}
