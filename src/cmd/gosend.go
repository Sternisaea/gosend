package main

import (
	"log"

	"github.com/Sternisaea/gosend/src/cmdflags"
	"github.com/Sternisaea/gosend/src/message"
	"github.com/Sternisaea/gosend/src/sendmail"
)

func main() {
	st, err := cmdflags.GetSettings()
	if err != nil {
		log.Fatal(err)
	}
	if st == nil {
		return
	}

	sc := sendmail.NewSmtpConnect()
	if err := sc.SetServer(st.SmtpHost, st.SmtpPort, st.Security, st.Authentication, st.Login, st.Password); err != nil {
		log.Fatal(err)
	}
	if err := sc.SetPemCertificate(st.RootCA); err != nil {
		log.Fatal(err)
	}

	msg := message.NewMessage()
	msg.SetSender(st.Sender.GetMailAddress())
	msg.SetRecipient(st.RecipientsTo.GetMailAddresses(), st.RecipientsCC.GetMailAddresses(), st.RecipientsBCC.GetMailAddresses())
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

	err = sc.SendMail(msg)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("E-mail sent succesfully")
}
