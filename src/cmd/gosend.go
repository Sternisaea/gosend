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
	if err := sc.SetServer(st.SmtpHost, st.SmtpPort, st.AuthMethod, st.Login, st.Password); err != nil {
		log.Fatal(err)
	}
	if err := sc.SetPemCertificate(st.RootCA); err != nil {
		log.Fatal(err)
	}

	msg := message.NewMessage()
	msg.SetSender(st.Sender.String())
	msg.SetRecipient(st.RecipientsTo.StringSlice(), st.RecipientsCC.StringSlice(), st.RecipientsBCC.StringSlice())
	msg.SetReplyTo(st.ReplyTo.StringSlice())
	msg.SetSubject(st.Subject)
	msg.SetMessageId(st.MessageID)
	msg.SetBodyPlainText(st.BodyText)
	msg.SetBodyHtml(st.BodyHtml)
	for _, a := range st.Attachments {
		msg.AddAttachment(a.String())
	}

	err = sc.SendMailTLS(msg)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("E-mail sent succesfully")
}
