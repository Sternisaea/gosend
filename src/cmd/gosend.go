package main

import (
	"log"

	"github.com/Sternisaea/gosend/src/cmdflags"
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

	err = sc.SendMailTLS(st.Sender, st.RecipientsTo, st.RecipientsCC, st.RecipientsBCC, st.ReplyTo, st.Subject, st.BodyText, st.BodyHtml, st.Attachments)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("E-mail sent succesfully")
}
