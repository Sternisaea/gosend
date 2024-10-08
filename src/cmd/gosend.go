package main

import (
	"fmt"
	"log"

	"github.com/Sternisaea/gosend/src/cmdflags"
	"github.com/Sternisaea/gosend/src/message"
	"github.com/Sternisaea/gosend/src/sendmail"
)

func main() {
	fmt.Println("gosend")

	s, err := cmdflags.GetSettings()
	if err != nil {
		log.Fatal(err)
	}
	if s != nil {
		fmt.Printf("%#v\n", *s)
	}
}

func exampleSend() {
	sc := sendmail.NewSmtpConnect()
	if err := sc.SetServer("mail.losbron.nl", 2525, "gebruiker", "wachtwoord"); err != nil {
		log.Fatal(err)
	}
	if err := sc.SetPemCertificate("certificates/maillosbronnl.pem"); err != nil {
		log.Fatal(err)
	}

	msg := message.NewMessage()
	msg.SetSender("zender@mail.com")
	msg.SetRecipient([]string{"ontvanger@mail.com", "andere@mail.org"}, []string{"ikook@mail.nl"}, []string{"mijziejeniet@mail.nl"})
	msg.SetSubject("volstrekt onbelangrijk")
	msg.SetBodyPlainText("Hoi\nDit is een bericht")
	// msg.SetBodyHtml("<html><body><h1>Hoi</h1><p>Dit is een bericht</p></body></html>")
	msg.AddAttachment("example/Tux.png", "image/png")
	if err := sc.SendMailTLS(msg); err != nil {
		log.Fatal(err)
	}
	log.Printf("E-mail sent succesfully")
}
