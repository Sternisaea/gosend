package main

import (
	"log"
	"os"

	"github.com/Sternisaea/gosend/src/authentication"
	"github.com/Sternisaea/gosend/src/cmdflags"
	"github.com/Sternisaea/gosend/src/secureconnection"
	"github.com/Sternisaea/gosend/src/send"
)

func main() {
	st, err := cmdflags.GetSettings(os.Stdout)
	if err != nil {
		log.Println(err)
		os.Exit(2)
	}
	if (*st).Help {
		return
	}

	conn, err := secureconnection.GetSecureConnection(st)
	if err != nil {
		log.Fatal(err)
	}

	auth, err := authentication.GetAuthentication(st)
	if err != nil {
		log.Fatal(err)
	}

	send := send.NewSmtpSend(conn, auth)
	if err := send.CreateMessage(st); err != nil {
		log.Fatal(err)
	}
	if err := send.SendMail(); err != nil {
		log.Fatal(err)
	}

	log.Printf("E-mail sent succesfully")
}
