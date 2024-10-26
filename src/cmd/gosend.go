package main

import (
	"log"
	"os"

	"github.com/Sternisaea/gosend/src/cmdflags"
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

	conn, err := getSecureConnection(st)
	if err != nil {
		log.Fatal(err)
	}

	auth, err := getAuthentication(st)
	if err != nil {
		log.Fatal(err)
	}

	msg, err := getMessage(st)
	if err != nil {
		log.Fatal(err)
	}

	if err := checkSettings(st, conn, auth, msg); err != nil {
		log.Fatal(err)
	}

	send := send.NewSmtpSend(conn, auth, msg)
	if err := send.SendMail(); err != nil {
		log.Fatal(err)
	}

	log.Printf("E-mail sent succesfully")
}
