package main

import (
	"fmt"
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
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(2)
	}
	if st == nil {
		return
	}

	conn, err := secureconnection.GetSecureConnection(st)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(2)
	}

	auth, err := authentication.GetAuthentication(st)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(2)
	}

	send := send.NewSmtpSend(conn, auth)
	if err := send.CreateMessage(st); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	if err := send.CheckMessage(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(2)
	} else {
		if err := send.SendMail(); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}
	}

	log.Printf("E-mail sent succesfully")
}
