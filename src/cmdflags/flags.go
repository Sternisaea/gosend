package cmdflags

import (
	"flag"
	"fmt"
	"strings"
)

func GetCmdFlags() {
	var co cmdOptions
	flag.StringVar(&co.serverSettingsFile, "server-settings-file", "", "Path to settings file")
	flag.StringVar(&co.smtpHost, "smtp-host", "", "Hostname of SMTP server")
	flag.IntVar(&co.smtpPort, "smtp-port", 0, "TCP port of SMTP server")

	flag.StringVar(&co.authFile, "auth-file", "", "Path to authentication file")
	flag.StringVar(&co.authMethod, "auth-method", "", "Authentication method")
	flag.StringVar(&co.login, "login", "", "Login username")
	flag.StringVar(&co.password, "password", "", "Login password")

	flag.StringVar(&co.sender, "sender", "", "Email sender address")
	flag.StringVar(&co.subject, "subject", "", "Email subject")

	var RecipientsTo, RecipientsCC, RecipientsBCC stringSlice
	flag.Var(&RecipientsTo, "to", "Recipient TO address")
	flag.Var(&RecipientsCC, "cc", "Recipient CC address")
	flag.Var(&RecipientsBCC, "bcc", "Recipient BCC address")

	// flag.StringVar(&co.attachments, "attachments", "", "Comma-separated list of file paths to attach")
	flag.Parse()

	co.recipientsTo = extractEmailAddresses(RecipientsTo)
	co.recipientsCC = extractEmailAddresses(RecipientsCC)
	co.recipientsBCC = extractEmailAddresses(RecipientsBCC)

	fmt.Printf("%#v\n", co)
}

func extractEmailAddresses(addresses []string) []string {
	var addrs []string
	for _, addr := range addresses {
		for _, a := range strings.Split(addr, ",") {
			ea := strings.Trim(a, " ")
			if ea != "" {
				addrs = append(addrs, ea)
			}
		}
	}
	return addrs
}
