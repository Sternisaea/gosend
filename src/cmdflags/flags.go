package cmdflags

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Sternisaea/gosend/src/types"
)

const (
	flagServerFile = "server-file"
	flagSmtpHost   = "smtp-host"
	flagSmtpPort   = "smtp-port"
	flagRootCA     = "rootca"
	flagSecurity   = "security"
	flagAuthFile   = "auth-file"
	flagAuthMethod = "auth-method"
	flagLogin      = "login"
	flagPassword   = "password"
	flagSender     = "sender"
	flagReplyTo    = "reply-to"
	flagTo         = "to"
	flagCc         = "cc"
	flagBcc        = "bcc"
	flagMessageId  = "message-id"
	flagSubject    = "subject"
	flagHeader     = "header"
	flagBodyText   = "body-text"
	flagBodyHtml   = "body-html"
	flagAttachment = "attachment"
	flagHelp       = "help"
)

type Settings struct {
	SmtpHost       types.DomainName
	SmtpPort       types.TCPPort
	RootCA         types.FilePath
	Security       types.Security
	Authentication types.AuthenticationMethod
	Login          string
	Password       string

	Sender        types.Email
	ReplyTo       types.EmailAddresses
	RecipientsTo  types.EmailAddresses
	RecipientsCC  types.EmailAddresses
	RecipientsBCC types.EmailAddresses
	MessageID     string
	Subject       string
	Headers       types.Headers

	BodyText    string
	BodyHtml    string
	Attachments types.Attachments

	help bool
}

func GetSettings() (*Settings, error) {
	fs, serverFilePath, authFilePath := getFlagsettings()

	if fs.help {
		flag.Usage()
		return nil, nil
	}

	opts := make(map[string]string)
	opts, err := appendOptionsOfFile(opts, serverFilePath)
	if err != nil {
		return nil, err
	}
	opts, err = appendOptionsOfFile(opts, authFilePath)
	if err != nil {
		return nil, err
	}

	if fs.SmtpHost == "" {
		if err := fs.SmtpHost.Set(opts[flagSmtpHost]); err != nil {
			return nil, err
		}
	}
	if fs.SmtpPort == 0 {
		if err := fs.SmtpPort.Set(opts[flagSmtpPort]); err != nil {
			return nil, err
		}
	}
	if fs.RootCA == "" {
		if err := fs.RootCA.Set(opts[flagRootCA]); err != nil {
			return nil, err
		}
	}
	if fs.Security == types.NoSecurity {
		if err := fs.Security.Set(opts[flagSecurity]); err != nil {
			return nil, err
		}
	}
	if fs.Authentication == types.NoAuthentication {
		if err := fs.Authentication.Set(opts[flagAuthMethod]); err != nil {
			return nil, err
		}
	}
	if fs.Login == "" {
		fs.Login = opts[flagLogin]
	}
	if fs.Password == "" {
		fs.Password = opts[flagPassword]
	}
	if fs.Sender.Address == "" {
		if err := fs.Sender.Set(opts[flagSender]); err != nil {
			return nil, err
		}
	}
	return &fs, nil
}

func getFlagsettings() (Settings, types.FilePath, types.FilePath) {
	var serverFilePath, authFilePath types.FilePath
	var fs Settings
	flag.Var(&serverFilePath, flagServerFile, "Path to settings file.")
	flag.Var(&fs.SmtpHost, flagSmtpHost, "Hostname of SMTP server.")
	flag.Var(&fs.SmtpPort, flagSmtpPort, "TCP port of SMTP server.")
	flag.Var(&fs.RootCA, flagRootCA, "File path to X.509 certificate in PEM format for the Root CA when using a self-signed certificate on the mail server.")
	flag.Var(&fs.Security, flagSecurity, fmt.Sprintf("Security protocol (%s, %s).", types.StartTlsSec, types.SslTlsSec))

	flag.Var(&authFilePath, flagAuthFile, "Path to authentication file.")
	flag.Var(&fs.Authentication, flagAuthMethod, fmt.Sprintf("Authentication Method (%s, %s).", types.PlainAuth, types.CramMd5Auth))
	flag.StringVar(&fs.Login, flagLogin, "", "Login username")
	flag.StringVar(&fs.Password, flagPassword, "", "Login password.")

	flag.Var(&fs.Sender, flagSender, "Email address of sender.")
	flag.Var(&fs.ReplyTo, flagReplyTo, fmt.Sprintf("Reply-To address. Comma separate multiple email addresses or use multiple %s options.", flagReplyTo))

	flag.Var(&fs.RecipientsTo, flagTo, fmt.Sprintf("Recipient TO address. Comma separate multiple email addresses or use multiple %s options.", flagTo))
	flag.Var(&fs.RecipientsCC, flagCc, fmt.Sprintf("Recipient CC address. Comma separate multiple email addresses or use multiple %s options.", flagCc))
	flag.Var(&fs.RecipientsBCC, flagBcc, fmt.Sprintf("Recipient BCC address. Comma separate multiple email addresses or use multiple %s options.", flagBcc))
	flag.StringVar(&fs.MessageID, flagMessageId, "", "Custom Message-ID.")
	flag.StringVar(&fs.Subject, flagSubject, "", "Email subject")
	flag.Var(&fs.Headers, flagHeader, fmt.Sprintf("Custom header. Multiple -%s flags are allowed.", flagHeader))

	flag.StringVar(&fs.BodyText, flagBodyText, "", "Body content in plain text.Add new lines as \\n.")
	flag.StringVar(&fs.BodyHtml, flagBodyHtml, "", "Body content in HTML.")
	flag.Var(&fs.Attachments, flagAttachment, fmt.Sprintf("File path to attachment. Comma separate multiple attachments of use multiple %s options.", flagAttachment))
	flag.BoolVar(&fs.help, flagHelp, false, "Show flag options.")
	flag.Parse()
	return fs, serverFilePath, authFilePath
}

func appendOptionsOfFile(opts map[string]string, filePath types.FilePath) (map[string]string, error) {
	if filePath == "" {
		return opts, nil
	}
	file, err := os.Open(filePath.String())
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %s", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		equalIndex := strings.Index(line, "=")
		if equalIndex == -1 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:equalIndex]))
		value := strings.TrimSpace(strings.Trim(line[equalIndex+1:], "\""))
		opts[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %s", err)
	}
	return opts, nil
}
