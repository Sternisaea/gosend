package cmdflags

import (
	"bufio"
	"flag"
	"fmt"
	"io"
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

	Help bool
}

func GetSettings(output io.Writer) (*Settings, error) {
	settings, serverFilePath, authFilePath, err := getFlagSettings(output)
	if err != nil {
		return nil, err
	}

	if (*settings).Help {
		return settings, nil
	}

	opts := make(map[string]string)
	opts, err = appendOptionsOfFile(opts, serverFilePath)
	if err != nil {
		return nil, err
	}
	opts, err = appendOptionsOfFile(opts, authFilePath)
	if err != nil {
		return nil, err
	}

	if (*settings).SmtpHost == "" {
		if opts[flagSmtpHost] != "" {
			if err := (*settings).SmtpHost.Set(opts[flagSmtpHost]); err != nil {
				return nil, err
			}
		}
	}
	if (*settings).SmtpPort == 0 {
		if opts[flagSmtpPort] != "" {
			if err := (*settings).SmtpPort.Set(opts[flagSmtpPort]); err != nil {
				return nil, err
			}
		}
	}
	if (*settings).RootCA == "" {
		if opts[flagRootCA] != "" {
			if err := (*settings).RootCA.Set(opts[flagRootCA]); err != nil {
				return nil, err
			}
		}
	}
	if (*settings).Security == types.NoSecurity {
		if opts[flagSecurity] != "" {
			if err := (*settings).Security.Set(opts[flagSecurity]); err != nil {
				return nil, err
			}
		}
	}
	if (*settings).Authentication == types.NoAuthentication {
		if opts[flagAuthMethod] != "" {
			if err := (*settings).Authentication.Set(opts[flagAuthMethod]); err != nil {
				return nil, err
			}
		}
	}
	if (*settings).Login == "" {
		(*settings).Login = opts[flagLogin]
	}
	if (*settings).Password == "" {
		(*settings).Password = opts[flagPassword]
	}
	if (*settings).Sender.Address == "" {
		if opts[flagSender] != "" {
			if err := (*settings).Sender.Set(opts[flagSender]); err != nil {
				return nil, err
			}
		}
	}
	return settings, nil
}

func getFlagSettings(output io.Writer) (*Settings, types.FilePath, types.FilePath, error) {
	var serverFilePath, authFilePath types.FilePath
	var settings Settings

	fs := flag.NewFlagSet("cmdflags", flag.ContinueOnError)
	fs.Usage = func() {}     // Disable flags usage output
	fs.SetOutput(io.Discard) // Disable text output
	fs.Var(&serverFilePath, flagServerFile, "Path to settings file.")
	fs.Var(&settings.SmtpHost, flagSmtpHost, "Hostname of SMTP server.")
	fs.Var(&settings.SmtpPort, flagSmtpPort, "TCP port of SMTP server.")
	fs.Var(&settings.RootCA, flagRootCA, "File path to X.509 certificate in PEM format for the Root CA when using a self-signed certificate on the mail server.")
	fs.Var(&settings.Security, flagSecurity, fmt.Sprintf("Security protocol (%s, %s).", types.StartTlsSec, types.SslTlsSec))

	fs.Var(&authFilePath, flagAuthFile, "Path to authentication file.")
	fs.Var(&settings.Authentication, flagAuthMethod, fmt.Sprintf("Authentication Method (%s, %s).", types.PlainAuth, types.CramMd5Auth))
	fs.StringVar(&settings.Login, flagLogin, "", "Login username")
	fs.StringVar(&settings.Password, flagPassword, "", "Login password.")

	fs.Var(&settings.Sender, flagSender, "Email address of sender.")
	fs.Var(&settings.ReplyTo, flagReplyTo, fmt.Sprintf("Reply-To address. Comma separate multiple email addresses or use multiple %s options.", flagReplyTo))

	fs.Var(&settings.RecipientsTo, flagTo, fmt.Sprintf("Recipient TO address. Comma separate multiple email addresses or use multiple %s options.", flagTo))
	fs.Var(&settings.RecipientsCC, flagCc, fmt.Sprintf("Recipient CC address. Comma separate multiple email addresses or use multiple %s options.", flagCc))
	fs.Var(&settings.RecipientsBCC, flagBcc, fmt.Sprintf("Recipient BCC address. Comma separate multiple email addresses or use multiple %s options.", flagBcc))
	fs.StringVar(&settings.MessageID, flagMessageId, "", "Custom Message-ID.")
	fs.StringVar(&settings.Subject, flagSubject, "", "Email subject")
	fs.Var(&settings.Headers, flagHeader, fmt.Sprintf("Custom header. Multiple -%s flags are allowed.", flagHeader))

	fs.StringVar(&settings.BodyText, flagBodyText, "", "Body content in plain text.Add new lines as \\n.")
	fs.StringVar(&settings.BodyHtml, flagBodyHtml, "", "Body content in HTML.")
	fs.Var(&settings.Attachments, flagAttachment, fmt.Sprintf("File path to attachment. Comma separate multiple attachments of use multiple %s options.", flagAttachment))
	fs.BoolVar(&settings.Help, flagHelp, false, "Show flag options.")

	err := fs.Parse(os.Args[1:])
	if err != nil {
		return &Settings{}, "", "", err
	}

	if settings.Help {
		fs.SetOutput(output) // Enable text output
		fs.PrintDefaults()   // Print flags usage
		return &settings, "", "", nil
	}
	return &settings, serverFilePath, authFilePath, nil
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
		value := strings.Trim(strings.TrimSpace(line[equalIndex+1:]), "\"")
		opts[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %s", err)
	}
	return opts, nil
}
