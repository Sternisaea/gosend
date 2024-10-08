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
	flagServerSettingsFile = "server-settings-file"
	flagSmtpHost           = "smtp-host"
	flagSmtpPort           = "smtp-port"
	flagAuthFile           = "auth-file"
	flagAuthMethod         = "auth-method"
	flagLogin              = "login"
	flagPassword           = "password"
	flagSender             = "sender"
	flagTo                 = "to"
	flagCc                 = "cc"
	flagBcc                = "bcc"
	flagSubject            = "subject"
	flagAttachment         = "attachment"
)

type Settings struct {
	smtpHost   types.DomainName
	smtpPort   types.TCPPort
	authMethod types.AuthMethod
	login      string
	password   string
	sender     types.Email

	recipientsTo  types.EmailAddresses
	recipientsCC  types.EmailAddresses
	recipientsBCC types.EmailAddresses
	subject       string

	attachments types.Attachments
}

func GetSettings() (*Settings, error) {
	fs, serverFilePath, authFilePath := getFlagsettings()

	opts := make(map[string]string)
	opts, err := appendOptionsOfFile(opts, serverFilePath)
	if err != nil {
		return nil, err
	}
	opts, err = appendOptionsOfFile(opts, authFilePath)
	if err != nil {
		return nil, err
	}

	if fs.smtpHost == "" {
		if err := fs.smtpHost.Set(opts[flagSmtpHost]); err != nil {
			return nil, err
		}
	}
	if fs.smtpPort == 0 {
		if err := fs.smtpPort.Set(opts[flagSmtpPort]); err != nil {
			return nil, err
		}
	}
	if fs.authMethod == "" {
		if err := fs.authMethod.Set(opts[flagAuthMethod]); err != nil {
			return nil, err
		}
	}
	if fs.login == "" {
		fs.login = opts[flagLogin]
	}
	if fs.password == "" {
		fs.password = opts[flagPassword]
	}
	if fs.sender == "" {
		if err := fs.sender.Set(opts[flagSender]); err != nil {
			return nil, err
		}
	}
	return &fs, nil
}

func getFlagsettings() (Settings, types.FilePath, types.FilePath) {
	var serverFilePath, authFilePath types.FilePath
	var fs Settings
	flag.Var(&serverFilePath, flagServerSettingsFile, "Path to settings file")
	flag.Var(&fs.smtpHost, flagSmtpHost, "Hostname of SMTP server")
	flag.Var(&fs.smtpPort, flagSmtpPort, "TCP port of SMTP server")

	flag.Var(&authFilePath, flagAuthFile, "Path to authentication file")
	flag.Var(&fs.authMethod, flagAuthMethod, fmt.Sprintf("Authentication method (%s, %s)", types.STARTTLS, types.SSLTLS))
	flag.StringVar(&fs.login, flagLogin, "", "Login username")
	flag.StringVar(&fs.password, flagPassword, "", "Login password")
	flag.Var(&fs.sender, flagSender, "Email address of sender")

	flag.Var(&fs.recipientsTo, flagTo, fmt.Sprintf("Recipient TO address. Comma separate multiple email addresses or use multiple %s options.", flagTo))
	flag.Var(&fs.recipientsCC, flagCc, fmt.Sprintf("Recipient CC address. Comma separate multiple email addresses or use multiple %s options.", flagCc))
	flag.Var(&fs.recipientsBCC, flagBcc, fmt.Sprintf("Recipient BCC address. Comma separate multiple email addresses or use multiple %s options.", flagBcc))
	flag.StringVar(&fs.subject, flagSubject, "", "Email subject")

	flag.Var(&fs.attachments, flagAttachment, fmt.Sprintf("File path to attachment. Comma separate multiple attachments of use multiple %s options.", flagAttachment))
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
		key := strings.TrimSpace(line[:equalIndex])
		value := strings.TrimSpace(line[equalIndex+1:])
		opts[key] = value

	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %s", err)
	}
	return opts, nil
}
