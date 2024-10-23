package cmdflags

import (
	"os"
	"reflect"
	"testing"

	"github.com/Sternisaea/gosend/src/types"
)

type option struct {
	name                   string
	arguments              []string
	expectedSettings       Settings
	expectedServerFilePath types.FilePath
	expectedAuthFilePath   types.FilePath
	expectedErrorMessage   string
}

func Test_getFlagsettings(t *testing.T) {
	tmpExistingFile, err := os.CreateTemp(os.TempDir(), "gosend_file.tmp")
	if err != nil {
		t.Errorf("Cannot create file %s", err)
	} else {
		defer func() {
			if err := tmpExistingFile.Close(); err != nil {
				t.Errorf("Cannot close file %s", err)
			}
			if err := os.Remove(tmpExistingFile.Name()); err != nil {
				t.Errorf("Cannot remove file %s", err)
			}

		}()
	}

	tmpNonExistingFile, err := os.CreateTemp(os.TempDir(), "gosend_non.tmp")
	if err != nil {
		t.Errorf("Cannot create file %s", err)
	}
	if err := tmpNonExistingFile.Close(); err != nil {
		t.Errorf("Cannot close file %s", err)
	}
	if err := os.Remove(tmpNonExistingFile.Name()); err != nil {
		t.Errorf("Cannot remove file %s", err)
	}

	options := make([]option, 0, 100)
	options = append(options, OptOk(t, "empty", flagSmtpHost, "", Settings{}))
	options = append(options, OptOk(t, "normal", flagSmtpHost, "domain.com", Settings{SmtpHost: "domain.com"}))
	options = append(options, OptOk(t, "non-tld", flagSmtpHost, "domain", Settings{SmtpHost: "domain"}))
	options = append(options, OptErr(t, "directory", flagSmtpHost, "domain.com/dir", "invalid domain name: domain.com/dir (idna: disallowed rune U+002F)"))

	options = append(options, OptOk(t, "regular", flagSmtpPort, "587", Settings{SmtpPort: 587}))
	options = append(options, OptErr(t, "negative", flagSmtpPort, "-1", types.ErrPortNegative.Error()))
	options = append(options, OptErr(t, "out of range", flagSmtpPort, "65536", types.ErrPortOutOfRange.Error()))

	options = append(options, OptOk(t, "existing", flagRootCA, tmpExistingFile.Name(), Settings{RootCA: types.FilePath(tmpExistingFile.Name())}))
	options = append(options, OptErr(t, "non-existing", flagRootCA, tmpNonExistingFile.Name(), "file "+tmpNonExistingFile.Name()+" does not exist (stat "+tmpNonExistingFile.Name()+": no such file or directory)"))

	options = append(options, OptOk(t, "none", flagSecurity, string(types.NoSecurity), Settings{Security: types.NoSecurity}))
	options = append(options, OptOk(t, "StartTLS", flagSecurity, string(types.StartTlsSec), Settings{Security: types.StartTlsSec}))
	options = append(options, OptOk(t, "SSLTLS", flagSecurity, string(types.SslTlsSec), Settings{Security: types.SslTlsSec}))
	options = append(options, OptErr(t, "invalid", flagSecurity, "INVALID", "invalid security protocol: INVALID (valid options are: starttls, ssl/tls)"))

	// options = append(options, OptOk(t, "auth method", flagAuthMethod, "PLAIN", Settings{AuthMethod: "PLAIN"}))
	// options = append(options, OptErr(t, "invalid auth method", flagAuthMethod, "INVALID", "unsupported authentication method: INVALID"))

	// options = append(options, OptOk(t, "login", flagLogin, "user@example.com", Settings{Login: "user@example.com"}))

	// options = append(options, OptOk(t, "password", flagPassword, "password123", Settings{Password: "password123"}))

	// options = append(options, OptOk(t, "sender", flagSender, "sender@example.com", Settings{Sender: "sender@example.com"}))

	// options = append(options, OptOk(t, "reply-to", flagReplyTo, "replyto@example.com", Settings{ReplyTo: "replyto@example.com"}))

	// options = append(options, OptOk(t, "to", flagTo, "recipient@example.com", Settings{To: "recipient@example.com"}))

	// options = append(options, OptOk(t, "cc", flagCc, "cc@example.com", Settings{Cc: "cc@example.com"}))

	// options = append(options, OptOk(t, "bcc", flagBcc, "bcc@example.com", Settings{Bcc: "bcc@example.com"}))

	// options = append(options, OptOk(t, "message-id", flagMessageId, "12345", Settings{MessageID: "12345"}))

	// options = append(options, OptOk(t, "subject", flagSubject, "Test Subject", Settings{Subject: "Test Subject"}))

	// options = append(options, OptOk(t, "header", flagHeader, "X-Custom-Header: value", Settings{Header: "X-Custom-Header: value"}))

	// options = append(options, OptOk(t, "body-text", flagBodyText, "This is a plain text body.", Settings{BodyText: "This is a plain text body."}))

	// options = append(options, OptOk(t, "body-html", flagBodyHtml, "<p>This is an HTML body.</p>", Settings{BodyHtml: "<p>This is an HTML body.</p>"}))

	// options = append(options, OptOk(t, "attachment", flagAttachment, tmpExistingFile.Name(), Settings{Attachment: types.FilePath(tmpExistingFile.Name())}))
	// options = append(options, OptErr(t, "non-existing attachment", flagAttachment, tmpNonExistingFile.Name(), "file "+tmpNonExistingFile.Name()+" does not exist (stat "+tmpNonExistingFile.Name()+": no such file or directory)"))

	// options = append(options, OptOk(t, "help", flagHelp, "", Settings{Help: true}))

	for _, opt := range options {
		t.Run(opt.name, func(t *testing.T) {
			os.Args = opt.arguments
			settings, serverFilePath, authFilePath, err := getFlagsettings()

			var errMsg string
			if err != nil {
				errMsg = err.Error()
			}
			if errMsg != opt.expectedErrorMessage {
				t.Errorf("Expected Error %s, got %s", opt.expectedErrorMessage, errMsg)
			}

			if !reflect.DeepEqual(settings, opt.expectedSettings) {
				t.Errorf("Expected %v, got %v", opt.expectedSettings, settings)
			}
			if serverFilePath != opt.expectedServerFilePath {
				t.Errorf("Expected %s, got %s", opt.expectedServerFilePath, serverFilePath)
			}
			if authFilePath != opt.expectedAuthFilePath {
				t.Errorf("Expected %s, got %s", opt.expectedAuthFilePath, authFilePath)
			}
		})
	}

}

func OptOk(t testing.TB, name, flag, value string, settings Settings) option {
	t.Helper()
	opt := option{
		name:                   "flag " + flag + " " + name,
		arguments:              []string{"gosend", "-" + flag, value},
		expectedSettings:       settings,
		expectedServerFilePath: "",
		expectedAuthFilePath:   "",
		expectedErrorMessage:   "",
	}
	switch flag {
	case flagServerFile:
		opt.expectedServerFilePath = types.FilePath(value)
	case flagAuthFile:
		opt.expectedAuthFilePath = types.FilePath(value)
	}
	return opt
}

func OptErr(t testing.TB, name, flag, value, errMsg string) option {
	t.Helper()
	return option{
		name:                   "flag " + flag + " " + name,
		arguments:              []string{"gosend", "-" + flag, value},
		expectedSettings:       Settings{},
		expectedServerFilePath: "",
		expectedAuthFilePath:   "",
		expectedErrorMessage:   "invalid value \"" + value + "\" for flag -" + flag + ": " + errMsg,
	}
}
