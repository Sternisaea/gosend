package cmdflags

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Sternisaea/gosend/src/types"
)

type option struct {
	name                   string
	arguments              []string
	expectedSettings       Settings
	expectedServerFilePath types.FilePath
	expectedAuthFilePath   types.FilePath
	expectedError          error
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

	headerLength := "X-Length: "
	headerIsMax := fmt.Sprintf("%s%s", headerLength, strings.Repeat("H", types.MaxLineLength-len(headerLength)))
	headerOverMax := fmt.Sprintf("%s%s", headerLength, strings.Repeat("H", types.MaxLineLength-len(headerLength)+1))

	options := []option{
		OptOk(t, "empty", flagSmtpHost, "", Settings{}),
		OptOk(t, "normal", flagSmtpHost, "domain.com", Settings{SmtpHost: "domain.com"}),
		OptOk(t, "non-tld", flagSmtpHost, "domain", Settings{SmtpHost: "domain"}),
		OptErr(t, "directory", flagSmtpHost, "domain.com/dir", types.ErrDomainInvalid),
		OptErr(t, "double quoted", flagSmtpHost, `"domain.com"`, types.ErrDomainInvalid),

		OptOk(t, "regular", flagSmtpPort, "587", Settings{SmtpPort: 587}),
		OptErr(t, "negative", flagSmtpPort, "-1", types.ErrPortNegative),
		OptErr(t, "out of range", flagSmtpPort, "65536", types.ErrPortOutOfRange),
		OptErr(t, "empty", flagSmtpPort, "", types.ErrPortInvalid),

		OptOk(t, "existing", flagRootCA, tmpExistingFile.Name(), Settings{RootCA: types.FilePath(tmpExistingFile.Name())}),
		OptErr(t, "non-existing", flagRootCA, tmpNonExistingFile.Name(), types.ErrFileNotExist),

		OptOk(t, "none", flagSecurity, string(types.NoSecurity), Settings{Security: types.NoSecurity}),
		OptOk(t, "StartTLS", flagSecurity, string(types.StartTlsSec), Settings{Security: types.StartTlsSec}),
		OptOk(t, "SSLTLS", flagSecurity, string(types.SslTlsSec), Settings{Security: types.SslTlsSec}),
		OptErr(t, "invalid", flagSecurity, "INVALID", types.ErrSecurityInvalid),

		OptOk(t, "none", flagAuthMethod, string(types.NoAuthentication), Settings{Authentication: types.NoAuthentication}),
		OptOk(t, "plain", flagAuthMethod, string(types.PlainAuth), Settings{Authentication: types.PlainAuth}),
		OptOk(t, "crammd5", flagAuthMethod, string(types.CramMd5Auth), Settings{Authentication: types.CramMd5Auth}),
		OptErr(t, "invalid", flagAuthMethod, "INVALID", types.ErrAuthenticationInvalid),

		OptOk(t, "empty", flagLogin, "", Settings{}),
		OptOk(t, "regular", flagLogin, "My Name", Settings{Login: "My Name"}),
		OptOk(t, "unicode", flagLogin, "私の名前", Settings{Login: "私の名前"}),
		OptOk(t, "email", flagLogin, "user@example.com", Settings{Login: "user@example.com"}),

		OptOk(t, "empty", flagPassword, "", Settings{}),
		OptOk(t, "regular", flagPassword, "MySecret", Settings{Password: "MySecret"}),
		OptOk(t, "unicode", flagPassword, "秘密のパスワード", Settings{Password: "秘密のパスワード"}),
		OptOk(t, "special", flagPassword, "!\"#$%&'()*+,-./:;<=>?@[]\\^_`{}|~", Settings{Password: "!\"#$%&'()*+,-./:;<=>?@[]\\^_`{}|~"}),

		OptOk(t, "email", flagSender, "sender@example.com", Settings{Sender: types.Email{Name: "", Address: "sender@example.com"}}),
		OptOk(t, "name", flagSender, "Sender<sender@example.com>", Settings{Sender: types.Email{Name: "Sender", Address: "sender@example.com"}}),
		OptErr(t, "empty", flagSender, "", types.ErrEmailInvalid),
		OptErr(t, "no at", flagSender, "sender", types.ErrEmailInvalid),
		OptErr(t, "no domain", flagSender, "sender@", types.ErrEmailInvalid),

		OptOk(t, "empty", flagReplyTo, "", Settings{}),
		OptOk(t, "email", flagReplyTo, "replyto@example.com", Settings{ReplyTo: types.EmailAddresses{types.Email{Name: "", Address: "replyto@example.com"}}}),
		OptOk(t, "emails", flagReplyTo, "reply1@example.com, reply2@example.com", Settings{ReplyTo: types.EmailAddresses{types.Email{Name: "", Address: "reply1@example.com"}, types.Email{Name: "", Address: "reply2@example.com"}}}),
		OptOk(t, "name", flagReplyTo, "ReplyTo<replyto@example.com>", Settings{ReplyTo: types.EmailAddresses{types.Email{Name: "ReplyTo", Address: "replyto@example.com"}}}),
		OptOk(t, "names", flagReplyTo, "Reply1<reply1@example.com>,Reply2<reply2@example.com>", Settings{ReplyTo: types.EmailAddresses{types.Email{Name: "Reply1", Address: "reply1@example.com"}, types.Email{Name: "Reply2", Address: "reply2@example.com"}}}),
		OptErr(t, "no at", flagReplyTo, "replyto", types.ErrEmailInvalid),
		OptErr(t, "no domain", flagReplyTo, "replyto@", types.ErrEmailInvalid),
		OptErr(t, "partly", flagReplyTo, "reply1@example.com, reply2", types.ErrEmailInvalid),

		OptOk(t, "empty", flagTo, "", Settings{}),
		OptOk(t, "names", flagTo, "To1<to1@example.com>,To2<to2@example.com>", Settings{RecipientsTo: types.EmailAddresses{types.Email{Name: "To1", Address: "to1@example.com"}, types.Email{Name: "To2", Address: "to2@example.com"}}}),
		OptErr(t, "partly", flagTo, "to1@example.com, to2", types.ErrEmailInvalid),

		OptOk(t, "empty", flagCc, "", Settings{}),
		OptOk(t, "names", flagCc, "Cc1<cc1@example.com>,Cc2<cc2@example.com>", Settings{RecipientsCC: types.EmailAddresses{types.Email{Name: "Cc1", Address: "cc1@example.com"}, types.Email{Name: "Cc2", Address: "cc2@example.com"}}}),
		OptErr(t, "partly", flagCc, "cc1@example.com, cc2", types.ErrEmailInvalid),

		OptOk(t, "empty", flagBcc, "", Settings{}),
		OptOk(t, "names", flagBcc, "Bcc1<bcc1@example.com>,Bcc2<bcc2@example.com>", Settings{RecipientsBCC: types.EmailAddresses{types.Email{Name: "Bcc1", Address: "bcc1@example.com"}, types.Email{Name: "Bcc2", Address: "bcc2@example.com"}}}),
		OptErr(t, "partly", flagBcc, "bcc1@example.com, bcc2", types.ErrEmailInvalid),

		OptOk(t, "empty", flagMessageId, "", Settings{}),
		OptOk(t, "regular", flagMessageId, "ID-1234567890", Settings{MessageID: "ID-1234567890"}),
		OptOk(t, "special", flagMessageId, "!\"#$%&'()*+,-./:;<=>?@[]\\^_`{}|~", Settings{MessageID: "!\"#$%&'()*+,-./:;<=>?@[]\\^_`{}|~"}),

		OptOk(t, "empty", flagSubject, "", Settings{}),
		OptOk(t, "regular", flagSubject, "Subject", Settings{Subject: "Subject"}),
		OptOk(t, "unicode", flagSubject, "件名", Settings{Subject: "件名"}),
		OptOk(t, "special", flagSubject, "!\"#$%&'()*+,-./:;<=>?@[]\\^_`{}|~", Settings{Subject: "!\"#$%&'()*+,-./:;<=>?@[]\\^_`{}|~"}),

		OptOk(t, "custom", flagHeader, "X-Test: testing", Settings{Headers: types.Headers{"X-Test: testing"}}),
		OptErr(t, "empty", flagHeader, "", types.ErrHeaderEmpty),
		OptErr(t, "name empty", flagHeader, " : testing", types.ErrHeaderNameEmpty),
		OptErr(t, "body empty", flagHeader, "X-Test: ", types.ErrHeaderBodyEmpty),
		OptErr(t, "no colons", flagHeader, "X-Test testing", types.ErrHeaderNoColon),
		OptErr(t, "2 colons", flagHeader, "X-Test: X-Custom: testing", types.ErrHeaderMultipleColons),
		OptErr(t, "illegal name", flagHeader, "X-試験: testing", types.ErrHeaderNameIllegalChars),
		OptErr(t, "illegal body", flagHeader, "X-Test: 試験", types.ErrHeaderBodyIllegalChars),
		OptOk(t, "length max", flagHeader, headerIsMax, Settings{Headers: types.Headers{types.Header(headerIsMax)}}),
		OptErr(t, "length max+1", flagHeader, headerOverMax, types.ErrHeaderLineTooLong),

		// OptOk(t, "body-text", flagBodyText, "This is a plain text body.", Settings{BodyText: "This is a plain text body."}),

		// OptOk(t, "body-html", flagBodyHtml, "<p>This is an HTML body.</p>", Settings{BodyHtml: "<p>This is an HTML body.</p>"}),

		// OptOk(t, "attachment", flagAttachment, tmpExistingFile.Name(), Settings{Attachment: types.FilePath(tmpExistingFile.Name())}),
		// OptErr(t, "non-existing attachment", flagAttachment, tmpNonExistingFile.Name(), "file "+tmpNonExistingFile.Name()+" does not exist (stat "+tmpNonExistingFile.Name()+": no such file or directory)"),

		// OptOk(t, "help", flagHelp, "", Settings{Help: true}),

	}

	for _, opt := range options {
		t.Run(opt.name, func(t *testing.T) {
			os.Args = opt.arguments
			settings, serverFilePath, authFilePath, err := getFlagsettings()

			if opt.expectedError == nil {
				if err != nil {
					t.Errorf("Expected no error, got %s", err)
					return
				}
			} else {
				if err == nil {
					t.Errorf("Expected error %s, but got no error", opt.expectedError)
				} else {
					// if !errors.Is(err, opt.expectedError)  // Flag package does not wrap errors
					if !strings.Contains(err.Error(), opt.expectedError.Error()) {
						t.Errorf("Expected error %s, got %s", opt.expectedError, err.Error())
					}
				}
				return
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
		expectedError:          nil,
	}
	switch flag {
	case flagServerFile:
		opt.expectedServerFilePath = types.FilePath(value)
	case flagAuthFile:
		opt.expectedAuthFilePath = types.FilePath(value)
	}
	return opt
}

func OptErr(t testing.TB, name, flag, value string, expErr error) option {
	t.Helper()
	return option{
		name:                   "flag " + flag + " " + name,
		arguments:              []string{"gosend", "-" + flag, value},
		expectedSettings:       Settings{},
		expectedServerFilePath: "",
		expectedAuthFilePath:   "",
		expectedError:          expErr,
	}
}
