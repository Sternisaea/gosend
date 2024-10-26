package cmdflags

import (
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Sternisaea/gosend/src/types"
)

type option struct {
	name             string
	arguments        []string
	expectedSettings Settings
	expectedError    error
	fileName         string
}

func Test_getFlagsettings(t *testing.T) {

	tmpExistingFileName, err := createSettingsFile("exist", "", "", false, false)
	if err != nil {
		t.Errorf("Cannot create file %s", err)
	}
	defer os.Remove(tmpExistingFileName)

	tmpNonExistingFileName, err := createSettingsFile("exist", "", "", false, false)
	if err != nil {
		t.Errorf("Cannot create file %s", err)
	} else {
		if err := os.Remove(tmpNonExistingFileName); err != nil {
			t.Errorf("Cannot remove file %s", err)
		}
	}

	headerLength := "X-Length: "
	headerMax := fmt.Sprintf("%s%s", headerLength, strings.Repeat("H", types.MaxLineLength-len(headerLength)))
	headerMaxPlus1 := fmt.Sprintf("%s%s", headerLength, strings.Repeat("H", types.MaxLineLength-len(headerLength)+1))
	header2LinesMax := fmt.Sprintf("%s%s\r\n%s", headerLength, strings.Repeat("H", types.MaxLineLength-len(headerLength)), strings.Repeat("D", types.MaxLineLength))
	header2LinesMaxPlus1 := fmt.Sprintf("%s%s\r\n%s", headerLength, strings.Repeat("H", types.MaxLineLength-len(headerLength)), strings.Repeat("D", types.MaxLineLength+1))

	options := &[]option{
		optOk(t, "normal", flagSmtpHost, "domain.com", Settings{SmtpHost: "domain.com"}),
		optOk(t, "non-tld", flagSmtpHost, "domain", Settings{SmtpHost: "domain"}),
		optErr(t, "empty", flagSmtpHost, "", types.ErrDomainEmpty),
		optErr(t, "directory", flagSmtpHost, "domain.com/dir", types.ErrDomainInvalid),
		optErr(t, "double quoted", flagSmtpHost, `"domain.com"`, types.ErrDomainInvalid),

		optOk(t, "regular", flagSmtpPort, "587", Settings{SmtpPort: 587}),
		optErr(t, "negative", flagSmtpPort, "-1", types.ErrPortNegative),
		optErr(t, "out of range", flagSmtpPort, "65536", types.ErrPortOutOfRange),
		optErr(t, "empty", flagSmtpPort, "", types.ErrPortInvalid),

		optOk(t, "existing", flagRootCA, tmpExistingFileName, Settings{RootCA: types.FilePath(tmpExistingFileName)}),
		optErr(t, "empty", flagRootCA, "", types.ErrFileEmpty),
		optErr(t, "non-existing", flagRootCA, tmpNonExistingFileName, types.ErrFileNotExist),

		optOk(t, "none", flagSecurity, string(types.NoSecurity), Settings{Security: types.NoSecurity}),
		optOk(t, "StartTLS", flagSecurity, string(types.StartTlsSec), Settings{Security: types.StartTlsSec}),
		optOk(t, "SSLTLS", flagSecurity, string(types.SslTlsSec), Settings{Security: types.SslTlsSec}),
		optErr(t, "invalid", flagSecurity, "INVALID", types.ErrSecurityInvalid),

		optOk(t, "none", flagAuthMethod, string(types.NoAuthentication), Settings{Authentication: types.NoAuthentication}),
		optOk(t, "plain", flagAuthMethod, string(types.PlainAuth), Settings{Authentication: types.PlainAuth}),
		optOk(t, "crammd5", flagAuthMethod, string(types.CramMd5Auth), Settings{Authentication: types.CramMd5Auth}),
		optErr(t, "invalid", flagAuthMethod, "INVALID", types.ErrAuthenticationInvalid),

		optOk(t, "empty", flagLogin, "", Settings{}),
		optOk(t, "regular", flagLogin, "My Name", Settings{Login: "My Name"}),
		optOk(t, "unicode", flagLogin, "私の名前", Settings{Login: "私の名前"}),
		optOk(t, "email", flagLogin, "user@example.com", Settings{Login: "user@example.com"}),

		optOk(t, "empty", flagPassword, "", Settings{}),
		optOk(t, "regular", flagPassword, "MySecret", Settings{Password: "MySecret"}),
		optOk(t, "unicode", flagPassword, "秘密のパスワード", Settings{Password: "秘密のパスワード"}),
		optOk(t, "special", flagPassword, "!\"#$%&'()*+,-./:;<=>?@[]\\^_`{}|~", Settings{Password: "!\"#$%&'()*+,-./:;<=>?@[]\\^_`{}|~"}),

		optOk(t, "email", flagSender, "sender@example.com", Settings{Sender: types.Email{Name: "", Address: "sender@example.com"}}),
		optOk(t, "name", flagSender, "Sender<sender@example.com>", Settings{Sender: types.Email{Name: "Sender", Address: "sender@example.com"}}),
		optErr(t, "empty", flagSender, "", types.ErrEmailInvalid),
		optErr(t, "no at", flagSender, "sender", types.ErrEmailInvalid),
		optErr(t, "no domain", flagSender, "sender@", types.ErrEmailInvalid),

		optOk(t, "empty", flagReplyTo, "", Settings{}),
		optOk(t, "email", flagReplyTo, "replyto@example.com", Settings{ReplyTo: types.EmailAddresses{types.Email{Name: "", Address: "replyto@example.com"}}}),
		optOk(t, "emails", flagReplyTo, "reply1@example.com, reply2@example.com", Settings{ReplyTo: types.EmailAddresses{types.Email{Name: "", Address: "reply1@example.com"}, types.Email{Name: "", Address: "reply2@example.com"}}}),
		optOk(t, "name", flagReplyTo, "ReplyTo<replyto@example.com>", Settings{ReplyTo: types.EmailAddresses{types.Email{Name: "ReplyTo", Address: "replyto@example.com"}}}),
		optOk(t, "names", flagReplyTo, "Reply1<reply1@example.com>,Reply2<reply2@example.com>", Settings{ReplyTo: types.EmailAddresses{types.Email{Name: "Reply1", Address: "reply1@example.com"}, types.Email{Name: "Reply2", Address: "reply2@example.com"}}}),
		optErr(t, "no at", flagReplyTo, "replyto", types.ErrEmailInvalid),
		optErr(t, "no domain", flagReplyTo, "replyto@", types.ErrEmailInvalid),
		optErr(t, "partly", flagReplyTo, "reply1@example.com, reply2", types.ErrEmailInvalid),

		optOk(t, "empty", flagTo, "", Settings{}),
		optOk(t, "names", flagTo, "To1<to1@example.com>,To2<to2@example.com>", Settings{RecipientsTo: types.EmailAddresses{types.Email{Name: "To1", Address: "to1@example.com"}, types.Email{Name: "To2", Address: "to2@example.com"}}}),
		optErr(t, "partly", flagTo, "to1@example.com, to2", types.ErrEmailInvalid),

		optOk(t, "empty", flagCc, "", Settings{}),
		optOk(t, "names", flagCc, "Cc1<cc1@example.com>,Cc2<cc2@example.com>", Settings{RecipientsCC: types.EmailAddresses{types.Email{Name: "Cc1", Address: "cc1@example.com"}, types.Email{Name: "Cc2", Address: "cc2@example.com"}}}),
		optErr(t, "partly", flagCc, "cc1@example.com, cc2", types.ErrEmailInvalid),

		optOk(t, "empty", flagBcc, "", Settings{}),
		optOk(t, "names", flagBcc, "Bcc1<bcc1@example.com>,Bcc2<bcc2@example.com>", Settings{RecipientsBCC: types.EmailAddresses{types.Email{Name: "Bcc1", Address: "bcc1@example.com"}, types.Email{Name: "Bcc2", Address: "bcc2@example.com"}}}),
		optErr(t, "partly", flagBcc, "bcc1@example.com, bcc2", types.ErrEmailInvalid),

		optOk(t, "empty", flagMessageId, "", Settings{}),
		optOk(t, "regular", flagMessageId, "ID-1234567890", Settings{MessageID: "ID-1234567890"}),
		optOk(t, "special", flagMessageId, "!\"#$%&'()*+,-./:;<=>?@[]\\^_`{}|~", Settings{MessageID: "!\"#$%&'()*+,-./:;<=>?@[]\\^_`{}|~"}),

		optOk(t, "empty", flagSubject, "", Settings{}),
		optOk(t, "regular", flagSubject, "Subject", Settings{Subject: "Subject"}),
		optOk(t, "unicode", flagSubject, "件名", Settings{Subject: "件名"}),
		optOk(t, "special", flagSubject, "!\"#$%&'()*+,-./:;<=>?@[]\\^_`{}|~", Settings{Subject: "!\"#$%&'()*+,-./:;<=>?@[]\\^_`{}|~"}),

		optOk(t, "custom", flagHeader, "X-Test: testing", Settings{Headers: types.Headers{"X-Test: testing"}}),
		optErr(t, "empty", flagHeader, "", types.ErrHeaderEmpty),
		optErr(t, "name empty", flagHeader, " : testing", types.ErrHeaderNameEmpty),
		optErr(t, "body empty", flagHeader, "X-Test: ", types.ErrHeaderBodyEmpty),
		optErr(t, "no colons", flagHeader, "X-Test testing", types.ErrHeaderNoColon),
		optErr(t, "2 colons", flagHeader, "X-Test: X-Custom: testing", types.ErrHeaderMultipleColons),
		optErr(t, "illegal name", flagHeader, "X-試験: testing", types.ErrHeaderNameIllegalChars),
		optErr(t, "illegal body", flagHeader, "X-Test: 試験", types.ErrHeaderBodyIllegalChars),
		optOk(t, "length max", flagHeader, headerMax, Settings{Headers: types.Headers{types.Header(headerMax)}}),
		optErr(t, "length max+1", flagHeader, headerMaxPlus1, types.ErrHeaderLineTooLong),
		optOk(t, "2 lines max", flagHeader, header2LinesMax, Settings{Headers: types.Headers{types.Header(header2LinesMax)}}),
		optErr(t, "2 lines max+1", flagHeader, header2LinesMaxPlus1, types.ErrHeaderLineTooLong),

		optOk(t, "empty", flagBodyText, "", Settings{}),
		optOk(t, "text", flagBodyText, "This is a plain text \nbody.", Settings{BodyText: "This is a plain text \nbody."}),

		optOk(t, "empty", flagBodyHtml, "", Settings{}),
		optOk(t, "html", flagBodyHtml, "<p>This is an HTML body.</p>", Settings{BodyHtml: "<p>This is an HTML body.</p>"}),

		optOk(t, "1 file", flagAttachment, tmpExistingFileName, Settings{Attachments: types.Attachments{types.FilePath(tmpExistingFileName)}}),
		optOk(t, "2 file", flagAttachment, fmt.Sprintf("%s, %s", tmpExistingFileName, tmpExistingFileName), Settings{Attachments: types.Attachments{types.FilePath(tmpExistingFileName), types.FilePath(tmpExistingFileName)}}),
		optErr(t, "empty", flagAttachment, "", types.ErrFileEmpty),
		optErr(t, "fake-1", flagAttachment, tmpNonExistingFileName, types.ErrAttachmentInvalid),
		optErr(t, "fake-2", flagAttachment, tmpNonExistingFileName, types.ErrFileNotExist),

		optOk(t, "help", flagHelp, "", Settings{Help: true}),

		settOk(t, "normal", flagServerFile, flagSmtpHost, "domain.com", false, false, Settings{SmtpHost: "domain.com"}),
		settOk(t, "normal", flagServerFile, flagSmtpHost, "domain.com", false, true, Settings{SmtpHost: "domain.com"}),
		settOk(t, "normal", flagServerFile, flagSmtpHost, "domain.com", true, false, Settings{SmtpHost: "domain.com"}),
		settOk(t, "normal", flagServerFile, flagSmtpHost, "domain.com", true, true, Settings{SmtpHost: "domain.com"}),
	}

	for _, opt := range *options {
		t.Run(opt.name, func(t *testing.T) {
			if opt.fileName != "" {
				defer os.Remove(opt.fileName)
			}

			os.Args = opt.arguments
			settings, err := GetSettings(io.Discard)

			if opt.expectedError == nil {
				if err != nil {
					t.Fatalf("Expected no error, got %s", err)
				}
			} else {
				if err == nil {
					t.Fatalf("Expected error %s, but got no error", opt.expectedError)
				} else {
					// Cannot use 'errors.Is' because flag package does not wrap errors (as for go1.23.2)
					if strings.Contains(err.Error(), opt.expectedError.Error()) {
						return // Expected error
					} else {
						t.Fatalf("Expected error %s, got %s", opt.expectedError, err.Error())
					}
				}
			}

			if !reflect.DeepEqual(*settings, opt.expectedSettings) {
				t.Errorf("Expected %v, got %v", opt.expectedSettings, settings)
			}
		})
	}
}

func optOk(t testing.TB, name, flag, value string, settings Settings) option {
	t.Helper()
	return option{
		name:             "flag " + flag + " " + name,
		arguments:        []string{"gosend", "-" + flag, value},
		expectedSettings: settings,
		expectedError:    nil,
	}
}

func optErr(t testing.TB, name, flag, value string, expectedErr error) option {
	t.Helper()
	return option{
		name:             "flag " + flag + " " + name,
		arguments:        []string{"gosend", "-" + flag, value},
		expectedSettings: Settings{},
		expectedError:    expectedErr,
	}
}

func settOk(t testing.TB, name, settingsFlag, flag, value string, spaces, quotes bool, settings Settings) option {
	t.Helper()
	sn := getSettingName(flag, name, spaces, quotes)
	fileName, err := createSettingsFile(sn, flag, value, spaces, quotes)
	if err != nil {
		t.Fatal(err)
	}
	return option{
		name:             sn,
		arguments:        []string{"gosend", "-" + settingsFlag, fileName},
		expectedSettings: settings,
		expectedError:    nil,
		fileName:         fileName,
	}
}

func settErr(t testing.TB, name, settingsFlag, flag, value string, spaces, quotes bool, expectedErr error) option {
	t.Helper()
	sn := getSettingName(flag, name, spaces, quotes)
	fileName, err := createSettingsFile(sn, flag, value, spaces, quotes)
	if err != nil {
		t.Fatal(err)
	}
	return option{
		name:             sn,
		arguments:        []string{"gosend", "-" + settingsFlag, fileName},
		expectedSettings: Settings{},
		expectedError:    expectedErr,
		fileName:         fileName,
	}
}

func getSettingName(flag, name string, spaces, quotes bool) string {
	sn := "setting " + flag + " " + name
	if spaces {
		sn += " SP"
	}
	if quotes {
		sn += " QU"
	}
	return sn
}

func createSettingsFile(name, flag, value string, spaces, quotes bool) (string, error) {
	tmpFile, err := os.CreateTemp(os.TempDir(), name)
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()
	fileName := tmpFile.Name()
	if flag != "" {
		var text string
		switch {
		case !spaces && !quotes:
			text = fmt.Sprintf("%s=%s", flag, value)
		case !spaces && quotes:
			text = fmt.Sprintf("%s=\"%s\"", flag, value)
		case spaces && !quotes:
			text = fmt.Sprintf("%s = %s", flag, value)
		case spaces && quotes:
			text = fmt.Sprintf("%s = \"%s\"", flag, value)
		}
		if _, err := fmt.Fprintln(tmpFile, text); err != nil {
			return "", err
		}
	}
	return fileName, nil
}
