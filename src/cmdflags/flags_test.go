package cmdflags

import (
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Sternisaea/gosend/src/types"
)

type check struct {
	name             string
	arguments        []string
	expectedSettings *Settings
	expectedErrors   *[]error
	fileName         string
}

type option struct {
	name, value string
}

type settingsFormat int

const (
	NoSpacesAndNoQuotes settingsFormat = iota
	NoSpacesAndQuotes
	SpacesAndNoQuotes
	SpacesAndQuotes
)

func Test_GetSettings(t *testing.T) {

	tmpExistingFileName, err := createSettingsFile("exist", []option{}, NoSpacesAndNoQuotes)
	if err != nil {
		t.Errorf("Cannot create file %s", err)
	}
	defer os.Remove(tmpExistingFileName)

	tmpExistingFileName2, err := createSettingsFile("exist", []option{}, NoSpacesAndNoQuotes)
	if err != nil {
		t.Errorf("Cannot create file %s", err)
	}
	defer os.Remove(tmpExistingFileName2)

	tmpNonExistingFileName, err := createSettingsFile("exist", []option{}, NoSpacesAndNoQuotes)
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

	checklist := make([]check, 0, 100)
	addCheckOk(t, &checklist, "flag "+flagSmtpHost+" normal", []option{{flagSmtpHost, "domain.com"}}, &Settings{SmtpHost: "domain.com"})
	addCheckOk(t, &checklist, "flag "+flagSmtpHost+" non-tld", []option{{flagSmtpHost, "domain"}}, &Settings{SmtpHost: "domain"})
	addCheckErr(t, &checklist, "flag "+flagSmtpHost+" empty", []option{{flagSmtpHost, ""}}, &[]error{types.ErrDomainEmpty})
	addCheckErr(t, &checklist, "flag "+flagSmtpHost+" directory", []option{{flagSmtpHost, "domain.com/dir"}}, &[]error{types.ErrDomainInvalid})
	addCheckErr(t, &checklist, "flag "+flagSmtpHost+" double quoted", []option{{flagSmtpHost, `"domain.com"`}}, &[]error{types.ErrDomainInvalid})

	addCheckOk(t, &checklist, "flag "+flagSmtpPort+" regular", []option{{flagSmtpPort, "587"}}, &Settings{SmtpPort: 587})
	addCheckErr(t, &checklist, "flag "+flagSmtpPort+" negative", []option{{flagSmtpPort, "-1"}}, &[]error{types.ErrPortNegative})
	addCheckErr(t, &checklist, "flag "+flagSmtpPort+" out of range", []option{{flagSmtpPort, "65536"}}, &[]error{types.ErrPortOutOfRange})
	addCheckErr(t, &checklist, "flag "+flagSmtpPort+" empty", []option{{flagSmtpPort, ""}}, &[]error{types.ErrPortInvalid})

	addCheckOk(t, &checklist, "flag "+flagRootCA+" existing", []option{{flagRootCA, tmpExistingFileName}}, &Settings{RootCA: types.FilePath(tmpExistingFileName)})
	addCheckErr(t, &checklist, "flag "+flagRootCA+" empty", []option{{flagRootCA, ""}}, &[]error{types.ErrFileEmpty})
	addCheckErr(t, &checklist, "flag "+flagRootCA+" non-existing", []option{{flagRootCA, tmpNonExistingFileName}}, &[]error{types.ErrFileNotExist})

	addCheckOk(t, &checklist, "flag "+flagSecurity+" none", []option{{flagSecurity, string(types.NoSecurity)}}, &Settings{Security: types.NoSecurity})
	addCheckOk(t, &checklist, "flag "+flagSecurity+" StartTLS", []option{{flagSecurity, string(types.StartTlsSec)}}, &Settings{Security: types.StartTlsSec})
	addCheckOk(t, &checklist, "flag "+flagSecurity+" SSLTLS", []option{{flagSecurity, string(types.SslTlsSec)}}, &Settings{Security: types.SslTlsSec})
	addCheckErr(t, &checklist, "flag "+flagSecurity+" invalid", []option{{flagSecurity, "INVALID"}}, &[]error{types.ErrSecurityInvalid})

	addCheckOk(t, &checklist, "flag "+flagAuthMethod+" none", []option{{flagAuthMethod, string(types.NoAuthentication)}}, &Settings{Authentication: types.NoAuthentication})
	addCheckOk(t, &checklist, "flag "+flagAuthMethod+" plain", []option{{flagAuthMethod, string(types.PlainAuth)}}, &Settings{Authentication: types.PlainAuth})
	addCheckOk(t, &checklist, "flag "+flagAuthMethod+" crammd5", []option{{flagAuthMethod, string(types.CramMd5Auth)}}, &Settings{Authentication: types.CramMd5Auth})
	addCheckErr(t, &checklist, "flag "+flagAuthMethod+" invalid", []option{{flagAuthMethod, "INVALID"}}, &[]error{types.ErrAuthenticationInvalid})

	addCheckOk(t, &checklist, "flag "+flagLogin+" empty", []option{{flagLogin, ""}}, &Settings{})
	addCheckOk(t, &checklist, "flag "+flagLogin+" regular", []option{{flagLogin, "My Name"}}, &Settings{Login: "My Name"})
	addCheckOk(t, &checklist, "flag "+flagLogin+" unicode", []option{{flagLogin, "私の名前"}}, &Settings{Login: "私の名前"})
	addCheckOk(t, &checklist, "flag "+flagLogin+" email", []option{{flagLogin, "user@example.com"}}, &Settings{Login: "user@example.com"})

	addCheckOk(t, &checklist, "flag "+flagPassword+" empty", []option{{flagPassword, ""}}, &Settings{})
	addCheckOk(t, &checklist, "flag "+flagPassword+" regular", []option{{flagPassword, "MySecret"}}, &Settings{Password: "MySecret"})
	addCheckOk(t, &checklist, "flag "+flagPassword+" unicode", []option{{flagPassword, "秘密のパスワード"}}, &Settings{Password: "秘密のパスワード"})
	addCheckOk(t, &checklist, "flag "+flagPassword+" special", []option{{flagPassword, "!\"#$%&'()*+,-./:;<=>?@[]\\^_`{}|~"}}, &Settings{Password: "!\"#$%&'()*+,-./:;<=>?@[]\\^_`{}|~"})

	addCheckOk(t, &checklist, "flag "+flagSender+" email", []option{{flagSender, "sender@example.com"}}, &Settings{Sender: types.Email{Name: "", Address: "sender@example.com"}})
	addCheckOk(t, &checklist, "flag "+flagSender+" name", []option{{flagSender, "Sender<sender@example.com>"}}, &Settings{Sender: types.Email{Name: "Sender", Address: "sender@example.com"}})
	addCheckErr(t, &checklist, "flag "+flagSender+" empty", []option{{flagSender, ""}}, &[]error{types.ErrEmailInvalid})
	addCheckErr(t, &checklist, "flag "+flagSender+" no at", []option{{flagSender, "sender"}}, &[]error{types.ErrEmailInvalid})
	addCheckErr(t, &checklist, "flag "+flagSender+" no domain", []option{{flagSender, "sender@"}}, &[]error{types.ErrEmailInvalid})

	addCheckOk(t, &checklist, "flag "+flagReplyTo+" empty", []option{{flagReplyTo, ""}}, &Settings{})
	addCheckOk(t, &checklist, "flag "+flagReplyTo+" email", []option{{flagReplyTo, "replyto@example.com"}}, &Settings{ReplyTo: types.EmailAddresses{types.Email{Name: "", Address: "replyto@example.com"}}})
	addCheckOk(t, &checklist, "flag "+flagReplyTo+" emails", []option{{flagReplyTo, "reply1@example.com, reply2@example.com"}}, &Settings{ReplyTo: types.EmailAddresses{types.Email{Name: "", Address: "reply1@example.com"}, types.Email{Name: "", Address: "reply2@example.com"}}})
	addCheckOk(t, &checklist, "flag "+flagReplyTo+" name", []option{{flagReplyTo, "ReplyTo<replyto@example.com>"}}, &Settings{ReplyTo: types.EmailAddresses{types.Email{Name: "ReplyTo", Address: "replyto@example.com"}}})
	addCheckOk(t, &checklist, "flag "+flagReplyTo+" names", []option{{flagReplyTo, "Reply1<reply1@example.com>,Reply2<reply2@example.com>"}}, &Settings{ReplyTo: types.EmailAddresses{types.Email{Name: "Reply1", Address: "reply1@example.com"}, types.Email{Name: "Reply2", Address: "reply2@example.com"}}})
	addCheckErr(t, &checklist, "flag "+flagReplyTo+" no at", []option{{flagReplyTo, "replyto"}}, &[]error{types.ErrEmailInvalid})
	addCheckErr(t, &checklist, "flag "+flagReplyTo+" no domain", []option{{flagReplyTo, "replyto@"}}, &[]error{types.ErrEmailInvalid})
	addCheckErr(t, &checklist, "flag "+flagReplyTo+" partly", []option{{flagReplyTo, "reply1@example.com, reply2"}}, &[]error{types.ErrEmailInvalid})

	addCheckOk(t, &checklist, "flag "+flagTo+" empty", []option{{flagTo, ""}}, &Settings{})
	addCheckOk(t, &checklist, "flag "+flagTo+" names", []option{{flagTo, "To1<to1@example.com>,To2<to2@example.com>"}}, &Settings{RecipientsTo: types.EmailAddresses{types.Email{Name: "To1", Address: "to1@example.com"}, types.Email{Name: "To2", Address: "to2@example.com"}}})
	addCheckErr(t, &checklist, "flag "+flagTo+" partly", []option{{flagTo, "to1@example.com, to2"}}, &[]error{types.ErrEmailInvalid})

	addCheckOk(t, &checklist, "flag "+flagCc+" empty", []option{{flagCc, ""}}, &Settings{})
	addCheckOk(t, &checklist, "flag "+flagCc+" names", []option{{flagCc, "Cc1<cc1@example.com>,Cc2<cc2@example.com>"}}, &Settings{RecipientsCC: types.EmailAddresses{types.Email{Name: "Cc1", Address: "cc1@example.com"}, types.Email{Name: "Cc2", Address: "cc2@example.com"}}})
	addCheckErr(t, &checklist, "flag "+flagCc+" partly", []option{{flagCc, "cc1@example.com, cc2"}}, &[]error{types.ErrEmailInvalid})

	addCheckOk(t, &checklist, "flag "+flagBcc+" empty", []option{{flagBcc, ""}}, &Settings{})
	addCheckOk(t, &checklist, "flag "+flagBcc+" names", []option{{flagBcc, "Bcc1<bcc1@example.com>,Bcc2<bcc2@example.com>"}}, &Settings{RecipientsBCC: types.EmailAddresses{types.Email{Name: "Bcc1", Address: "bcc1@example.com"}, types.Email{Name: "Bcc2", Address: "bcc2@example.com"}}})
	addCheckErr(t, &checklist, "flag "+flagBcc+" partly", []option{{flagBcc, "bcc1@example.com, bcc2"}}, &[]error{types.ErrEmailInvalid})

	addCheckOk(t, &checklist, "flag "+flagMessageId+" empty", []option{{flagMessageId, ""}}, &Settings{})
	addCheckOk(t, &checklist, "flag "+flagMessageId+" regular", []option{{flagMessageId, "ID-1234567890"}}, &Settings{MessageID: "ID-1234567890"})
	addCheckOk(t, &checklist, "flag "+flagMessageId+" special", []option{{flagMessageId, "!\"#$%&'()*+,-./:;<=>?@[]\\^_`{}|~"}}, &Settings{MessageID: "!\"#$%&'()*+,-./:;<=>?@[]\\^_`{}|~"})

	addCheckOk(t, &checklist, "flag "+flagSubject+" empty", []option{{flagSubject, ""}}, &Settings{})
	addCheckOk(t, &checklist, "flag "+flagSubject+" regular", []option{{flagSubject, "Subject"}}, &Settings{Subject: "Subject"})
	addCheckOk(t, &checklist, "flag "+flagSubject+" unicode", []option{{flagSubject, "件名"}}, &Settings{Subject: "件名"})
	addCheckOk(t, &checklist, "flag "+flagSubject+" special", []option{{flagSubject, "!\"#$%&'()*+,-./:;<=>?@[]\\^_`{}|~"}}, &Settings{Subject: "!\"#$%&'()*+,-./:;<=>?@[]\\^_`{}|~"})

	addCheckOk(t, &checklist, "flag "+flagHeader+" custom", []option{{flagHeader, "X-Test: testing"}}, &Settings{Headers: types.Headers{"X-Test: testing"}})
	addCheckErr(t, &checklist, "flag "+flagHeader+" empty", []option{{flagHeader, ""}}, &[]error{types.ErrHeaderEmpty})
	addCheckErr(t, &checklist, "flag "+flagHeader+" name empty", []option{{flagHeader, " : testing"}}, &[]error{types.ErrHeaderNameEmpty})
	addCheckErr(t, &checklist, "flag "+flagHeader+" body empty", []option{{flagHeader, "X-Test: "}}, &[]error{types.ErrHeaderBodyEmpty})
	addCheckErr(t, &checklist, "flag "+flagHeader+" no colons", []option{{flagHeader, "X-Test testing"}}, &[]error{types.ErrHeaderNoColon})
	addCheckErr(t, &checklist, "flag "+flagHeader+" 2 colons", []option{{flagHeader, "X-Test: X-Custom: testing"}}, &[]error{types.ErrHeaderMultipleColons})
	addCheckErr(t, &checklist, "flag "+flagHeader+" illegal name", []option{{flagHeader, "X-試験: testing"}}, &[]error{types.ErrHeaderNameIllegalChars})
	addCheckErr(t, &checklist, "flag "+flagHeader+" illegal body", []option{{flagHeader, "X-Test: 試験"}}, &[]error{types.ErrHeaderBodyIllegalChars})
	addCheckOk(t, &checklist, "flag "+flagHeader+" length max", []option{{flagHeader, headerMax}}, &Settings{Headers: types.Headers{types.Header(headerMax)}})
	addCheckErr(t, &checklist, "flag "+flagHeader+" length max+1", []option{{flagHeader, headerMaxPlus1}}, &[]error{types.ErrHeaderLineTooLong})
	addCheckOk(t, &checklist, "flag "+flagHeader+" 2 lines max", []option{{flagHeader, header2LinesMax}}, &Settings{Headers: types.Headers{types.Header(header2LinesMax)}})
	addCheckErr(t, &checklist, "flag "+flagHeader+" 2 lines max+1", []option{{flagHeader, header2LinesMaxPlus1}}, &[]error{types.ErrHeaderLineTooLong})

	addCheckOk(t, &checklist, "flag "+flagBodyText+" empty", []option{{flagBodyText, ""}}, &Settings{})
	addCheckOk(t, &checklist, "flag "+flagBodyText+" text", []option{{flagBodyText, "This is a plain text \nbody."}}, &Settings{BodyText: "This is a plain text \nbody."})

	addCheckOk(t, &checklist, "flag "+flagBodyHtml+" empty", []option{{flagBodyHtml, ""}}, &Settings{})
	addCheckOk(t, &checklist, "flag "+flagBodyHtml+" html", []option{{flagBodyHtml, "<p>This is an HTML body.</p>"}}, &Settings{BodyHtml: "<p>This is an HTML body.</p>"})

	addCheckOk(t, &checklist, "flag "+flagAttachment+" 1 file", []option{{flagAttachment, tmpExistingFileName}}, &Settings{Attachments: types.Attachments{types.FilePath(tmpExistingFileName)}})
	addCheckOk(t, &checklist, "flag "+flagAttachment+" 2 files", []option{{flagAttachment, fmt.Sprintf("%s, %s", tmpExistingFileName, tmpExistingFileName2)}}, &Settings{Attachments: types.Attachments{types.FilePath(tmpExistingFileName), types.FilePath(tmpExistingFileName2)}})
	addCheckErr(t, &checklist, "flag "+flagAttachment+" empty", []option{{flagAttachment, ""}}, &[]error{types.ErrAttachmentInvalid, types.ErrFileEmpty})
	addCheckErr(t, &checklist, "flag "+flagAttachment+" fake", []option{{flagAttachment, tmpNonExistingFileName}}, &[]error{types.ErrAttachmentInvalid, types.ErrFileNotExist})

	addCheckOk(t, &checklist, "flag "+flagHelp+" help", []option{{flagHelp, ""}}, nil)
	addCheckOk(t, &checklist, "flag "+flagVersion+" help", []option{{flagVersion, ""}}, nil)

	addSettingsCheckOk(t, &checklist, "setting "+flagSmtpHost+" normal", flagServerFile, []option{{flagSmtpHost, "domain.com"}}, []option{}, &Settings{SmtpHost: "domain.com"})
	addSettingsCheckOk(t, &checklist, "setting "+flagSmtpHost+" non-tld", flagServerFile, []option{{flagSmtpHost, "domain"}}, []option{}, &Settings{SmtpHost: "domain"})
	addSettingsCheckOk(t, &checklist, "setting "+flagSmtpHost+" empty", flagServerFile, []option{{flagSmtpHost, ""}}, []option{}, &Settings{})
	addSettingsCheckOk(t, &checklist, "setting "+flagSmtpHost+" double quoted", flagServerFile, []option{{flagSmtpHost, `"domain.com"`}}, []option{}, &Settings{SmtpHost: "domain.com"})
	addSettingsCheckErr(t, &checklist, "setting "+flagSmtpHost+" directory", flagServerFile, []option{{flagSmtpHost, "domain.com/dir"}}, []option{}, &[]error{types.ErrDomainInvalid})
	addSettingsCheckOk(t, &checklist, "setting "+flagSmtpHost+" overrule", flagServerFile, []option{{flagSmtpHost, "notthis.com"}}, []option{{flagSmtpHost, "domain.com"}}, &Settings{SmtpHost: "domain.com"})

	addSettingsCheckOk(t, &checklist, "setting "+flagSmtpPort+" regular", flagServerFile, []option{{flagSmtpPort, "587"}}, []option{}, &Settings{SmtpPort: 587})
	addSettingsCheckOk(t, &checklist, "setting "+flagSmtpPort+" empty", flagServerFile, []option{{flagSmtpPort, ""}}, []option{}, &Settings{})
	addSettingsCheckErr(t, &checklist, "setting "+flagSmtpPort+" negative", flagServerFile, []option{{flagSmtpPort, "-1"}}, []option{}, &[]error{types.ErrPortNegative})
	addSettingsCheckErr(t, &checklist, "setting "+flagSmtpPort+" out of range", flagServerFile, []option{{flagSmtpPort, "65536"}}, []option{}, &[]error{types.ErrPortOutOfRange})
	addSettingsCheckOk(t, &checklist, "setting "+flagSmtpPort+" overrule", flagServerFile, []option{{flagSmtpPort, "999"}}, []option{{flagSmtpPort, "587"}}, &Settings{SmtpPort: 587})

	addSettingsCheckOk(t, &checklist, "setting "+flagRootCA+" existing", flagServerFile, []option{{flagRootCA, tmpExistingFileName}}, []option{}, &Settings{RootCA: types.FilePath(tmpExistingFileName)})
	addSettingsCheckOk(t, &checklist, "setting "+flagRootCA+" empty", flagServerFile, []option{{flagRootCA, ""}}, []option{}, &Settings{})
	addSettingsCheckErr(t, &checklist, "setting "+flagRootCA+" non-existing", flagServerFile, []option{{flagRootCA, tmpNonExistingFileName}}, []option{}, &[]error{types.ErrFileNotExist})
	addSettingsCheckOk(t, &checklist, "setting "+flagRootCA+" overrule", flagServerFile, []option{{flagRootCA, tmpExistingFileName2}}, []option{{flagRootCA, tmpExistingFileName}}, &Settings{RootCA: types.FilePath(tmpExistingFileName)})

	addSettingsCheckOk(t, &checklist, "setting "+flagSecurity+" none", flagServerFile, []option{{flagSecurity, string(types.NoSecurity)}}, []option{}, &Settings{Security: types.NoSecurity})
	addSettingsCheckOk(t, &checklist, "setting "+flagSecurity+" StartTLS", flagServerFile, []option{{flagSecurity, string(types.StartTlsSec)}}, []option{}, &Settings{Security: types.StartTlsSec})
	addSettingsCheckOk(t, &checklist, "setting "+flagSecurity+" SSLTLS", flagServerFile, []option{{flagSecurity, string(types.SslTlsSec)}}, []option{}, &Settings{Security: types.SslTlsSec})
	addSettingsCheckErr(t, &checklist, "setting "+flagSecurity+" invalid", flagServerFile, []option{{flagSecurity, "INVALID"}}, []option{}, &[]error{types.ErrSecurityInvalid})
	addSettingsCheckOk(t, &checklist, "setting "+flagSecurity+" overrule", flagServerFile, []option{{flagSecurity, string(types.SslTlsSec)}}, []option{{flagSecurity, string(types.StartTlsSec)}}, &Settings{Security: types.StartTlsSec})

	addSettingsCheckOk(t, &checklist, "setting "+flagAuthMethod+" none", flagServerFile, []option{{flagAuthMethod, string(types.NoAuthentication)}}, []option{}, &Settings{Authentication: types.NoAuthentication})
	addSettingsCheckOk(t, &checklist, "setting "+flagAuthMethod+" plain", flagServerFile, []option{{flagAuthMethod, string(types.PlainAuth)}}, []option{}, &Settings{Authentication: types.PlainAuth})
	addSettingsCheckOk(t, &checklist, "setting "+flagAuthMethod+" crammd5", flagServerFile, []option{{flagAuthMethod, string(types.CramMd5Auth)}}, []option{}, &Settings{Authentication: types.CramMd5Auth})
	addSettingsCheckErr(t, &checklist, "setting "+flagAuthMethod+" invalid", flagServerFile, []option{{flagAuthMethod, "INVALID"}}, []option{}, &[]error{types.ErrAuthenticationInvalid})
	addSettingsCheckOk(t, &checklist, "setting "+flagAuthMethod+" plain", flagServerFile, []option{{flagAuthMethod, string(types.CramMd5Auth)}}, []option{{flagAuthMethod, string(types.PlainAuth)}}, &Settings{Authentication: types.PlainAuth})

	addSettingsCheckOk(t, &checklist, "setting "+flagLogin+" empty", flagServerFile, []option{{flagLogin, ""}}, []option{}, &Settings{})
	addSettingsCheckOk(t, &checklist, "setting "+flagLogin+" regular", flagServerFile, []option{{flagLogin, "My Name"}}, []option{}, &Settings{Login: "My Name"})
	addSettingsCheckOk(t, &checklist, "setting "+flagLogin+" unicode", flagServerFile, []option{{flagLogin, "私の名前"}}, []option{}, &Settings{Login: "私の名前"})
	addSettingsCheckOk(t, &checklist, "setting "+flagLogin+" email", flagServerFile, []option{{flagLogin, "user@example.com"}}, []option{}, &Settings{Login: "user@example.com"})
	addSettingsCheckOk(t, &checklist, "setting "+flagLogin+" overrule", flagServerFile, []option{{flagLogin, "Not shown Name"}}, []option{{flagLogin, "My Name"}}, &Settings{Login: "My Name"})

	addSettingsCheckOk(t, &checklist, "setting "+flagPassword+" empty", flagServerFile, []option{{flagPassword, ""}}, []option{}, &Settings{})
	addSettingsCheckOk(t, &checklist, "setting "+flagPassword+" regular", flagServerFile, []option{{flagPassword, "MySecret"}}, []option{}, &Settings{Password: "MySecret"})
	addSettingsCheckOk(t, &checklist, "setting "+flagPassword+" unicode", flagServerFile, []option{{flagPassword, "秘密のパスワード"}}, []option{}, &Settings{Password: "秘密のパスワード"})
	addSettingsCheckOk(t, &checklist, "setting "+flagPassword+" special", flagServerFile, []option{{flagPassword, "!\"#$%&'()*+,-./:;<=>?@[]\\^_`{}|~"}}, []option{}, &Settings{Password: "!\"#$%&'()*+,-./:;<=>?@[]\\^_`{}|~"})
	addSettingsCheckOk(t, &checklist, "setting "+flagPassword+" overrule", flagServerFile, []option{{flagPassword, "NotShownSecret"}}, []option{{flagPassword, "MySecret"}}, &Settings{Password: "MySecret"})

	addSettingsCheckOk(t, &checklist, "setting "+flagSender+" email", flagServerFile, []option{{flagSender, "sender@example.com"}}, []option{}, &Settings{Sender: types.Email{Name: "", Address: "sender@example.com"}})
	addSettingsCheckOk(t, &checklist, "setting "+flagSender+" name", flagServerFile, []option{{flagSender, "Sender<sender@example.com>"}}, []option{}, &Settings{Sender: types.Email{Name: "Sender", Address: "sender@example.com"}})
	addSettingsCheckOk(t, &checklist, "setting "+flagSender+" empty", flagServerFile, []option{{flagSender, ""}}, []option{}, &Settings{})
	addSettingsCheckErr(t, &checklist, "setting "+flagSender+" no at", flagServerFile, []option{{flagSender, "sender"}}, []option{}, &[]error{types.ErrEmailInvalid})
	addSettingsCheckErr(t, &checklist, "setting "+flagSender+" no domain", flagServerFile, []option{{flagSender, "sender@"}}, []option{}, &[]error{types.ErrEmailInvalid})
	addSettingsCheckOk(t, &checklist, "setting "+flagSender+" overrule", flagServerFile, []option{{flagSender, "Sender<sender@example.com>"}}, []option{{flagSender, "sender@example.com"}}, &Settings{Sender: types.Email{Name: "", Address: "sender@example.com"}})

	addSettingsCheckErr(t, &checklist, "not allowed setting "+flagReplyTo, flagServerFile, []option{{flagReplyTo, "replyto@example.com"}}, []option{}, &[]error{ErrIllegalFlagOption})
	addSettingsCheckErr(t, &checklist, "not allowed setting "+flagTo, flagServerFile, []option{{flagTo, "To1<to1@example.com>,To2<to2@example.com>"}}, []option{}, &[]error{ErrIllegalFlagOption})
	addSettingsCheckErr(t, &checklist, "not allowed setting "+flagCc, flagServerFile, []option{{flagCc, "Cc1<cc1@example.com>,Cc2<cc2@example.com>"}}, []option{}, &[]error{ErrIllegalFlagOption})
	addSettingsCheckErr(t, &checklist, "not allowed setting "+flagBcc, flagServerFile, []option{{flagBcc, "Bcc1<bcc1@example.com>,Bcc2<bcc2@example.com>"}}, []option{}, &[]error{ErrIllegalFlagOption})
	addSettingsCheckErr(t, &checklist, "not allowed setting "+flagMessageId, flagServerFile, []option{{flagMessageId, "ID-1234567890"}}, []option{}, &[]error{ErrIllegalFlagOption})
	addSettingsCheckErr(t, &checklist, "not allowed setting "+flagSubject, flagServerFile, []option{{flagSubject, "Subject"}}, []option{}, &[]error{ErrIllegalFlagOption})
	addSettingsCheckErr(t, &checklist, "not allowed setting "+flagHeader, flagServerFile, []option{{flagHeader, "X-Test: testing"}}, []option{}, &[]error{ErrIllegalFlagOption})
	addSettingsCheckErr(t, &checklist, "not allowed setting "+flagBodyText, flagServerFile, []option{{flagBodyText, "This is a plain text \nbody."}}, []option{}, &[]error{ErrIllegalFlagOption})
	addSettingsCheckErr(t, &checklist, "not allowed setting "+flagBodyHtml, flagServerFile, []option{{flagBodyHtml, "<p>This is an HTML body.</p>"}}, []option{}, &[]error{ErrIllegalFlagOption})
	addSettingsCheckErr(t, &checklist, "not allowed setting "+flagAttachment, flagServerFile, []option{{flagAttachment, fmt.Sprintf("%s, %s", tmpExistingFileName, tmpExistingFileName2)}}, []option{}, &[]error{ErrIllegalFlagOption})
	addSettingsCheckErr(t, &checklist, "not allowed setting "+flagHelp, flagServerFile, []option{{flagHelp, ""}}, []option{}, &[]error{ErrIllegalFlagOption})

	for _, opt := range checklist {
		t.Run(opt.name, func(t *testing.T) {
			if opt.fileName != "" {
				defer os.Remove(opt.fileName)
			}

			os.Args = opt.arguments
			settings, err := GetSettings(io.Discard, "test")

			if opt.expectedErrors == nil || len(*opt.expectedErrors) == 0 {
				if err != nil {
					t.Fatalf("Expected no error, got %s", err)
				}
			} else {
				if err == nil {
					if len(*opt.expectedErrors) == 1 {
						t.Fatalf("Expected error %s, but got no error", (*opt.expectedErrors)[0])
					} else {
						t.Fatalf("Expected errors %s, but got no error", errors.Join(*opt.expectedErrors...))
					}
				} else {

					for _, e := range *opt.expectedErrors {
						// Cannot use 'errors.Is' because flag package does not wrap errors (as for go1.23.2)
						if !strings.Contains(err.Error(), e.Error()) {
							t.Errorf("Expected error %s, got %s", e, err.Error())
						}
					}
					return
				}
			}

			if !reflect.DeepEqual(settings, opt.expectedSettings) {
				t.Errorf("Expected %v, got %v", opt.expectedSettings, settings)
			}
		})
	}
}

func addCheckOk(t testing.TB, checklist *[]check, name string, options []option, settings *Settings) {
	t.Helper()
	addCheck(checklist, name, options, settings, nil, "")
}

func addCheckErr(t testing.TB, checklist *[]check, name string, options []option, expectedErrors *[]error) {
	t.Helper()
	addCheck(checklist, name, options, nil, expectedErrors, "")
}

func addSettingsCheckOk(t testing.TB, checklist *[]check, name, settingsFlag string, settingsOptions []option, flagOptions []option, settings *Settings) {
	t.Helper()
	if err := addSettingsCheck(checklist, name, settingsFlag, settingsOptions, flagOptions, settings, nil); err != nil {
		t.Fatal(err)
	}
}

func addSettingsCheckErr(t testing.TB, checklist *[]check, name, settingsFlag string, settingsOptions []option, flagOptions []option, expectedErrors *[]error) {
	t.Helper()
	if err := addSettingsCheck(checklist, name, settingsFlag, settingsOptions, flagOptions, nil, expectedErrors); err != nil {
		t.Fatal(err)
	}
}

func addSettingsCheck(checklist *[]check, name, settingsFlag string, settingsOptions []option, flagOptions []option, settings *Settings, expectedErrors *[]error) error {
	for sf := settingsFormat(0); sf < settingsFormat(4); sf++ {
		namepart := name
		switch sf {
		case NoSpacesAndNoQuotes:
		case NoSpacesAndQuotes:
			namepart += " Q"
		case SpacesAndNoQuotes:
			namepart += " SP"
		case SpacesAndQuotes:
			namepart += " SP Q"
		}

		fileName, err := createSettingsFile(namepart, settingsOptions, sf)
		if err != nil {
			return err
		}

		flags := flagOptions
		flags = append(flags, option{settingsFlag, fileName})
		addCheck(checklist, namepart, flags, settings, expectedErrors, fileName)
	}
	return nil
}

func addCheck(checklist *[]check, name string, options []option, settings *Settings, expectedErrors *[]error, fileName string) {
	*checklist = append(*checklist, check{
		name:             name,
		arguments:        getArguments(options),
		expectedSettings: settings,
		expectedErrors:   expectedErrors,
		fileName:         fileName,
	})
}

func getArguments(options []option) []string {
	args := make([]string, 0, (2*len(options))+1)
	args = append(args, "gosend")
	for _, opt := range options {
		args = append(args, "-"+opt.name, opt.value)
	}
	return args
}

func createSettingsFile(name string, options []option, format settingsFormat) (string, error) {
	tmpFile, err := os.CreateTemp(os.TempDir(), strings.ReplaceAll(name, " ", "_"))
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()
	fileName := tmpFile.Name()

	for _, opt := range options {
		var text string
		switch format {
		case NoSpacesAndNoQuotes:
			text = fmt.Sprintf("%s=%s", opt.name, opt.value)
		case NoSpacesAndQuotes:
			text = fmt.Sprintf("%s=\"%s\"", opt.name, opt.value)
		case SpacesAndNoQuotes:
			text = fmt.Sprintf("%s = %s", opt.name, opt.value)
		case SpacesAndQuotes:
			text = fmt.Sprintf("%s = \"%s\"", opt.name, opt.value)
		}
		if _, err := fmt.Fprintln(tmpFile, text); err != nil {
			return "", err
		}
	}
	return fileName, nil
}
