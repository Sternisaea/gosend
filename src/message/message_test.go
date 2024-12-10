package message

import (
	"context"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Sternisaea/dnsservermock/src/dnsconst"
	"github.com/Sternisaea/dnsservermock/src/dnsservermock"
	"github.com/Sternisaea/dnsservermock/src/dnsstorage/dnsstoragememory"
	"github.com/Sternisaea/gosend/src/certificates"
	"github.com/Sternisaea/gosend/src/cmdflags"
	"github.com/Sternisaea/gosend/src/secureconnection"
	"github.com/Sternisaea/gosend/src/types"
	"github.com/Sternisaea/smtpservermock/src/smtpservermock"
)

var (
	MaxLineLength = 78
	dnsIP         = "127.0.0.1"
	dnsPort       = types.TCPPort(5355)
	smtpPort      = types.TCPPort(40975)
)

type check struct {
	name            string
	message         *Message
	expectedErrors  *[]error
	expectedMessage *smtpservermock.Message
}

type attach struct {
	filePath    string
	contentType string
}

var (
	ErrNoRecipients = errors.New("no recipients provided")
	ErrNoSender     = errors.New("no sender provided")
)

func Test_Message(t *testing.T) {

	cancelDns, err := startDns(net.ParseIP(dnsIP), int(dnsPort))
	if err != nil {
		t.Fatalf("Cannot start DNS server: %s", err)
	}
	defer cancelDns()

	setDefaultResolver(fmt.Sprintf("%s:%d", dnsIP, dnsPort))

	validCert, validKey, err := certificates.CreateCertificate("Domain Local", "mail.domain.local")
	if err != nil {
		t.Fatalf("Error creating certificate: %s", err)
	}
	defer os.Remove(validKey)
	defer os.Remove(validCert)

	mockSmtp, err := smtpservermock.NewSmtpServer(
		smtpservermock.NoSecurity,
		"Mock SMTP Server",
		getAddress("localhost", smtpPort),
		"",
		"")
	if err != nil {
		t.Fatalf("Cannot initialise SMTP server: %s", err)
	}
	if err := mockSmtp.ListenAndServe(); err != nil {
		t.Fatalf("Cannot start SMTP server: %s", err)
	}
	defer mockSmtp.Shutdown()

	imgFilePath1, err := createImageFile(0, 10)
	if err != nil {
		t.Fatalf("Error creating image file: %s", err)
	}
	defer os.Remove(imgFilePath1)
	imgFileName1 := filepath.Base(imgFilePath1)

	imgFilePath2, err := createImageFile(50, 10)
	if err != nil {
		t.Fatalf("Error creating image file: %s", err)
	}
	defer os.Remove(imgFilePath2)
	imgFileName2 := filepath.Base(imgFilePath2)

	checklist := make([]check, 0, 100)
	addCheck(t, &checklist, "To",
		mail.Address{Name: "Me", Address: "me@domain.local"},
		[]mail.Address{{Name: "You 1", Address: "you1@domain.local"}, {Name: "You 2", Address: "you2@domain.local"}},
		[]mail.Address{},
		[]mail.Address{},
		[]mail.Address{},
		"",
		"Subject To",
		"Plain text.",
		"",
		[]string{},
		[]attach{},
		nil,
		&smtpservermock.Message{
			From: "me@domain.local",
			To:   []string{"you1@domain.local", "you2@domain.local"},
			Data: "From: \"Me\" <me@domain.local>\r\n" +
				"To: \"You 1\" <you1@domain.local>,\"You 2\" <you2@domain.local>\r\n" +
				"Subject: Subject To\r\n" +
				"MIME-Version: 1.0\r\n" +
				"contentType: Content-Type: text/plain; charset=\"UTF-8\"\r\n" +
				"Content-Transfer-Encoding: 7bit\r\n" +
				"\r\n" +
				"Plain text.\r\n" +
				"\r\n",
		},
	)
	addCheck(t, &checklist, "CC",
		mail.Address{Name: "Me", Address: "me@domain.local"},
		[]mail.Address{{Name: "You 1", Address: "you1@domain.local"}, {Name: "You 2", Address: "you2@domain.local"}},
		[]mail.Address{{Name: "Too 1", Address: "too1@domain.local"}, {Name: "Too 2", Address: "too2@domain.local"}},
		[]mail.Address{},
		[]mail.Address{},
		"",
		"Subject CC",
		"Plain text.",
		"",
		[]string{},
		[]attach{},
		nil,
		&smtpservermock.Message{
			From: "me@domain.local",
			To:   []string{"you1@domain.local", "you2@domain.local", "too1@domain.local", "too2@domain.local"},
			Data: "From: \"Me\" <me@domain.local>\r\n" +
				"To: \"You 1\" <you1@domain.local>,\"You 2\" <you2@domain.local>\r\n" +
				"Cc: \"Too 1\" <too1@domain.local>,\"Too 2\" <too2@domain.local>\r\n" +
				"Subject: Subject CC\r\n" +
				"MIME-Version: 1.0\r\n" +
				"contentType: Content-Type: text/plain; charset=\"UTF-8\"\r\n" +
				"Content-Transfer-Encoding: 7bit\r\n" +
				"\r\n" +
				"Plain text.\r\n" +
				"\r\n",
		},
	)
	addCheck(t, &checklist, "BCC",
		mail.Address{Name: "Me", Address: "me@domain.local"},
		[]mail.Address{{Name: "You 1", Address: "you1@domain.local"}, {Name: "You 2", Address: "you2@domain.local"}},
		[]mail.Address{{Name: "Too 1", Address: "too1@domain.local"}, {Name: "Too 2", Address: "too2@domain.local"}},
		[]mail.Address{{Name: "Secretly 1", Address: "secretly1@domain.local"}, {Name: "Secretly 2", Address: "secretly2@domain.local"}},
		[]mail.Address{},
		"",
		"Subject BCC",
		"Plain text.",
		"",
		[]string{},
		[]attach{},
		nil,
		&smtpservermock.Message{
			From: "me@domain.local",
			To:   []string{"you1@domain.local", "you2@domain.local", "too1@domain.local", "too2@domain.local", "secretly1@domain.local", "secretly2@domain.local"},
			Data: "From: \"Me\" <me@domain.local>\r\n" +
				"To: \"You 1\" <you1@domain.local>,\"You 2\" <you2@domain.local>\r\n" +
				"Cc: \"Too 1\" <too1@domain.local>,\"Too 2\" <too2@domain.local>\r\n" +
				"Subject: Subject BCC\r\n" +
				"MIME-Version: 1.0\r\n" +
				"contentType: Content-Type: text/plain; charset=\"UTF-8\"\r\n" +
				"Content-Transfer-Encoding: 7bit\r\n" +
				"\r\n" +
				"Plain text.\r\n" +
				"\r\n",
		},
	)
	addCheck(t, &checklist, "Reply To",
		mail.Address{Name: "Me", Address: "me@domain.local"},
		[]mail.Address{{Name: "You 1", Address: "you1@domain.local"}, {Name: "You 2", Address: "you2@domain.local"}},
		[]mail.Address{{Name: "Too 1", Address: "too1@domain.local"}, {Name: "Too 2", Address: "too2@domain.local"}},
		[]mail.Address{{Name: "Secretly 1", Address: "secretly1@domain.local"}, {Name: "Secretly 2", Address: "secretly2@domain.local"}},
		[]mail.Address{{Name: "Answer 1", Address: "answer1@domain.local"}, {Name: "Answer 2", Address: "answer2@domain.local"}},
		"",
		"Subject Reply To",
		"Plain text.",
		"",
		[]string{},
		[]attach{},
		nil,
		&smtpservermock.Message{
			From: "me@domain.local",
			To:   []string{"you1@domain.local", "you2@domain.local", "too1@domain.local", "too2@domain.local", "secretly1@domain.local", "secretly2@domain.local"},
			Data: "From: \"Me\" <me@domain.local>\r\n" +
				"To: \"You 1\" <you1@domain.local>,\"You 2\" <you2@domain.local>\r\n" +
				"Cc: \"Too 1\" <too1@domain.local>,\"Too 2\" <too2@domain.local>\r\n" +
				"Subject: Subject Reply To\r\n" +
				"Reply-To: \"Answer 1\" <answer1@domain.local>,\"Answer 2\" <answer2@domain.local>\r\n" +
				"MIME-Version: 1.0\r\n" +
				"contentType: Content-Type: text/plain; charset=\"UTF-8\"\r\n" +
				"Content-Transfer-Encoding: 7bit\r\n" +
				"\r\n" +
				"Plain text.\r\n" +
				"\r\n",
		},
	)
	addCheck(t, &checklist, "Message ID",
		mail.Address{Name: "Me", Address: "me@domain.local"},
		[]mail.Address{{Name: "You 1", Address: "you1@domain.local"}, {Name: "You 2", Address: "you2@domain.local"}},
		[]mail.Address{},
		[]mail.Address{},
		[]mail.Address{},
		"Identification123",
		"Subject To",
		"Plain text.",
		"",
		[]string{},
		[]attach{},
		nil,
		&smtpservermock.Message{
			From: "me@domain.local",
			To:   []string{"you1@domain.local", "you2@domain.local"},
			Data: "From: \"Me\" <me@domain.local>\r\n" +
				"To: \"You 1\" <you1@domain.local>,\"You 2\" <you2@domain.local>\r\n" +
				"Subject: Subject To\r\n" +
				"Message-ID: Identification123\r\n" +
				"MIME-Version: 1.0\r\n" +
				"contentType: Content-Type: text/plain; charset=\"UTF-8\"\r\n" +
				"Content-Transfer-Encoding: 7bit\r\n" +
				"\r\n" +
				"Plain text.\r\n" +
				"\r\n",
		},
	)
	addCheck(t, &checklist, "Headers",
		mail.Address{Name: "Me", Address: "me@domain.local"},
		[]mail.Address{{Name: "You 1", Address: "you1@domain.local"}, {Name: "You 2", Address: "you2@domain.local"}},
		[]mail.Address{},
		[]mail.Address{},
		[]mail.Address{},
		"",
		"Subject To",
		"Plain text.",
		"",
		[]string{"X-Privacy: Private", "X-Test: Not important"},
		[]attach{},
		nil,
		&smtpservermock.Message{
			From: "me@domain.local",
			To:   []string{"you1@domain.local", "you2@domain.local"},
			Data: "From: \"Me\" <me@domain.local>\r\n" +
				"To: \"You 1\" <you1@domain.local>,\"You 2\" <you2@domain.local>\r\n" +
				"Subject: Subject To\r\n" +
				"MIME-Version: 1.0\r\n" +
				"X-Privacy: Private\r\n" +
				"X-Test: Not important\r\n" +
				"contentType: Content-Type: text/plain; charset=\"UTF-8\"\r\n" +
				"Content-Transfer-Encoding: 7bit\r\n" +
				"\r\n" +
				"Plain text.\r\n" +
				"\r\n",
		},
	)
	addCheck(t, &checklist, "Plain Text",
		mail.Address{Name: "Me", Address: "me@domain.local"},
		[]mail.Address{{Name: "You", Address: "you@domain.local"}},
		[]mail.Address{},
		[]mail.Address{},
		[]mail.Address{},
		"",
		"Subject Plain Text",
		"Plain text.",
		"",
		[]string{},
		[]attach{},
		nil,
		&smtpservermock.Message{
			From: "me@domain.local",
			To:   []string{"you@domain.local"},
			Data: "From: \"Me\" <me@domain.local>\r\n" +
				"To: \"You\" <you@domain.local>\r\n" +
				"Subject: Subject Plain Text\r\n" +
				"MIME-Version: 1.0\r\n" +
				"contentType: Content-Type: text/plain; charset=\"UTF-8\"\r\n" +
				"Content-Transfer-Encoding: 7bit\r\n" +
				"\r\n" +
				"Plain text.\r\n" +
				"\r\n",
		},
	)
	addCheck(t, &checklist, "HTML Text",
		mail.Address{Name: "Me", Address: "me@domain.local"},
		[]mail.Address{{Name: "You", Address: "you@domain.local"}},
		[]mail.Address{},
		[]mail.Address{},
		[]mail.Address{},
		"",
		"Subject HMTL Text",
		"",
		"<h1>Title</h1>\r\n<p>HTML text</p>",
		[]string{},
		[]attach{},
		nil,
		&smtpservermock.Message{
			From: "me@domain.local",
			To:   []string{"you@domain.local"},
			Data: "From: \"Me\" <me@domain.local>\r\n" +
				"To: \"You\" <you@domain.local>\r\n" +
				"Subject: Subject HMTL Text\r\n" +
				"MIME-Version: 1.0\r\n" +
				"Content-Type: text/html; charset=\"UTF-8\"\r\n" +
				"Content-Transfer-Encoding: 7bit\r\n" +
				"\r\n" +
				"<h1>Title</h1>\r\n<p>HTML text</p>\r\n" +
				"\r\n",
		},
	)
	addCheck(t, &checklist, "HTML and Plain Text",
		mail.Address{Name: "Me", Address: "me@domain.local"},
		[]mail.Address{{Name: "You", Address: "you@domain.local"}},
		[]mail.Address{},
		[]mail.Address{},
		[]mail.Address{},
		"",
		"Subject HMTL & Plain Text",
		"Plain text.",
		"<h1>Title</h1>\r\n<p>HTML text</p>",
		[]string{},
		[]attach{},
		nil,
		&smtpservermock.Message{
			From: "me@domain.local",
			To:   []string{"you@domain.local"},
			Data: "From: \"Me\" <me@domain.local>\r\n" +
				"To: \"You\" <you@domain.local>\r\n" +
				"Subject: Subject HMTL & Plain Text\r\n" +
				"MIME-Version: 1.0\r\n" +
				"Content-Type: multipart/alternative; boundary=\"BOUNDARY_ID_00000001\"\r\n" +
				"\r\n" +
				"--BOUNDARY_ID_00000001\r\n" +
				"contentType: Content-Type: text/plain; charset=\"UTF-8\"\r\n" +
				"Content-Transfer-Encoding: 7bit\r\n" +
				"\r\n" +
				"Plain text.\r\n" +
				"\r\n" +
				"--BOUNDARY_ID_00000001\r\n" +
				"Content-Type: text/html; charset=\"UTF-8\"\r\n" +
				"Content-Transfer-Encoding: 7bit\r\n" +
				"\r\n" +
				"<h1>Title</h1>\r\n<p>HTML text</p>\r\n" +
				"\r\n" +
				"--BOUNDARY_ID_00000001--\r\n",
		},
	)
	addCheck(t, &checklist, "Attachments",
		mail.Address{Name: "Me", Address: "me@domain.local"},
		[]mail.Address{{Name: "You", Address: "you@domain.local"}},
		[]mail.Address{},
		[]mail.Address{},
		[]mail.Address{},
		"",
		"Subject Attachments",
		"Plain text.",
		"<h1>Title</h1>\r\n<p>HTML text</p>",
		[]string{},
		[]attach{{filePath: imgFilePath1}, {filePath: imgFilePath2, contentType: "image/png"}},
		nil,
		&smtpservermock.Message{
			From: "me@domain.local",
			To:   []string{"you@domain.local"},
			Data: "From: \"Me\" <me@domain.local>\r\n" +
				"To: \"You\" <you@domain.local>\r\n" +
				"Subject: Subject Attachments\r\n" +
				"MIME-Version: 1.0\r\n" +
				"Content-Type: multipart/mixed; boundary=\"BOUNDARY_ID_00000002\"\r\n" +
				"\r\n" +
				"--BOUNDARY_ID_00000002\r\n" +
				"Content-Type: multipart/alternative; boundary=\"BOUNDARY_ID_00000001\"\r\n" +
				"\r\n" +
				"--BOUNDARY_ID_00000001\r\n" +
				"contentType: Content-Type: text/plain; charset=\"UTF-8\"\r\n" +
				"Content-Transfer-Encoding: 7bit\r\n" +
				"\r\n" +
				"Plain text.\r\n" +
				"\r\n" +
				"--BOUNDARY_ID_00000001\r\n" +
				"Content-Type: text/html; charset=\"UTF-8\"\r\n" +
				"Content-Transfer-Encoding: 7bit\r\n" +
				"\r\n" +
				"<h1>Title</h1>\r\n<p>HTML text</p>\r\n" +
				"\r\n" +
				"--BOUNDARY_ID_00000001--\r\n" +
				"--BOUNDARY_ID_00000002\r\n" +
				"Content-Type: image/png; name=\"" + imgFileName1 + "\"\r\n" +
				"Content-Transfer-Encoding: base64\r\n" +
				"Content-Disposition: attachment; filename=\"" + imgFileName1 + "\"\r\n" +
				"Content-ID: ATTACHMENT_ID_00000000000000000000000000000000000001\r\n" +
				"\r\n" +
				"iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAIAAAAC64paAAAAJElEQVR4nGJhYDjBxcBAHmIBEeSCUc2jmkc1j2qmXDMgAAD//7nxApWuSReTAAAAAElFTkSuQmCC\r\n" +
				"\r\n" +
				"--BOUNDARY_ID_00000002\r\n" +
				"Content-Type: image/png; name=\"" + imgFileName2 + "\"\r\n" +
				"Content-Transfer-Encoding: base64\r\n" +
				"Content-Disposition: attachment; filename=\"" + imgFileName2 + "\"\r\n" +
				"Content-ID: ATTACHMENT_ID_00000000000000000000000000000000000002\r\n" +
				"\r\n" +
				"iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAIAAAAC64paAAAAJElEQVR4nGIxMjrBxcBAHmIBEeSCUc2jmkc1j2qmXDMgAAD//5YJAvns+K/iAAAAAElFTkSuQmCC\r\n" +
				"\r\n" +
				"--BOUNDARY_ID_00000002--\r\n",
		},
	)
	addCheck(t, &checklist, "Attachments Embedded",
		mail.Address{Name: "Me", Address: "me@domain.local"},
		[]mail.Address{{Name: "You", Address: "you@domain.local"}},
		[]mail.Address{},
		[]mail.Address{},
		[]mail.Address{},
		"",
		"Subject Attachments Embedded",
		"Plain text.",
		"<h1>Title</h1>\r\n<p>HTML text\r\n<img src=\""+imgFilePath1+"\" alt=\"Image1\">\r\n<img src=\""+imgFileName2+"\" alt=\"Image2\">\r\n</p>",
		[]string{},
		[]attach{{filePath: imgFilePath1}, {filePath: imgFilePath2, contentType: "image/png"}},
		nil,
		&smtpservermock.Message{
			From: "me@domain.local",
			To:   []string{"you@domain.local"},
			Data: "From: \"Me\" <me@domain.local>\r\n" +
				"To: \"You\" <you@domain.local>\r\n" +
				"Subject: Subject Attachments Embedded\r\n" +
				"MIME-Version: 1.0\r\n" +
				"Content-Type: multipart/mixed; boundary=\"BOUNDARY_ID_00000002\"\r\n" +
				"\r\n" +
				"--BOUNDARY_ID_00000002\r\n" +
				"Content-Type: multipart/alternative; boundary=\"BOUNDARY_ID_00000001\"\r\n" +
				"\r\n" +
				"--BOUNDARY_ID_00000001\r\n" +
				"contentType: Content-Type: text/plain; charset=\"UTF-8\"\r\n" +
				"Content-Transfer-Encoding: 7bit\r\n" +
				"\r\n" +
				"Plain text.\r\n" +
				"\r\n" +
				"--BOUNDARY_ID_00000001\r\n" +
				"Content-Type: text/html; charset=\"UTF-8\"\r\n" +
				"Content-Transfer-Encoding: 7bit\r\n" +
				"\r\n" +
				"<h1>Title</h1>\r\n" +
				"<p>HTML text\r\n" +
				"<img src=\"cid:ATTACHMENT_ID_00000000000000000000000000000000000001\" alt=\"Image1\">\r\n" +
				"<img src=\"cid:ATTACHMENT_ID_00000000000000000000000000000000000002\" alt=\"Image2\">\r\n" +
				"</p>\r\n" +
				"\r\n" +
				"--BOUNDARY_ID_00000001--\r\n" +
				"--BOUNDARY_ID_00000002\r\n" +
				"Content-Type: image/png; name=\"" + imgFileName1 + "\"\r\n" +
				"Content-Transfer-Encoding: base64\r\n" +
				"Content-Disposition: attachment; filename=\"" + imgFileName1 + "\"\r\n" +
				"Content-ID: ATTACHMENT_ID_00000000000000000000000000000000000001\r\n" +
				"\r\n" +
				"iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAIAAAAC64paAAAAJElEQVR4nGJhYDjBxcBAHmIBEeSCUc2jmkc1j2qmXDMgAAD//7nxApWuSReTAAAAAElFTkSuQmCC\r\n" +
				"\r\n" +
				"--BOUNDARY_ID_00000002\r\n" +
				"Content-Type: image/png; name=\"" + imgFileName2 + "\"\r\n" +
				"Content-Transfer-Encoding: base64\r\n" +
				"Content-Disposition: attachment; filename=\"" + imgFileName2 + "\"\r\n" +
				"Content-ID: ATTACHMENT_ID_00000000000000000000000000000000000002\r\n" +
				"\r\n" +
				"iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAIAAAAC64paAAAAJElEQVR4nGIxMjrBxcBAHmIBEeSCUc2jmkc1j2qmXDMgAAD//5YJAvns+K/iAAAAAElFTkSuQmCC\r\n" +
				"\r\n" +
				"--BOUNDARY_ID_00000002--\r\n",
		},
	)

	addCheck(t, &checklist, "From without To",
		mail.Address{Name: "Me", Address: "me@domain.local"},
		[]mail.Address{},
		[]mail.Address{},
		[]mail.Address{},
		[]mail.Address{},
		"",
		"Subject From",
		"Plain text.",
		"",
		[]string{},
		[]attach{},
		&[]error{ErrNoRecipients},
		&smtpservermock.Message{},
	)
	addCheck(t, &checklist, "To without From",
		mail.Address{},
		[]mail.Address{{Name: "You", Address: "you@domain.local"}},
		[]mail.Address{},
		[]mail.Address{},
		[]mail.Address{},
		"",
		"Subject To",
		"Plain text.",
		"",
		[]string{},
		[]attach{},
		&[]error{ErrNoSender},
		&smtpservermock.Message{},
	)
	addCheck(t, &checklist, "BCC without To",
		mail.Address{Name: "Me", Address: "me@domain.local"},
		[]mail.Address{},
		[]mail.Address{},
		[]mail.Address{{Name: "Secretly 1", Address: "secretly1@domain.local"}, {Name: "Secretly 2", Address: "secretly2@domain.local"}},
		[]mail.Address{},
		"",
		"Subject BCC",
		"Plain text.",
		"",
		[]string{},
		[]attach{},
		&[]error{ErrNoRecipients},
		&smtpservermock.Message{},
	)

	t.Run("SMTP Connection", func(t *testing.T) {
		sc, err := secureconnection.GetSecureConnection(&cmdflags.Settings{Security: types.NoSecurity, SmtpHost: "mail.domain.local", SmtpPort: smtpPort})
		if err != nil {
			t.Fatal(err)
		}
		cl, close, addr, err := sc.ClientConnect()
		if err != nil {
			t.Fatal(err)
		}
		defer close()

		i := 0
		for _, c := range checklist {
			t.Run(c.name, func(t *testing.T) {
				c.message.SetDeterministicIDs("BOUNDARY_ID_")
				err := c.message.SendContent(cl)
				if cont, err := checkError(err, c.expectedErrors); !cont || err != nil {
					if err != nil {
						t.Fatal(err)
					}
					return
				}

				i++
				msg, err := mockSmtp.GetResultMessage(addr, 1, i)
				if err != nil {
					t.Fatal(err)
				}

				if !reflect.DeepEqual(*msg, *c.expectedMessage) {
					t.Fatalf("Expected %v, got %v", c.expectedMessage, *msg)
				}
			})
		}
	})
}

func addCheck(t testing.TB, checklist *[]check, name string, from mail.Address, to, cc, bcc []mail.Address, replyTo []mail.Address, messageId, subject, plainText, htmlText string, headers []string, attachments []attach, expectedErrors *[]error, expectedMessage *smtpservermock.Message) {
	t.Helper()

	msg := NewMessage()
	msg.SetSender(from)
	msg.SetRecipientTo(to)
	msg.SetRecipientCC(cc)
	msg.SetRecipientBCC(bcc)
	msg.SetReplyTo(replyTo)
	msg.SetSubject(subject)
	msg.SetMessageId(messageId)
	for _, h := range headers {
		msg.AddCustomHeader(h)
	}
	msg.SetBodyPlainText(plainText)
	msg.SetBodyHtml(htmlText)
	msg.SetDeterministicIDs("ATTACHMENT_ID_")
	for _, a := range attachments {
		if a.contentType == "" {
			if _, err := msg.AddAttachment(a.filePath); err != nil {
				t.Fatalf("Error attachment %s: %s", a.filePath, err)
			}
		} else {
			if _, err := msg.AddAttachmentWithContentType(a.filePath, a.contentType); err != nil {
				t.Fatalf("Error attachment %s: %s", a.filePath, err)
			}
		}
	}

	*checklist = append(*checklist, check{name: name, message: msg, expectedErrors: expectedErrors, expectedMessage: expectedMessage})
}

func checkError(occuredErr error, expectedErr *[]error) (bool, error) {
	if expectedErr == nil || len(*expectedErr) == 0 {
		if occuredErr != nil {
			return false, fmt.Errorf("Expected no error, got %s", occuredErr)
		}
	} else {
		if occuredErr == nil {
			if len(*expectedErr) == 1 {
				return false, fmt.Errorf("Expected error %s, got no error", (*expectedErr)[0])
			} else {
				return false, fmt.Errorf("Expected errors %s, got no error", errors.Join(*expectedErr...))
			}
		} else {
			for _, exp := range *expectedErr {
				if !strings.Contains(occuredErr.Error(), exp.Error()) {
					return false, fmt.Errorf("Expected error %s, got %s", exp, occuredErr)
				}
			}
			return false, nil
		}
	}
	return true, nil
}

func startDns(ip net.IP, port int) (func() error, error) {
	store := dnsstoragememory.NewMemoryStore()
	(*store).Set("domain.local", dnsconst.Type_A, "127.0.0.1")
	(*store).Set("mail.domain.local", dnsconst.Type_A, "127.0.0.1")
	(*store).Set("domain.local", dnsconst.Type_AAAA, "::1")
	(*store).Set("mail.domain.local", dnsconst.Type_AAAA, "::1")
	(*store).Set("domain.local", dnsconst.Type_MX, "mail.domain.local")

	ds := dnsservermock.NewDnsServer(ip, port, store)
	if err := (*ds).Start(); err != nil {
		return nil, err
	}
	return (*ds).Stop, nil
}

func setDefaultResolver(dnsAddress string) {
	cr := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Second,
			}
			return d.DialContext(ctx, "udp", dnsAddress)
		},
	}
	net.DefaultResolver = cr
}

func getAddress(host string, port types.TCPPort) string {
	return fmt.Sprintf("%s:%d", host, port)
}

func createImageFile(offset, multiplier int) (string, error) {
	img := image.NewRGBA(image.Rect(0, 0, 20, 20))
	for x := 0; x < 20; x++ {
		for y := 0; y < 20; y++ {
			img.Set(x, y, color.RGBA{uint8((x * multiplier) + offset), uint8((y * multiplier) + offset), 200, 255})
		}
	}

	imgFile, err := os.CreateTemp(os.TempDir(), "image.png")
	if err != nil {
		return "", err
	}
	defer imgFile.Close()

	err = png.Encode(imgFile, img)
	if err != nil {
		return "", err
	}

	return imgFile.Name(), nil
}
