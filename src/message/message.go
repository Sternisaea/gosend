package message

import (
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
)

type Message struct {
	from          mail.Address
	to, cc, bcc   []mail.Address
	replyTo       []mail.Address
	messageId     string
	subject       string
	plainText     string
	htmlText      string
	customHeaders []string
	attachments   []attachment
}

type attachment struct {
	filePath    string
	fileName    string
	contentType string
	contentID   string
}

func NewMessage() *Message {
	return &Message{}
}

func (msg *Message) SetSender(from mail.Address) {
	(*msg).from = from
}

func (msg *Message) GetSender() mail.Address {
	return (*msg).from
}

func (msg *Message) SetRecipient(to, cc, bcc []mail.Address) {
	(*msg).to = to
	(*msg).cc = cc
	(*msg).bcc = bcc
}

func (msg *Message) GetAllRecipients() []mail.Address {
	rcps := append((*msg).to, (*msg).cc...)
	rcps = append(rcps, (*msg).bcc...)
	return rcps
}

func (msg *Message) SetReplyTo(replyto []mail.Address) {
	(*msg).replyTo = replyto
}

func (msg *Message) SetMessageId(id string) {
	(*msg).messageId = id
}

func (msg *Message) SetSubject(subject string) {
	(*msg).subject = subject
}

func (msg *Message) AddCustomHeader(header string) {
	(*msg).customHeaders = append((*msg).customHeaders, header)
}

func (msg *Message) SetBodyPlainText(plaintext string) {
	(*msg).plainText = plaintext
}

func (msg *Message) SetBodyHtml(htmltext string) {
	(*msg).htmlText = htmltext
}

func (msg *Message) AddAttachment(filePath string) string {
	return msg.AddAttachmentWithContentType(filePath, "")
}

func (msg *Message) AddAttachmentWithContentType(filePath string, contentType string) string {
	fileName := filepath.Base(filePath)
	id := getRandomString(52)
	(*msg).attachments = append((*msg).attachments, attachment{filePath: filePath, fileName: fileName, contentType: contentType, contentID: id})
	return id
}

func (msg *Message) CheckMessage() string {
	var errMsgs []string
	if (*msg).from.Address == "" {
		errMsgs = append(errMsgs, "No sender provided")
	}
	if len((*msg).to) == 0 {
		errMsgs = append(errMsgs, "No recipients provided")
	}
	if (*msg).subject == "" {
		errMsgs = append(errMsgs, "No subject provided")
	}
	for _, a := range (*msg).attachments {
		if _, err := os.Stat(a.filePath); os.IsNotExist(err) {
			errMsgs = append(errMsgs, fmt.Sprintf("Attachment file %s does not exist", a.filePath))
		}
	}
	if len(errMsgs) > 0 {
		return fmt.Sprintf("Message: %s", strings.Join(errMsgs, ", "))
	}
	return ""
}
