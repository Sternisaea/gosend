package message

import (
	"errors"
	"fmt"
	"net/mail"
	"net/smtp"
	"os"
	"path/filepath"
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

func (msg *Message) SetRecipientTo(to []mail.Address) {
	(*msg).to = to
}

func (msg *Message) SetRecipientCC(cc []mail.Address) {
	(*msg).cc = cc
}

func (msg *Message) SetRecipientBCC(bcc []mail.Address) {
	(*msg).bcc = bcc
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

func (msg *Message) CheckMessage() error {
	var errMsgs []error
	if (*msg).from.Address == "" {
		errMsgs = append(errMsgs, fmt.Errorf("no sender provided"))
	}
	if len((*msg).to) == 0 {
		errMsgs = append(errMsgs, fmt.Errorf("no recipients provided"))
	}
	if (*msg).subject == "" {
		errMsgs = append(errMsgs, fmt.Errorf("no subject provided"))
	}
	for _, a := range (*msg).attachments {
		if _, err := os.Stat(a.filePath); os.IsNotExist(err) {
			errMsgs = append(errMsgs, fmt.Errorf("attachment file %s does not exist", a.filePath))
		}
	}
	return errors.Join(errMsgs...)
}

func (msg *Message) SendContent(client *smtp.Client) error {
	if err := msg.CheckMessage(); err != nil {
		return err
	}

	if err := client.Mail(msg.from.Address); err != nil {
		return err
	}

	for _, e := range msg.to {
		if err := client.Rcpt(e.Address); err != nil {
			return err
		}
	}
	for _, e := range msg.cc {
		if err := client.Rcpt(e.Address); err != nil {
			return err
		}
	}

	wc, err := client.Data()
	if err != nil {
		return err
	}
	defer wc.Close()

	text, err := msg.getContentText()
	if err != nil {
		return err
	}

	_, err = wc.Write([]byte(text))
	if err != nil {
		return err
	}
	return nil
}
