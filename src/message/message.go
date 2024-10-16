package message

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/http"
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
	if len(errMsgs) > 0 {
		return fmt.Sprintf("Message: %s", strings.Join(errMsgs, ", "))
	}
	for _, a := range (*msg).attachments {
		if _, err := os.Stat(a.filePath); os.IsNotExist(err) {
			errMsgs = append(errMsgs, fmt.Sprintf("Attachment file %s does not exist", a.filePath))
		}
	}
	return ""
}

func (msg *Message) GetContentText() (string, error) {
	cnt, err := (*msg).getContentTree()
	if err != nil {
		return "", err
	}
	result := ""
	if cnt != nil {
		result += fmt.Sprintf("From: %s\r\n", (*msg).from.String())
		result += fmt.Sprintf("To: %s\r\n", getMailAddressesAsString((*msg).to))
		if len((*msg).cc) != 0 {
			result += fmt.Sprintf("Cc: %s\r\n", getMailAddressesAsString((*msg).cc))
		}
		result += fmt.Sprintf("Subject: %s\r\n", (*msg).subject)
		if len((*msg).replyTo) != 0 {
			result += fmt.Sprintf("Reply-To: %s\r\n", getMailAddressesAsString((*msg).replyTo))
		}
		if (*msg).messageId != "" {
			result += fmt.Sprintf("Message-ID: %s\r\n", (*msg).messageId)
		}
		result += "MIME-Version: 1.0\r\n"
		for _, h := range (*msg).customHeaders {
			if h != "" {
				result += fmt.Sprintf("%s\r\n", h)
			}
		}
		result += cnt.getContentPart("")
	}
	return result, nil
}

func (msg *Message) getContentTree() (*content, error) {
	body := msg.getBodyContent()
	attachs, err := msg.getAttachmentContent()
	if err != nil {
		return nil, err
	}

	if len(attachs) == 0 {
		return body, nil
	} else {
		var prts []content
		if body != nil {
			prts = append(prts, *body)
		}
		prts = append(prts, attachs...)
		bound := getRandomString(20)
		return &content{
			boundary: bound,
			headers:  []string{fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"%s\"", bound)},
			text:     "",
			parts:    &prts,
		}, nil
	}
}

func (msg *Message) getBodyContent() *content {
	var pl, ht content
	if (*msg).plainText != "" {
		plaintext := strings.ReplaceAll((*msg).plainText, `\n`, "\n")
		plaintext = strings.ReplaceAll(plaintext, `\r`, "")
		plaintext = strings.ReplaceAll(plaintext, "\r\n", "\n")
		plaintext = strings.ReplaceAll(plaintext, "\n", "\r\n")
		pl = content{
			boundary: "",
			headers:  []string{"contentType: Content-Type: text/plain; charset=\"UTF-8\"", "Content-Transfer-Encoding: 7bit"},
			text:     plaintext,
			parts:    nil,
		}
	}
	if (*msg).htmlText != "" {
		htmltxt := strings.ReplaceAll((*msg).htmlText, `\n`, "\n")
		htmltxt = strings.ReplaceAll(htmltxt, `\r`, "")
		htmltxt = strings.ReplaceAll(htmltxt, "\r\n", "\n")
		htmltxt = strings.ReplaceAll(htmltxt, "\n", "\r\n")
		for _, a := range (*msg).attachments {
			if a.contentID != "" {
				htmltxt = strings.ReplaceAll(htmltxt, fmt.Sprintf("\"%s\"", a.filePath), fmt.Sprintf("\"cid:%s\"", a.contentID))
				htmltxt = strings.ReplaceAll(htmltxt, fmt.Sprintf("\"%s\"", a.fileName), fmt.Sprintf("\"cid:%s\"", a.contentID))
			}
		}
		ht = content{
			boundary: "",
			headers:  []string{"Content-Type: text/html; charset=\"UTF-8\"", "Content-Transfer-Encoding: 7bit"},
			text:     htmltxt,
			parts:    nil,
		}
	}

	switch true {
	case (*msg).plainText != "" && (*msg).htmlText == "":
		return &pl
	case (*msg).plainText == "" && (*msg).htmlText != "":
		return &ht
	case (*msg).plainText != "" && (*msg).htmlText != "":
		bound := getRandomString(20)
		return &content{
			boundary: bound,
			headers:  []string{fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"", bound)},
			text:     "",
			parts:    &[]content{pl, ht},
		}
	}
	return nil
}

func (msg *Message) getAttachmentContent() ([]content, error) {
	var cnts []content
	for i, a := range (*msg).attachments {
		file, err := os.Open(a.filePath)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		fileInfo, err := file.Stat()
		if err != nil {
			return nil, err
		}

		buffer := make([]byte, fileInfo.Size())
		_, err = file.Read(buffer)
		if err != nil {
			return nil, err
		}

		if a.contentType == "" {
			contentType := http.DetectContentType(buffer[:512])
			(*msg).attachments[i].contentType = contentType
			a.contentType = contentType
		}

		encoded := base64.StdEncoding.EncodeToString(buffer)

		headers := make([]string, 0, 4)
		headers = append(headers, fmt.Sprintf("Content-Type: %s; name=\"%s\"", a.contentType, a.fileName))
		headers = append(headers, "Content-Transfer-Encoding: base64")
		headers = append(headers, fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"", a.fileName))
		if a.contentID != "" {
			headers = append(headers, fmt.Sprintf("Content-ID: %s", a.contentID))
		}

		cnts = append(cnts, content{
			boundary: "",
			headers:  headers,
			text:     encoded,
			parts:    nil,
		})
	}
	return cnts, nil
}

func getRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func getMailAddressesAsString(addrs []mail.Address) string {
	var as []string
	for _, a := range addrs {
		as = append(as, a.String())
	}
	return strings.Join(as, ",")
}
