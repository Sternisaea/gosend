package message

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"os"
	"strings"
)

type Message struct {
	from        string
	to, cc, bcc []string
	subject     string
	plaintext   string
	htmltext    string
	attachments []attachment
}

type content struct {
	boundary string
	headers  []string
	text     string
	parts    *[]content
}

type attachment struct {
	filePath    string
	contentType string
}

func NewMessage() *Message {
	return &Message{}
}

func (msg *Message) SetSender(from string) {
	(*msg).from = from
}

func (msg *Message) GetSender() string {
	return (*msg).from
}

func (msg *Message) SetRecipient(to, cc, bcc []string) {
	(*msg).to = to
	(*msg).cc = cc
	(*msg).bcc = bcc
}

func (msg *Message) GetRecipients() []string {
	rcps := append((*msg).to, (*msg).cc...)
	rcps = append(rcps, (*msg).bcc...)
	return rcps
}

func (msg *Message) SetSubject(subject string) {
	(*msg).subject = subject
}

func (msg *Message) SetBodyPlainText(plaintext string) {
	(*msg).plaintext = plaintext
}

func (msg *Message) SetBodyHtml(htmltext string) {
	(*msg).htmltext = htmltext
}

func (msg *Message) AddAttachment(filePath string, contentType string) {
	(*msg).attachments = append((*msg).attachments, attachment{filePath: filePath, contentType: contentType})
}

func (msg *Message) GetContentText() (string, error) {
	cnt, err := (*msg).getContentTree()
	if err != nil {
		return "", err
	}
	result := ""
	if cnt != nil {
		result += fmt.Sprintf("From: %s\r\n", (*msg).from)
		result += fmt.Sprintf("To: %s\r\n", strings.Join((*msg).to, ","))
		if len((*msg).cc) != 0 {
			result += fmt.Sprintf("Cc: %s\r\n", strings.Join((*msg).cc, ","))
		}
		result += fmt.Sprintf("Subject: %s\r\n", (*msg).subject)
		result += "MIME-Version: 1.0\r\n"
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
	if (*msg).plaintext != "" {
		pl = content{
			boundary: "",
			headers:  []string{"contentType: Content-Type: text/plain; charset=\"UTF-8\"", "Content-Transfer-Encoding: 7bit"},
			text:     (*msg).plaintext,
			parts:    nil,
		}
	}
	if (*msg).htmltext != "" {
		ht = content{
			boundary: "",
			headers:  []string{"Content-Type: text/html; charset=\"UTF-8\"", "Content-Transfer-Encoding: 7bit"},
			text:     (*msg).htmltext,
			parts:    nil,
		}
	}

	switch true {
	case (*msg).plaintext != "" && (*msg).htmltext == "":
		return &pl
	case (*msg).plaintext == "" && (*msg).htmltext != "":
		return &ht
	case (*msg).plaintext != "" && (*msg).htmltext != "":
		bound := getRandomString(20)
		return &content{
			boundary: bound,
			headers:  []string{fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"boundaryXXX\"", bound)},
			text:     "",
			parts:    &[]content{pl, ht},
		}
	}
	return nil
}

func (msg *Message) getAttachmentContent() ([]content, error) {
	var cnts []content
	for _, a := range (*msg).attachments {
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

		encoded := base64.StdEncoding.EncodeToString(buffer)
		filename := fileInfo.Name()

		cnts = append(cnts, content{
			boundary: "",
			headers: []string{
				fmt.Sprintf("Content-Type: %s; name=\"%s\"", a.contentType, filename),
				"Content-Transfer-Encoding: base64",
				fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"", filename),
			},
			text:  encoded,
			parts: nil,
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

func (cnt *content) getContentPart(bound string) string {
	if cnt == nil {
		return ""
	}
	result := ""
	if bound != "" {
		result += fmt.Sprintf("--%s\r\n", bound)
	}
	for _, h := range (*cnt).headers {
		result += fmt.Sprintf("%s\r\n", h)
	}
	result += "\r\n"
	if (*cnt).text != "" {
		result += (*cnt).text
		result += "\r\n\r\n"
	}
	if (*cnt).parts != nil {
		for _, p := range *(*cnt).parts {
			result += (&p).getContentPart((*cnt).boundary)
		}
	}
	if (*cnt).boundary != "" {
		result += fmt.Sprintf("--%s--\r\n", (*cnt).boundary)
	}
	return result
}
