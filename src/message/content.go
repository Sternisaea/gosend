package message

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/http"
	"net/mail"
	"os"
	"strconv"
	"strings"
)

type content struct {
	boundary string
	headers  []string
	text     string
	parts    *[]content
}

func (msg *Message) getContentText() (string, error) {
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
	body, err := msg.getBodyContent()
	if err != nil {
		return nil, err
	}
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
		bound, err := (*msg).getRandomString(20)
		if err != nil {
			return nil, err
		}
		return &content{
			boundary: bound,
			headers:  []string{fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"%s\"", bound)},
			text:     "",
			parts:    &prts,
		}, nil
	}
}

func (msg *Message) getBodyContent() (*content, error) {
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
		return &pl, nil
	case (*msg).plainText == "" && (*msg).htmlText != "":
		return &ht, nil
	case (*msg).plainText != "" && (*msg).htmlText != "":
		bound, err := (*msg).getRandomString(20)
		if err != nil {
			return nil, err
		}
		return &content{
			boundary: bound,
			headers:  []string{fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"", bound)},
			text:     "",
			parts:    &[]content{pl, ht},
		}, nil
	}
	return nil, nil
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

func (cnt *content) getContentPart(bound string) string {
	if cnt == nil {
		return ""
	}
	result := ""
	if bound != "" {
		result += fmt.Sprintf("--%s\r\n", bound)
	}
	for _, h := range (*cnt).headers {
		result += h + "\r\n"
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

func (msg *Message) getRandomString(length int) (string, error) {
	if (*msg).idPrefix != "" {
		(*msg).idCounter++
		c := strconv.Itoa((*msg).idCounter)
		if len((*msg).idPrefix)+len(c) > length {
			return "", fmt.Errorf("prefix %s and counter %d do not fit length %d", (*msg).idPrefix, (*msg).idCounter, length)
		}
		return fmt.Sprintf("%s%0*d", (*msg).idPrefix, length, (*msg).idCounter), nil
	}

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b), nil
}

func getMailAddressesAsString(addrs []mail.Address) string {
	var as []string
	for _, a := range addrs {
		as = append(as, a.String())
	}
	return strings.Join(as, ",")
}
