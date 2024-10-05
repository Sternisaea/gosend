package sendmail

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/smtp"
	"os"

	"github.com/Sternisaea/gosend/src/message"
)

const starttls = "STARTTLS"

type SmtpConnect struct {
	hostname   string
	port       int
	user       string
	password   string
	rootCAX509 *x509.CertPool
	sender     string
}

func NewSmtpConnect() *SmtpConnect {
	return &SmtpConnect{}
}

func (sc *SmtpConnect) SetServer(hostname string, port int, login string, password string) error {
	(*sc).hostname = hostname
	(*sc).port = port
	(*sc).user = login
	(*sc).password = password
	return nil
}

// Note: The certificate must support SAN (Subject Alternative Name)
func (sc *SmtpConnect) SetPemCertificate(path string) error {
	cert, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	rootCAs := x509.NewCertPool()
	if ok := rootCAs.AppendCertsFromPEM(cert); !ok {
		return fmt.Errorf("failed to append PEM certificate %s", path)
	}
	(*sc).rootCAX509 = rootCAs
	return nil
}

func (sc *SmtpConnect) SetSender(sender string) error {
	(*sc).sender = sender
	return nil
}

func (sc *SmtpConnect) SendMailTLS(to, cc, bcc []string, subject string, bodytext, bodyhtml string, attachments []string) error {
	c, err := smtp.Dial(fmt.Sprintf("%s:%d", (*sc).hostname, (*sc).port))
	if err != nil {
		return err
	}
	defer c.Close()

	if ok, _ := c.Extension(starttls); !ok {
		return fmt.Errorf("server %s does not support %s", (*sc).hostname, starttls)
	}
	config := &tls.Config{
		ServerName: (*sc).hostname,
		RootCAs:    (*sc).rootCAX509,
	}
	if err = c.StartTLS(config); err != nil {
		return err
	}

	auth := smtp.PlainAuth("", (*sc).user, (*sc).password, (*sc).hostname)
	if err := c.Auth(auth); err != nil {
		return err
	}

	if err := c.Mail((*sc).sender); err != nil {
		return err
	}

	rcps := append(to, cc...)
	rcps = append(rcps, bcc...)
	for _, e := range rcps {
		if err := c.Rcpt(e); err != nil {
			return err
		}
	}

	wc, err := c.Data()
	if err != nil {
		return err
	}
	defer wc.Close()

	msg := message.NewMessage()
	msg.SetSender((*sc).sender)
	msg.SetRecipient(to, cc, bcc)
	msg.SetSubject(subject)
	msg.SetBodyPlainText(bodytext)
	msg.SetBodyHtml(bodyhtml)
	msg.AddAttachment(attachments[0], "image/png") // test

	text, err := msg.GetContentText()
	if err != nil {
		return err
	}
	fmt.Println(text) // test

	_, err = wc.Write([]byte(text))
	if err != nil {
		return err
	}
	return nil
}
