package sendmail

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/smtp"
	"os"
)

const starttls = "STARTTLS"

type SmtpConnect struct {
	Hostname   string
	Port       int
	User       string
	Password   string
	RootCAX509 *x509.CertPool
	Sender     string
}

func NewSmtpConnect() *SmtpConnect {
	return &SmtpConnect{}
}

func (sc *SmtpConnect) SetServer(hostname string, port int, login string, password string) error {
	(*sc).Hostname = hostname
	(*sc).Port = port
	(*sc).User = login
	(*sc).Password = password
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
	(*sc).RootCAX509 = rootCAs
	return nil
}

func (sc *SmtpConnect) SetSender(sender string) error {
	(*sc).Sender = sender
	return nil
}

func (sc *SmtpConnect) SendMailTLS(to, cc, bcc string, body string, attachments []string) error {
	c, err := smtp.Dial(fmt.Sprintf("%s:%d", (*sc).Hostname, (*sc).Port))
	if err != nil {
		return err
	}
	defer c.Close()

	if ok, _ := c.Extension(starttls); !ok {
		return fmt.Errorf("server %s does not support %s", (*sc).Hostname, starttls)
	}
	config := &tls.Config{
		ServerName: (*sc).Hostname,
		RootCAs:    (*sc).RootCAX509,
	}
	if err = c.StartTLS(config); err != nil {
		return err
	}

	auth := smtp.PlainAuth("", (*sc).User, (*sc).Password, (*sc).Hostname)
	if err := c.Auth(auth); err != nil {
		return err
	}

	if err := c.Mail((*sc).Sender); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}

	wc, err := c.Data()
	if err != nil {
		return err
	}
	defer wc.Close()

	_, err = wc.Write([]byte(body))
	if err != nil {
		return err
	}
	return nil
}
