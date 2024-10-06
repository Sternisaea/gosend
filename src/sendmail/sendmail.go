package sendmail

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/smtp"
	"os"
	"strings"

	"github.com/Sternisaea/gosend/src/message"
)

const starttls = "STARTTLS"

type SmtpConnect struct {
	hostname   string
	port       int
	user       string
	password   string
	rootCAX509 *x509.CertPool
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

func (sc *SmtpConnect) SendMailTLS(message *message.Message) error {
	var errMsgs []string
	if errMsg := (*sc).CheckServer(); errMsg != "" {
		errMsgs = append(errMsgs, errMsg)
	}
	if errMsg := (*message).CheckMessage(); errMsg != "" {
		errMsgs = append(errMsgs, errMsg)
	}
	if len(errMsgs) != 0 {
		return fmt.Errorf("checking errors: [%s]", strings.Join(errMsgs, "], ["))
	}

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

	if err := c.Mail(message.GetSender()); err != nil {
		return err
	}

	for _, e := range message.GetRecipients() {
		if err := c.Rcpt(e); err != nil {
			return err
		}
	}

	wc, err := c.Data()
	if err != nil {
		return err
	}
	defer wc.Close()

	text, err := message.GetContentText()
	if err != nil {
		return err
	}

	_, err = wc.Write([]byte(text))
	if err != nil {
		return err
	}
	return nil
}

func (sc *SmtpConnect) CheckServer() string {
	var errMsgs []string
	if (*sc).hostname == "" {
		errMsgs = append(errMsgs, "No hostname provided")
	}
	if (*sc).port == 0 {
		errMsgs = append(errMsgs, "No port provided")
	}
	if (*sc).user == "" {
		errMsgs = append(errMsgs, "No login user provided")
	}
	if (*sc).password == "" {
		errMsgs = append(errMsgs, "No password provided")
	}
	if len(errMsgs) > 0 {
		return fmt.Sprintf("Server: %s", strings.Join(errMsgs, ", "))
	}
	return ""
}
