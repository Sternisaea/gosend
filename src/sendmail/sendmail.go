package sendmail

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/smtp"
	"os"
	"strings"

	"github.com/Sternisaea/gosend/src/message"
	"github.com/Sternisaea/gosend/src/types"
)

type SmtpConnect struct {
	hostname       types.DomainName
	port           types.TCPPort
	security       types.Security
	authentication types.AuthenticationMethod
	user           string
	password       string
	rootCAX509     *x509.CertPool
}

func NewSmtpConnect() *SmtpConnect {
	return &SmtpConnect{}
}

func (sc *SmtpConnect) SetServer(hostname types.DomainName, port types.TCPPort, sec types.Security, auth types.AuthenticationMethod, login string, password string) error {
	(*sc).hostname = hostname
	(*sc).port = port
	(*sc).security = sec
	(*sc).authentication = auth
	(*sc).user = login
	(*sc).password = password
	return nil
}

// Note: The certificate must support SAN (Subject Alternative Name)
func (sc *SmtpConnect) SetPemCertificate(path types.FilePath) error {
	if path == "" {
		return nil
	}
	cert, err := os.ReadFile(path.String())
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

func (sc *SmtpConnect) SendMail(msg *message.Message) error {
	var errMsgs []string
	if errMsg := (*sc).CheckServer(); errMsg != "" {
		errMsgs = append(errMsgs, errMsg)
	}
	if errMsg := msg.CheckMessage(); errMsg != "" {
		errMsgs = append(errMsgs, errMsg)
	}
	if len(errMsgs) != 0 {
		return fmt.Errorf("checking errors: [%s]", strings.Join(errMsgs, "], ["))
	}

	config := &tls.Config{
		ServerName: (*sc).hostname.String(),
		RootCAs:    (*sc).rootCAX509,
	}
	var cl *smtp.Client
	var err error
	switch (*sc).security {
	case "":
		cl, err = smtp.Dial(fmt.Sprintf("%s:%d", (*sc).hostname, (*sc).port))
		if err != nil {
			return err
		}
		defer cl.Close()
	case types.StartTlsSec:
		cl, err = smtp.Dial(fmt.Sprintf("%s:%d", (*sc).hostname, (*sc).port))
		if err != nil {
			return err
		}
		defer cl.Close()

		if ok, _ := cl.Extension(types.StartTlsSec.String()); !ok {
			return fmt.Errorf("server %s does not support %s", (*sc).hostname, types.StartTlsSec)
		}
		if err = cl.StartTLS(config); err != nil {
			return err
		}
	case types.SslTlsSec:
		conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", (*sc).hostname, (*sc).port), config)
		if err != nil {
			return fmt.Errorf("server %s does not support SSL/TLS: %s", (*sc).hostname, err)
		}
		defer conn.Close()

		cl, err = smtp.NewClient(conn, (*sc).hostname.String())
		if err != nil {
			return err
		}
		defer cl.Close()
	}

	switch (*sc).authentication {
	case types.NoAuthentication:
	case types.PlainAuth:
		auth := smtp.PlainAuth("", (*sc).user, (*sc).password, (*sc).hostname.String())
		if err = cl.Auth(auth); err != nil {
			return err
		}
	case types.CramMd5Auth:
		auth := smtp.CRAMMD5Auth((*sc).user, (*sc).password)
		if err = cl.Auth(auth); err != nil {
			return err
		}
	}

	if err := cl.Mail(msg.GetSender().Address); err != nil {
		return err
	}

	for _, e := range msg.GetAllRecipients() {
		if err := cl.Rcpt(e.Address); err != nil {
			return err
		}
	}

	wc, err := cl.Data()
	if err != nil {
		return err
	}
	defer wc.Close()

	text, err := msg.GetContentText()
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

	if (*sc).security == types.NoSecurity {
		if (*sc).authentication == types.PlainAuth && (*sc).hostname != "localhost" {
			errMsgs = append(errMsgs, fmt.Sprintf("Authentication method '%s' is only allowed on an secure connection", types.PlainAuth.String()))
		}
	} else {
		if (*sc).authentication == types.NoAuthentication {
			errMsgs = append(errMsgs, "Authentication is required for security protocol '%s'", (*sc).security.String())
		}
	}

	if (*sc).authentication != types.NoAuthentication {
		if (*sc).user == "" {
			errMsgs = append(errMsgs, "No login user provided")
		}
		if (*sc).password == "" {
			errMsgs = append(errMsgs, "No password provided")
		}
	}
	if len(errMsgs) > 0 {
		return fmt.Sprintf("Server: %s", strings.Join(errMsgs, ", "))
	}
	return ""
}
