package secureconnection

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/smtp"

	"github.com/Sternisaea/gosend/src/types"
)

const StartTls = "starttls"

type ConnectStarttls struct {
	hostname   string
	port       int
	rootCaPath string
}

func NewConnectStarttls(hostname string, port int, rootCaPath string) *ConnectStarttls {
	return &ConnectStarttls{hostname: hostname, port: port, rootCaPath: rootCaPath}
}

func (c *ConnectStarttls) Check() error {
	var errMsgs []error
	if (*c).hostname == "" {
		errMsgs = append(errMsgs, fmt.Errorf("no hostname provided"))
	}
	if (*c).port == 0 {
		errMsgs = append(errMsgs, fmt.Errorf("no tcp-port provided"))
	}
	if (*c).rootCaPath != "" {
		errMsgs = append(errMsgs, checkPath((*c).rootCaPath))
	}
	return errors.Join(errMsgs...)
}

func (c *ConnectStarttls) GetType() types.Security {
	return types.StartTlsSec
}

func (c *ConnectStarttls) GetHostName() string {
	return (*c).hostname
}

func (c *ConnectStarttls) ClientConnect() (*smtp.Client, func() error, error) {
	if err := c.Check(); err != nil {
		return nil, nil, err
	}

	client, err := smtp.Dial(fmt.Sprintf("%s:%d", (*c).hostname, (*c).port))
	if err != nil {
		return nil, nil, err
	}

	if ok, _ := client.Extension(StartTls); !ok {
		client.Close()
		return nil, nil, fmt.Errorf("server %s does not support STARTTLS", (*c).hostname)
	}

	config := &tls.Config{
		ServerName: (*c).hostname,
	}
	if c.rootCaPath != "" {
		var err error
		(*config).RootCAs, err = getPemCertificate((*c).rootCaPath)
		if err != nil {
			return nil, nil, err
		}
	}

	if err = client.StartTLS(config); err != nil {
		client.Close()
		return nil, nil, err
	}
	return client, client.Close, nil
}
