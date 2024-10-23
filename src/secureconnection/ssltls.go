package secureconnection

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/smtp"
)

type ConnectSslTls struct {
	hostname   string
	port       int
	rootCaPath string
}

func NewConnectSslTls(hostname string, port int, rootCaPath string) *ConnectSslTls {
	return &ConnectSslTls{hostname: hostname, port: port, rootCaPath: rootCaPath}
}

func (c *ConnectSslTls) Check() error {
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

func (c *ConnectSslTls) ClientConnect() (*smtp.Client, func() error, error) {
	if err := c.Check(); err != nil {
		return nil, nil, err
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

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", (*c).hostname, (*c).port), config)
	if err != nil {
		return nil, nil, fmt.Errorf("server %s does not support SSL/TLS: %s", (*c).hostname, err)
	}
	client, err := smtp.NewClient(conn, (*c).hostname)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	close := func() error {
		errClient := client.Close()
		errConnection := conn.Close()
		if errClient != nil || errConnection != nil {
			return errors.Join(errClient, errConnection)
		}
		return nil
	}
	return client, close, nil
}