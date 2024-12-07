package secureconnection

import (
	"errors"
	"fmt"
	"net"
	"net/smtp"

	"github.com/Sternisaea/gosend/src/types"
)

type ConnectNone struct {
	hostname string
	port     int
}

func NewConnectNone(hostname string, port int) *ConnectNone {
	return &ConnectNone{hostname: hostname, port: port}
}

func (c *ConnectNone) Check() error {
	var errMsgs []error
	if (*c).hostname == "" {
		errMsgs = append(errMsgs, ErrNoHostname)
	}
	if (*c).port == 0 {
		errMsgs = append(errMsgs, ErrNoPort)
	}
	return errors.Join(errMsgs...)
}

func (c *ConnectNone) GetType() types.Security {
	return types.NoSecurity
}

func (c *ConnectNone) GetHostName() string {
	return (*c).hostname
}

func (c *ConnectNone) ClientConnect() (*smtp.Client, func() error, string, error) {
	if err := c.Check(); err != nil {
		return nil, nil, "", err
	}

	// Not using smtp.Dial, because Source TCP Port need to be ascertained
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", (*c).hostname, (*c).port))
	if err != nil {
		return nil, nil, "", err
	}
	client, err := smtp.NewClient(conn, (*c).hostname)
	if err != nil {
		return nil, nil, "", err
	}

	return client, client.Close, conn.LocalAddr().String(), nil
}
