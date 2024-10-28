package secureconnection

import (
	"errors"
	"fmt"
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
		errMsgs = append(errMsgs, fmt.Errorf("no hostname provided"))
	}
	if (*c).port == 0 {
		errMsgs = append(errMsgs, fmt.Errorf("no tcp-port provided"))
	}
	return errors.Join(errMsgs...)
}

func (c *ConnectNone) GetType() types.Security {
	return types.NoSecurity
}

func (c *ConnectNone) GetHostName() string {
	return (*c).hostname
}

func (c *ConnectNone) ClientConnect() (*smtp.Client, func() error, error) {
	if err := c.Check(); err != nil {
		return nil, nil, err
	}

	client, err := smtp.Dial(fmt.Sprintf("%s:%d", (*c).hostname, (*c).port))
	if err != nil {
		return nil, nil, err
	}
	return client, client.Close, nil
}
