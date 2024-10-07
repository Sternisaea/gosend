package types

import (
	"errors"
	"fmt"
	"net/mail"
	"os"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

type FilePath string

func (fp *FilePath) Set(path string) error {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("file %s does not exist (%s)", path, err)
		}
		return fmt.Errorf("error file %s (%s)", path, err)
	}
	*fp = FilePath(path)
	return nil
}

func (fp FilePath) String() string {
	return string(fp)
}

type DomainName string

func (dn *DomainName) Set(host string) error {
	d, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return fmt.Errorf("invalid domain name: %s (%s)", host, err)
	}
	*dn = DomainName(d)
	return nil
}

func (dn DomainName) String() string {
	return string(dn)
}

var maxPort = int(^uint16(0))

type TCPPort int

func (tp *TCPPort) Set(portText string) error {
	p, err := strconv.Atoi(portText)
	if err != nil {
		return fmt.Errorf("invalid SMTP TCP port %s (%s)", portText, err)
	}
	if p > maxPort {
		return fmt.Errorf("port number %d out of range (maximum port no. is %d)", p, maxPort)
	}
	*tp = TCPPort(p)
	return nil
}

func (tp TCPPort) String() string {
	return strconv.Itoa(int(tp))
}

type AuthMethod string

const (
	_        AuthMethod = ""
	STARTTLS AuthMethod = "STARTTLS"
	SSLTLS   AuthMethod = "SSL/TLS"
)

func (a *AuthMethod) Set(auth string) error {
	switch auth {
	case "", STARTTLS.String(), SSLTLS.String():
		*a = AuthMethod(auth)
		return nil
	default:
		return fmt.Errorf("invalid authentication method: %s (valid options are STARTTLS or SSL/TLS)", auth)
	}
}

func (a AuthMethod) String() string {
	return string(a)
}

type Email string

func (e *Email) Set(email string) error {
	ea := strings.Trim(email, " ")
	if _, err := mail.ParseAddress(ea); err != nil {
		return fmt.Errorf("invalid email address: %s (%s)", ea, err)
	}
	*e = Email(ea)
	return nil
}

func (e Email) String() string {
	return string(e)
}

type EmailAddresses []string

func (eas *EmailAddresses) Set(emailsText string) error {
	for _, a := range strings.Split(emailsText, ",") {
		ea := strings.Trim(a, " ")
		if ea != "" {
			if _, err := mail.ParseAddress(ea); err != nil {
				return fmt.Errorf("invalid email address: %s (%s)", ea, err)
			}
			*eas = append(*eas, ea)
		}
	}
	return nil
}

func (eas EmailAddresses) String() string {
	return strings.Join(eas, ",")
}
