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
	if path == "" {
		return nil
	}
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
	switch strings.ToUpper(auth) {
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

type Email mail.Address

func (e *Email) Set(email string) error {
	if ea, err := mail.ParseAddress(strings.Trim(email, " ")); err != nil {
		return fmt.Errorf("invalid email address: %s (%s)", email, err)
	} else {
		*e = Email(*ea)
	}
	return nil
}

func (e Email) String() string {
	ea := mail.Address(e)
	return (&ea).String()
}

func (e Email) GetMailAddress() mail.Address {
	return mail.Address(e)
}

type EmailAddresses []Email

func (eas *EmailAddresses) Set(emails string) error {
	for _, e := range strings.Split(emails, ",") {
		em := strings.TrimSpace(e)
		if em != "" {
			var email Email
			if err := email.Set(em); err != nil {
				return err

			}
			*eas = append(*eas, email)
		}
	}
	return nil
}

func (eas EmailAddresses) String() string {
	emails := make([]string, 0, len(eas))
	for _, e := range eas {
		emails = append(emails, e.String())
	}
	return strings.Join(emails, ", ")
}

func (eas EmailAddresses) GetMailAddresses() []mail.Address {
	emails := make([]mail.Address, 0, len(eas))
	for _, e := range eas {
		emails = append(emails, e.GetMailAddress())
	}
	return emails
}

type Headers []string

func (hs *Headers) Set(text string) error {
	h := text
	(*hs) = append((*hs), h)
	return nil
}

func (hs Headers) String() string {
	return strings.Join(hs, ", ")
}

type Attachments []FilePath

func (at *Attachments) Set(attachments string) error {
	for _, a := range strings.Split(attachments, ",") {
		attach := strings.TrimSpace(a)
		if attach != "" {
			var fp FilePath
			if err := fp.Set(attach); err != nil {
				return fmt.Errorf("invalid attachment: %s (%s)", attach, err)
			}
			*at = append(*at, fp)
		}
	}
	return nil
}

func (at Attachments) String() string {
	attchs := make([]string, 0, len(at))
	for _, fp := range at {
		attchs = append(attchs, fp.String())
	}
	return strings.Join(attchs, ", ")
}
