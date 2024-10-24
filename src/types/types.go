package types

import (
	"errors"
	"fmt"
	"net/mail"
	"os"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

var (
	MaxLineLength = 78
	maxPort       = int(^uint16(0))
)

var (
	ErrFileNotExist = errors.New("file does not exist")
	ErrFile         = errors.New("file error")

	ErrDomainInvalid = errors.New("invalid domain name")

	ErrPortInvalid    = errors.New("invalid TCP port")
	ErrPortNegative   = errors.New("port number cannot be negative")
	ErrPortOutOfRange = fmt.Errorf("port number out of range (maximum port no. is %d)", maxPort)

	ErrSecurityInvalid       = errors.New("invalid security protocol")
	ErrAuthenticationInvalid = errors.New("invalid authentication method")

	ErrEmailInvalid = errors.New("invalid email address")

	ErrAttachmentInvalid = errors.New("invalid attachment")

	ErrHeaderEmpty            = errors.New("header is empty")
	ErrHeaderNoColon          = errors.New("header must contain a colon")
	ErrHeaderMultipleColons   = errors.New("header has multiple colons")
	ErrHeaderNameEmpty        = errors.New("header name is empty")
	ErrHeaderNameIllegalChars = errors.New("header name contains illegal characters")
	ErrHeaderBodyEmpty        = errors.New("header body is empty")
	ErrHeaderBodyIllegalChars = errors.New("header body contains illegal characters")
	ErrHeaderLineTooLong      = fmt.Errorf("header line exceeds maximum lenght of %d", MaxLineLength)
)

var (
	printableAscii         = regexp.MustCompile(`^[\x21-\x7E]+$`)
	printableAsciiSpaceTab = regexp.MustCompile(`^[\x09\x20-\x7E]+$`)
)

type FilePath string

func (fp *FilePath) Set(path string) error {
	if path == "" {
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: %w", ErrFileNotExist, err)
		}
		return fmt.Errorf("%w: %w", ErrFile, err)
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
		return fmt.Errorf("%w: %w", ErrDomainInvalid, err)
	}
	*dn = DomainName(d)
	return nil
}

func (dn DomainName) String() string {
	return string(dn)
}

type TCPPort int

func (tp *TCPPort) Set(portText string) error {
	p, err := strconv.Atoi(portText)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPortInvalid, err)
	}
	if p < 0 {
		return fmt.Errorf("%w", ErrPortNegative)
	}
	if p > maxPort {
		return fmt.Errorf("%w", ErrPortOutOfRange)
	}
	*tp = TCPPort(p)
	return nil
}

func (tp TCPPort) String() string {
	return strconv.Itoa(int(tp))
}

type Security string

const (
	NoSecurity  Security = ""
	StartTlsSec Security = "starttls"
	SslTlsSec   Security = "ssl/tls"
)

func (s *Security) Set(sec string) error {
	switch security := strings.ToLower(sec); security {
	case NoSecurity.String(), StartTlsSec.String(), SslTlsSec.String():
		*s = Security(security)
		return nil
	default:
		return fmt.Errorf("%w", ErrSecurityInvalid)
	}
}

func (s Security) String() string {
	return string(s)
}

type AuthenticationMethod string

const (
	NoAuthentication AuthenticationMethod = ""
	PlainAuth        AuthenticationMethod = "plain"
	CramMd5Auth      AuthenticationMethod = "cram-md5"
)

func (a *AuthenticationMethod) Set(auth string) error {
	switch authentication := strings.ToLower(auth); authentication {
	case NoAuthentication.String(), PlainAuth.String(), CramMd5Auth.String():
		*a = AuthenticationMethod(authentication)
		return nil
	default:
		return fmt.Errorf("%w", ErrAuthenticationInvalid)
	}
}

func (a AuthenticationMethod) String() string {
	return string(a)
}

type Email mail.Address

func (e *Email) Set(email string) error {
	if ea, err := mail.ParseAddress(strings.Trim(email, " ")); err != nil {
		return fmt.Errorf("%w: %w", ErrEmailInvalid, err)
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
	for _, e := range strings.SplitN(emails, ",", -1) {
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

type Header string

func (h *Header) Set(text string) error {
	if err := CheckHeader(text); err != nil {
		return err
	}
	*h = Header(text)
	return nil
}

func (h *Header) String() string {
	return string(*h)
}

func CheckHeader(text string) error {
	// RFC5322
	if text == "" {
		return ErrHeaderEmpty
	}
	parts := strings.SplitN(text, ":", -1)
	if len(parts) == 1 {
		return ErrHeaderNoColon
	}
	if len(parts) > 2 {
		return ErrHeaderMultipleColons
	}

	lines := strings.SplitN(text, "\r\n", -1)
	for i, line := range lines {
		if len(line) > MaxLineLength {
			return ErrHeaderLineTooLong
		}

		var body string
		if i == 0 {
			parts := strings.SplitN(line, ":", -1)
			name := strings.TrimSpace(parts[0])
			body = strings.TrimSpace(parts[1])

			if name == "" {
				return ErrHeaderNameEmpty
			}
			if !printableAscii.MatchString(name) {
				return ErrHeaderNameIllegalChars
			}
		} else {
			body = line
		}

		if body == "" {
			return ErrHeaderBodyEmpty
		}
		if !printableAsciiSpaceTab.MatchString(body) {
			return ErrHeaderBodyIllegalChars
		}

	}
	return nil
}

type Headers []Header

func (hs *Headers) Set(text string) error {
	var h Header
	if err := h.Set(text); err != nil {
		return err
	}
	(*hs) = append((*hs), h)
	return nil
}

func (hs Headers) String() string {
	headers := make([]string, 0, len(hs))
	for _, h := range hs {
		headers = append(headers, h.String())
	}
	return strings.Join(headers, ", ")
}

type Attachments []FilePath

func (at *Attachments) Set(attachments string) error {
	for _, a := range strings.SplitN(attachments, ",", -1) {
		attach := strings.TrimSpace(a)
		if attach != "" {
			var fp FilePath
			if err := fp.Set(attach); err != nil {
				return fmt.Errorf("%w: %w", ErrAttachmentInvalid, err)
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
