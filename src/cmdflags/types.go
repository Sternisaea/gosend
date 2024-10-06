package cmdflags

import "strings"

type cmdOptions struct {
	serverSettingsFile string
	smtpHost           string
	smtpPort           int

	authFile   string
	authMethod string
	login      string
	password   string

	sender        string
	recipientsTo  []string
	recipientsCC  []string
	recipientsBCC []string
	subject       string
	attachments   []string
}

type stringSlice []string

func (s *stringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func (s *stringSlice) String() string {
	return strings.Join(*s, ",")
}
