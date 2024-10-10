package message

import "fmt"

type content struct {
	boundary string
	headers  []string
	text     string
	parts    *[]content
}

func (cnt *content) getContentPart(bound string) string {
	if cnt == nil {
		return ""
	}
	result := ""
	if bound != "" {
		result += fmt.Sprintf("--%s\r\n", bound)
	}
	for _, h := range (*cnt).headers {
		result += h + "\r\n"
	}
	result += "\r\n"
	if (*cnt).text != "" {
		result += (*cnt).text
		result += "\r\n\r\n"
	}
	if (*cnt).parts != nil {
		for _, p := range *(*cnt).parts {
			result += (&p).getContentPart((*cnt).boundary)
		}
	}
	if (*cnt).boundary != "" {
		result += fmt.Sprintf("--%s--\r\n", (*cnt).boundary)
	}
	return result
}
