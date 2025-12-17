package sanitizer

import (
	"regexp"
	"strings"

	"winopsguard/internal/model"
)

var (
	ipv4Regex   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Regex   = regexp.MustCompile(`(?i)\b([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b`)
	userRegex   = regexp.MustCompile(`(?i)user\\?[:= ]?([A-Za-z0-9._-]+)`)
	hostRegex   = regexp.MustCompile(`(?i)host\\?[:= ]?([A-Za-z0-9._-]+)`)
)

// MaskRequest mutates AIRequest in-place to remove sensitive tokens.
func MaskRequest(req *model.AIRequest) {
	maskEventSet := func(set *model.LogSet) {
		for i := range set.Recent {
			set.Recent[i].Message = maskString(set.Recent[i].Message)
			set.Recent[i].Source = maskString(set.Recent[i].Source)
		}
	}
	maskEventSet(&req.EventLog.System)
	maskEventSet(&req.EventLog.Application)

	for i := range req.WindowsUpdateLog.Excerpt {
		req.WindowsUpdateLog.Excerpt[i] = maskString(req.WindowsUpdateLog.Excerpt[i])
	}
	req.WindowsUpdateLog.Summary = maskString(req.WindowsUpdateLog.Summary)
	req.Host.Hostname = maskString(req.Host.Hostname)
	req.Host.OS = maskString(req.Host.OS)
}

func maskString(in string) string {
	s := in
	s = ipv4Regex.ReplaceAllString(s, "***")
	s = ipv6Regex.ReplaceAllString(s, "***")
	s = userRegex.ReplaceAllStringFunc(s, func(m string) string {
		sub := userRegex.FindStringSubmatch(m)
		if len(sub) > 1 {
			return strings.Replace(m, sub[1], "***", 1)
		}
		return m
	})
	s = hostRegex.ReplaceAllStringFunc(s, func(m string) string {
		sub := hostRegex.FindStringSubmatch(m)
		if len(sub) > 1 {
			return strings.Replace(m, sub[1], "***", 1)
		}
		return m
	})
	return s
}
