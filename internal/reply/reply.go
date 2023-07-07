package reply

import (
	"io"
	"net/mail"
	"strings"
	"time"

	"github.com/coronon/pingpong-mail/internal/config"
)

// Build the subject for the response to `original`
func BuildReplySubject(original string) string {
	return strings.ReplaceAll(config.Cnf.ReplySubject, "{ORIG_SUBJ}", original)
}

// Build the body for the response to `email`
func BuildReplyBody(email *mail.Message) string {
	origMsg := new(strings.Builder)
	io.Copy(origMsg, email.Body)

	body := strings.ReplaceAll(config.Cnf.ReplyMessage, "{ORIG_BODY}", origMsg.String())
	body = strings.ReplaceAll(body, "{TIME}", time.Now().UTC().Format(time.RFC3339))

	return body
}
