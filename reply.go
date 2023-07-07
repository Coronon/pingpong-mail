package main

import (
	"io"
	"net/mail"
	"strings"
	"time"
)

// Build the subject for the response to `original`
func buildReplySubject(original string) string {
	return strings.ReplaceAll(config.ReplySubject, "{ORIG_SUBJ}", original)
}

// Build the body for the response to `email`
func buildReplyBody(email *mail.Message) string {
	origMsg := new(strings.Builder)
	io.Copy(origMsg, email.Body)

	body := strings.ReplaceAll(config.ReplyMessage, "{ORIG_BODY}", origMsg.String())
	body = strings.ReplaceAll(body, "{TIME}", time.Now().UTC().Format(time.RFC3339))

	return body
}
