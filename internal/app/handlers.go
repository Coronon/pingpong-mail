package app

import (
	"bytes"
	"fmt"
	"net/mail"
	"strings"

	"github.com/chrj/smtpd"
	"github.com/coronon/pingpong-mail/internal/config"
	"github.com/coronon/pingpong-mail/internal/dmarc"
	"github.com/coronon/pingpong-mail/internal/reply"
	"github.com/coronon/pingpong-mail/internal/util"
	"go.uber.org/zap"
	"gopkg.in/gomail.v2"
)

// Check valid recipient (if restricted)
func CheckRecipient(peer smtpd.Peer, addr string) error {
	if config.Cnf.RestrictInbox != "*" && addr != config.Cnf.RestrictInbox {
		zap.S().Debugf("Received email for invalid inbox: %v", addr)
		return fmt.Errorf("please send your test emails to: %v", config.Cnf.RestrictInbox)
	}
	zap.S().Debugf("Received email for valid inbox: %v", addr)

	return nil
}

// Initial handler for all incoming mail
func HandleIncoming(peer smtpd.Peer, env smtpd.Envelope) error {
	var err error

	parsedMail, err := mail.ReadMessage(bytes.NewReader(env.Data))
	if err != nil {
		zap.S().Debugw("Can't parse email body", "error", err)
		return config.ErrCantParseBody
	}

	// Check subject
	zap.S().Debugw("Checking subject",
		"subject", parsedMail.Header.Get("Subject"),
		"forced", config.Cnf.ForceSubjectPrefix,
	)
	if config.Cnf.ForceSubjectPrefix != "" &&
		!strings.HasPrefix(parsedMail.Header.Get("Subject"), config.Cnf.ForceSubjectPrefix) {

		zap.S().Debug("Subject check failed")
		return fmt.Errorf("please start your subject with '%v'", config.Cnf.ForceSubjectPrefix)
	}

	// Detmine sender main domain
	senderDomain := util.GetDomainOrFallback(env.Sender, peer.HeloName)

	//? To avoid becoming a spammer for people that spoof the sender address for
	//? us to reply to, we require a DMARC pass! No DMARC -> no reply!
	if config.Cnf.EnableDmarc {
		zap.S().Debug("Checking DMARC")
		err := dmarc.CheckDmarc(&peer, &env, parsedMail, senderDomain)
		if err != nil {
			return err
		}
	}

	// Handle email
	zap.S().Debugf("Will handle email :)")

	go handleAccepted(parsedMail, env.Recipients[0], env.Sender, senderDomain)

	return nil
}

// Handler for accepted email (passed all checks)
func handleAccepted(email *mail.Message, recipientAddr string, returnAddr string, returnDomain string) {
	// Decide address to reply from
	var replyFrom string
	if config.Cnf.ReplyAddress != "" {
		replyFrom = config.Cnf.ReplyAddress
	} else {
		replyFrom = recipientAddr
	}

	// Build new recipients
	recipients := make([]string, 1)
	recipients[0] = returnAddr

	// Build response subject
	subject := reply.BuildReplySubject(email.Header.Get("Subject"))

	// Build response message
	body := reply.BuildReplyBody(email)
	zap.S().Debugw("Prepared response", "subject", subject, "body", body)

	// Build response mail
	m := gomail.NewMessage()
	m.SetHeader("From", replyFrom)
	m.SetHeader("To", recipientAddr)
	m.SetHeader("Subject", subject)
	m.SetBody("text/plain", body)

	// Find MX server
	mxRecords := util.GetMXDomains(returnDomain)
	if len(mxRecords) == 0 {
		return
	}

	for _, mx := range mxRecords {
		for _, port := range config.Cnf.DeliveryPorts {
			zap.S().Debugw("Trying to send email",
				"from", replyFrom,
				"address", returnAddr,
				"domain", returnDomain,
				"mx_host", mx.Host,
				"mx_pref", mx.Pref,
				"port", port,
			)

			d := gomail.Dialer{Host: mx.Host, Port: port, LocalName: config.Cnf.ServerName}
			sender, err := d.Dial()
			if err != nil {
				zap.S().Debugw("Could not dial", "error", err)
				// Attempt other mx:port combination
				continue
			}

			//? If sending fails we won't retry as that could be seen as 'spammy'
			//? We know that a connection was established as dialing didn't fail
			err = sender.Send(replyFrom, recipients, m)
			sender.Close()
			if err == nil {
				zap.S().Infow("Sent reply", "to", returnAddr)
			} else {
				zap.S().Debugw("Error sending reply", "error", err)
			}

			return
		}
	}
}
