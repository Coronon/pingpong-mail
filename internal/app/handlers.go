package app

import (
	"bytes"
	"fmt"
	"net"
	"net/mail"
	"strings"

	"github.com/chrj/smtpd"
	"github.com/domodwyer/mailyak/v3"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/coronon/pingpong-mail/internal/config"
	"github.com/coronon/pingpong-mail/internal/dmarc"
	"github.com/coronon/pingpong-mail/internal/reply"
	"github.com/coronon/pingpong-mail/internal/util"
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

	// Determine sender <From:> address
	// This is also the address we will reply to -> honouring Reply-To could open
	// up attack vectors
	fromHeaderAddr, err := util.GetRawFromHeaderAddress(parsedMail.Header.Get("From"))
	if err != nil {
		zap.S().Debugw("Can't get <From:> address", "error", err)
		return err
	}
	// Determine sender <From:> domain (after the @)
	fromHeaderDomain := util.GetDomainOrFallback(fromHeaderAddr, "")
	if fromHeaderDomain == "" {
		zap.S().Debugw("Can't get <From:> domain", "error", err)
		return config.ErrFromHeaderInvalid
	}

	zap.S().Debugf("Sender domain: %v, From header: %v\n", senderDomain, fromHeaderAddr)

	//? To avoid becoming a spammer for people that spoof the sender address for
	//? us to reply to, we require a DMARC pass! No DMARC -> no reply!
	if config.Cnf.EnableDmarc {
		zap.S().Debug("Checking DMARC")
		err := dmarc.CheckDmarc(&peer, &env, fromHeaderDomain, senderDomain)
		if err != nil {
			return err
		}
	}

	// Handle email
	zap.S().Debugf("Will handle email :)")

	go handleAccepted(parsedMail, env.Recipients[0], fromHeaderAddr)

	return nil
}

// Handler for accepted email (passed all checks)
func handleAccepted(email *mail.Message, incomingRcptAddr string, outgoingRcptAddr string) {
	// Decide address to reply from
	var replyFrom string
	if config.Cnf.ReplyAddress != "" {
		replyFrom = config.Cnf.ReplyAddress
	} else {
		replyFrom = incomingRcptAddr
	}

	// Build new recipients
	recipients := make([]string, 1)
	recipients[0] = outgoingRcptAddr

	// Build response subject
	subject := reply.BuildReplySubject(email.Header.Get("Subject"))

	// Build response message
	body := reply.BuildReplyBody(email)
	zap.S().Debugw("Prepared response", "subject", subject, "body", body)

	// Build Message-ID
	msgUUID, err := uuid.NewRandom()
	if err != nil {
		zap.S().Debugw("Could not generate random UUID for Message-ID", "error", err)
	}
	msgID := fmt.Sprintf("<%s@%s>", msgUUID, config.Cnf.ServerName)

	// Build response mail
	response := mailyak.New("", nil)
	response.LocalName(config.Cnf.ServerName)
	response.SetHeader("Message-ID", msgID)
	response.From(replyFrom)
	response.To(incomingRcptAddr)
	response.Subject(subject)
	response.Plain().Set(body)

	// Find MX server
	outgoingRcptDomain := util.GetDomainOrFallback(outgoingRcptAddr, "")
	if outgoingRcptDomain == "" {
		zap.S().Debugw("Could not determine domain for address", "address", outgoingRcptAddr)
		return
	}
	mxRecords := util.GetMXDomains(outgoingRcptDomain)
	if len(mxRecords) == 0 {
		return
	}

	for _, mx := range mxRecords {
		for _, port := range config.Cnf.DeliveryPorts {
			zap.S().Debugw("Trying to send email",
				"from", replyFrom,
				"address", outgoingRcptAddr,
				"domain", outgoingRcptDomain,
				"mx_host", mx.Host,
				"mx_pref", mx.Pref,
				"port", port,
			)

			conn, err := net.Dial("tcp", fmt.Sprintf("%v:%v", mx.Host, port))
			if err != nil {
				zap.S().Debugw("Could not dial", "error", err)
				// Attempt other mx:port combination
				continue
			}
			defer func() { _ = conn.Close() }()

			//? If sending fails we won't retry as that could be seen as 'spammy'
			//? We know that a connection was established as dialing didn't fail
			err = util.SmtpExchange(response, conn, mx.Host, true)
			if err == nil {
				zap.S().Infow("Sent reply", "to", outgoingRcptAddr)
			} else {
				zap.S().Debugw("Error sending reply", "error", err)
			}

			return
		}
	}
}
