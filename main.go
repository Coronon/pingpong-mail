package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/mail"
	"strings"

	"github.com/chrj/smtpd"
	"github.com/emersion/go-msgauth/dmarc"
	"go.uber.org/zap"
	"gopkg.in/gomail.v2"
)

var (
	isVerbose     = flag.Bool("v", false, "Enable debug output (might include sensitive data!)")
	welcomeMsg    = flag.String("welcome", "PingPong email tester", "Welcome message for SMTP session")
	serverName    = flag.String("serverName", "localhost", "Name used in HELO/EHLO command when sending reply")
	inAddr        = flag.String("inaddr", "localhost:25", "Address to listen for incoming SMTP on")
	inbox         = flag.String("inbox", "*", "Inbox address to receive email for")
	replyAddr     = flag.String("replyAddr", "", "E-Mail address to send responses from (default: first recipient)")
	replySubject  = flag.String("replySubject", "PONG - {ORIGINAL_SUBJECT}", "Subject to reply with")
	replyMsg      = flag.String("replyMsg", "PONG in response to:\n\n{ORIGINAL_MSG}", "Text to reply with")
	forcedSubject = flag.String("subject", "", "Force some string at the beginning of subjects")
)

var (
	ErrCantParseBody     = errors.New("Could not parse message body")
	ErrFromHeaderMissing = errors.New("<From:> header is missing")
	ErrFromHeaderInvalid = errors.New("<From:> header is invalid")
	ErrSPFCantValidate   = errors.New("SPF can not be validated")
	ErrDKIMCantValidate  = errors.New("DKIM can not be validated")
	ErrDMARCFailed       = errors.New("DMARC failed or sender could not be validated")
)

// Check valid recipient (if limited)
func recipientChecker(peer smtpd.Peer, addr string) error {
	if *inbox != "*" && addr != *inbox {
		zap.S().Debugf("Received email for invalid inbox: %v", addr)
		return fmt.Errorf("please send your test emails to: %v", *inbox)
	}
	zap.S().Debugf("Received email for valid inbox: %v", addr)

	return nil
}

// Initial handler for all incoming mail
func handleIncoming(peer smtpd.Peer, env smtpd.Envelope) error {
	var err error

	parsedMail, err := mail.ReadMessage(bytes.NewReader(env.Data))
	if err != nil {
		zap.S().Debugw("Can't parse email body", "error", err)
		return ErrCantParseBody
	}

	// Check subject
	zap.S().Debugw("Checking subject",
		"subject", parsedMail.Header.Get("Subject"),
		"forced", *forcedSubject,
	)
	if *forcedSubject != "" && !strings.HasPrefix(parsedMail.Header.Get("Subject"), *forcedSubject) {
		zap.S().Debug("Subject check failed")
		return fmt.Errorf("please start your subject with '%v'", *forcedSubject)
	}

	//? To avoid becoming a spammer for people that spoof the sender address for
	//? us to reply to, we require a DMARC pass! No DMARC -> no reply!
	// Detmine sender main domain
	senderDomain := getDomainOrFallback(env.Sender, peer.HeloName)

	// Determine sender <From:> header domain
	fromHeaderParsed, err := getFromAddress(parsedMail.Header.Get("From"))
	if err != nil {
		zap.S().Debugw("Can't get <From:> address", "error", err)
		return err
	}
	fromHeaderAddr := getDomainOrFallback(fromHeaderParsed, "")
	if fromHeaderAddr == "" {
		zap.S().Debugw("Can't get <From:> domain", "error", err)
		return ErrFromHeaderInvalid
	}

	zap.S().Debugf("Sender domain: %v, From header: %v\n", senderDomain, fromHeaderAddr)

	// Check DMARC framework
	dmarcRecord, err := dmarc.Lookup(senderDomain)
	if err != nil {
		zap.S().Debugw("DMARC lookup failed", "error", err)
		return ErrDMARCFailed
	}

	validSPFDomain, err := getValidSPF(&peer, &env)
	if err != nil {
		zap.S().Debugw("SPF validation failed", "error", err)
		return err
	}
	isSPFValid := checkAlignment(fromHeaderAddr, validSPFDomain, dmarcRecord.SPFAlignment)

	validDKIMDomains, err := getValidDKIM(&peer, &env)
	if err != nil {
		zap.S().Debugw("DKIM validation failed", "error", err)
		return err
	}
	isDKIMValid := false
	for i := range validDKIMDomains {
		if checkAlignment(fromHeaderAddr, validDKIMDomains[i], dmarcRecord.DKIMAlignment) {
			isDKIMValid = true
			break
		}
	}

	zap.S().Debugf("SPF valid: %v, DKIM valid: %v -> %v\n", isSPFValid, isDKIMValid, isSPFValid || isDKIMValid)

	if !isSPFValid && !isDKIMValid {
		zap.S().Debugf("Will reject email :(")
		return ErrDMARCFailed
	}

	// Handle email
	zap.S().Debugf("Will handle email :)")

	go handleAccepted(parsedMail, env.Recipients[0], env.Sender, senderDomain)

	return nil
}

// Handler for accepted email (passed DMARC so we know people _actually_ want a response)
func handleAccepted(email *mail.Message, recipientAddr string, returnAddr string, returnDomain string) {
	// Decide address to reply from
	var replyFrom string
	if *replyAddr != "" {
		replyFrom = *replyAddr
	} else {
		replyFrom = recipientAddr
	}

	// Build new recipients
	recipients := make([]string, 1)
	recipients[0] = returnAddr

	// Build response subject
	subject := strings.ReplaceAll(*replySubject, "{ORIGINAL_SUBJECT}", email.Header.Get("Subject"))

	// Build response message
	origMsg := new(strings.Builder)
	io.Copy(origMsg, email.Body)

	msg := strings.ReplaceAll(*replyMsg, "{ORIGINAL_MSG}", origMsg.String())
	zap.S().Debugw("Prepared response", "msg", msg)

	m := gomail.NewMessage()
	m.SetHeader("From", replyFrom)
	m.SetHeader("To", recipientAddr)
	m.SetHeader("Subject", subject)
	m.SetBody("text/plain", msg)

	// Find MX server
	mxRecords, err := net.LookupMX(returnDomain)
	if err != nil {
		zap.S().Info("Can't lookup MX records", "domain", returnDomain)
		return
	}
	if len(mxRecords) == 0 {
		zap.S().Info("No MX records found", "domain", returnDomain)
		return
	}
	zap.S().Debugw("Found MX records",
		"domain", returnDomain,
		"records", mxRecords,
	)

	for _, mx := range mxRecords {
		zap.S().Debugw("Trying to send email",
			"from", replyFrom,
			"address", returnAddr,
			"domain", returnDomain,
			"mx_host", mx.Host,
			"mx_pref", mx.Pref,
		)

		d := gomail.Dialer{Host: mx.Host, Port: 587, LocalName: *serverName}
		sender, err := d.Dial()
		if err != nil {
			zap.S().Debugw("Could not dial", "error", err)
			continue
		}

		err = sender.Send(replyFrom, recipients, m)
		sender.Close()
		if err == nil {
			zap.S().Info("Sent reply", "to", returnAddr)
			return
		} else {
			zap.S().Debugw("Error sending reply", "error", err)
		}
	}
}

func init() {
	// Setup logging
	cfg := zap.NewProductionConfig()

	logger, _ := cfg.Build()
	defer logger.Sync()

	zap.ReplaceGlobals(logger)
}

func main() {
	flag.Parse()

	// Setup verbose logging
	if *isVerbose {
		verboseCfg := zap.NewDevelopmentConfig()

		verboseLogger, _ := verboseCfg.Build()
		defer verboseLogger.Sync()

		zap.ReplaceGlobals(verboseLogger)
	}

	server := &smtpd.Server{
		WelcomeMessage:   *welcomeMsg,
		RecipientChecker: recipientChecker,
		Handler:          handleIncoming,
	}

	zap.S().Infof("Starting server on %v...", *inAddr)
	server.ListenAndServe(*inAddr)
}
