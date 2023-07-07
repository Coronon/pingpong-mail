package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"net/mail"
	"strings"

	"github.com/chrj/smtpd"
	"go.uber.org/zap"
	"gopkg.in/gomail.v2"
)

var (
	isVerbose  = flag.Bool("v", false, "Enable debug output (might include sensitive data!)")
	configPath = flag.String("c", "pingpong.yml", "Path to a configuration file to use")
)

var config Config

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
	if config.RestrictInbox != "*" && addr != config.RestrictInbox {
		zap.S().Debugf("Received email for invalid inbox: %v", addr)
		return fmt.Errorf("please send your test emails to: %v", config.RestrictInbox)
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
		"forced", config.ForceSubjectPrefix,
	)
	if config.ForceSubjectPrefix != "" &&
		!strings.HasPrefix(parsedMail.Header.Get("Subject"), config.ForceSubjectPrefix) {

		zap.S().Debug("Subject check failed")
		return fmt.Errorf("please start your subject with '%v'", config.ForceSubjectPrefix)
	}

	// Detmine sender main domain
	senderDomain := getDomainOrFallback(env.Sender, peer.HeloName)

	//? To avoid becoming a spammer for people that spoof the sender address for
	//? us to reply to, we require a DMARC pass! No DMARC -> no reply!
	if config.EnableDmarc {
		zap.S().Debug("Checking DMARC")
		err := checkDmarc(&peer, &env, parsedMail, senderDomain)
		if err != nil {
			return err
		}
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
	if config.ReplyAddress != "" {
		replyFrom = config.ReplyAddress
	} else {
		replyFrom = recipientAddr
	}

	// Build new recipients
	recipients := make([]string, 1)
	recipients[0] = returnAddr

	// Build response subject
	subject := buildReplySubject(email.Header.Get("Subject"))

	// Build response message
	body := buildReplyBody(email)
	zap.S().Debugw("Prepared response", "subject", subject, "body", body)

	// Build response mail
	m := gomail.NewMessage()
	m.SetHeader("From", replyFrom)
	m.SetHeader("To", recipientAddr)
	m.SetHeader("Subject", subject)
	m.SetBody("text/plain", body)

	// Find MX server
	mxRecords := getMXDomains(returnDomain)
	if len(mxRecords) == 0 {
		return
	}

	for _, mx := range mxRecords {
		for _, port := range config.DeliveryPorts {
			zap.S().Debugw("Trying to send email",
				"from", replyFrom,
				"address", returnAddr,
				"domain", returnDomain,
				"mx_host", mx.Host,
				"mx_pref", mx.Pref,
				"port", port,
			)

			d := gomail.Dialer{Host: mx.Host, Port: port, LocalName: config.ServerName}
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

func init() {
	// Setup logging
	cfg := zap.NewProductionConfig()

	logger, _ := cfg.Build()
	defer logger.Sync()

	zap.ReplaceGlobals(logger)
}

func main() {
	flag.Parse()

	// Load configuration
	config = readConfig(*configPath)

	// Setup verbose logging
	if *isVerbose {
		verboseCfg := zap.NewDevelopmentConfig()

		verboseLogger, _ := verboseCfg.Build()
		defer verboseLogger.Sync()

		zap.ReplaceGlobals(verboseLogger)
	}

	// Start STMP server
	server := &smtpd.Server{
		WelcomeMessage:   config.SMTPWelcomeMessage,
		RecipientChecker: recipientChecker,
		Handler:          handleIncoming,
	}

	bindAddr := fmt.Sprintf("%v:%v", config.BindHost, config.BindPort)

	zap.S().Infof("Starting server on: ", bindAddr)
	server.ListenAndServe(bindAddr)
}
