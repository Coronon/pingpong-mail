package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"net/mail"

	"github.com/chrj/smtpd"
	"github.com/emersion/go-msgauth/dmarc"
	"go.uber.org/zap"
)

var (
	isVerbose  = flag.Bool("v", false, "Enable debug output (might include sensitive data!)")
	welcomeMsg = flag.String("welcome", "PingPong email tester", "Welcome message for SMTP session")
	inAddr     = flag.String("inaddr", "localhost:25", "Address to listen for incoming SMTP on")
	inbox      = flag.String("inbox", "*", "Inbox address to receive email for")
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

func handler(peer smtpd.Peer, env smtpd.Envelope) error {
	var err error

	parsedMail, err := mail.ReadMessage(bytes.NewReader(env.Data))
	if err != nil {
		zap.S().Debugw("Can't parse email body", "error", err)
		return ErrCantParseBody
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

	return nil
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
		Handler:          handler,
	}

	zap.S().Infof("Starting server on %v...", *inAddr)
	server.ListenAndServe(*inAddr)
}
