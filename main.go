package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"net/mail"

	"github.com/chrj/smtpd"
	"github.com/emersion/go-msgauth/dmarc"
)

var (
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
		return fmt.Errorf("please send your test emails to: %v", *inbox)
	}

	return nil
}

func handler(peer smtpd.Peer, env smtpd.Envelope) error {
	var err error

	parsedMail, err := mail.ReadMessage(bytes.NewReader(env.Data))
	if err != nil {
		return ErrCantParseBody
	}

	//? To avoid becoming a spammer for people that spoof the sender address for
	//? us to reply to, we require a DMARC pass! No DMARC -> no reply!
	// Detmine sender main domain
	senderDomain := getDomainOrFallback(env.Sender, peer.HeloName)

	// Determine sender <From:> header domain
	fromHeaderParsed, err := getFromAddress(parsedMail.Header.Get("From"))
	if err != nil {
		return err
	}
	fromHeaderAddr := getDomainOrFallback(fromHeaderParsed, "")
	if fromHeaderAddr == "" {
		return ErrFromHeaderInvalid
	}

	fmt.Printf("Sender domain: %v, From header: %v\n", senderDomain, fromHeaderAddr)

	// Check DMARC framework
	dmarcRecord, err := dmarc.Lookup(senderDomain)
	if err != nil {
		return ErrDMARCFailed
	}

	validSPFDomain, err := getValidSPF(&peer, &env)
	if err != nil {
		return err
	}
	isSPFValid := checkAlignment(fromHeaderAddr, validSPFDomain, dmarcRecord.SPFAlignment)

	validDKIMDomains, err := getValidDKIM(&peer, &env)
	if err != nil {
		return err
	}
	isDKIMValid := false
	for i := range validDKIMDomains {
		if checkAlignment(fromHeaderAddr, validDKIMDomains[i], dmarcRecord.DKIMAlignment) {
			isDKIMValid = true
			break
		}
	}

	fmt.Println(validSPFDomain)
	fmt.Println(validDKIMDomains)
	fmt.Printf("SPF valid: %v, DKIM valid: %v -> %v\n", isSPFValid, isDKIMValid, isSPFValid || isDKIMValid)

	if !isSPFValid && !isDKIMValid {
		fmt.Println("Will reject email :(")
		return ErrDMARCFailed
	}

	// Handle email
	fmt.Println("Will handle email :)")

	return nil
}

func main() {
	flag.Parse()

	server := &smtpd.Server{
		WelcomeMessage:   *welcomeMsg,
		RecipientChecker: recipientChecker,
		Handler:          handler,
	}

	fmt.Println("Starting server...")
	server.ListenAndServe(*inAddr)
}
