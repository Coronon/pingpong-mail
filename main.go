package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/mail"
	"strings"

	"blitiri.com.ar/go/spf"
	"github.com/chrj/smtpd"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
	"golang.org/x/net/publicsuffix"
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

// Detmine the domain of an email sender or fallback
// While technically an address could have multiple '@' signs, we will fallback
// if there isn't exactly one!
func getDomainOrFallback(address string, fallback string) string {
	domainParts := strings.SplitN(address, "@", 2)
	if len(domainParts) == 2 {
		return domainParts[1]
	} else {
		// Sketchy address
		return fallback
	}
}

// Get raw from address from RFC 5322 address
func getFromAddress(fromHeader string) (string, error) {
	// Check exists
	if fromHeader == "" {
		return "", ErrFromHeaderMissing
	}

	// Check valid RFC 5322 address, e.g. "Barry Gibbs <bg@example.com>"
	fromHeaderParsed, err := mail.ParseAddress(fromHeader)
	if err != nil {
		return "", ErrFromHeaderInvalid
	}

	return fromHeaderParsed.Address, nil
}

// Get domain with valid SPF record
func getValidSPF(peer *smtpd.Peer, env *smtpd.Envelope) (string, error) {
	// Get senders ip address
	tcpAddr, ok := peer.Addr.(*net.TCPAddr)
	if !ok {
		return "", fmt.Errorf("invalid sender address: %v", peer.Addr)
	}

	// Check if `sender` is authorized to send from the given `ip`.
	// The `domain` is used if the sender doesn't have one.
	spfResult, err := spf.CheckHostWithSender(tcpAddr.IP, peer.HeloName, env.Sender)
	if err != nil && (spfResult == spf.PermError || spfResult == spf.TempError) {
		// This is not returned if SPF failes, but if it can't even be validated
		return "", ErrSPFCantValidate
	}

	//? Match return the domain that was validated
	// This is a little ugly but streamlines the flow in `handler`
	if spfResult == spf.Pass {
		return getDomainOrFallback(env.Sender, peer.HeloName), nil
	}

	return "", nil
}

// Get domains with a valid DKIM signature
func getValidDKIM(peer *smtpd.Peer, env *smtpd.Envelope) ([]string, error) {
	validSignatures := make([]string, 0)

	reader := bytes.NewReader(env.Data)

	verifications, err := dkim.Verify(reader)
	if err != nil {
		// This is not returned if DKIM failes, but if it can't even be validated
		return validSignatures, ErrDKIMCantValidate
	}

	// No signatures -> failed
	if len(verifications) == 0 {
		return validSignatures, nil
	}

	for _, v := range verifications {
		if v.Err == nil {
			validSignatures = append(validSignatures, v.Domain)
		}
	}

	return validSignatures, nil
}

// Validate alignment between the <FROM:> header and a validated SPF/DKIM domain
func checkAlignment(
	fromHeaderAddr string,
	validatedAddr string,
	mode dmarc.AlignmentMode,
) bool {
	// Validated address may not be empty
	if validatedAddr == "" {
		return false
	}

	// Strict mode -> exact match
	if mode == dmarc.AlignmentStrict {
		return strings.EqualFold(fromHeaderAddr, validatedAddr)
	}

	// Relaxed mode -> main domain match
	fromHeaderDomain, err := publicsuffix.EffectiveTLDPlusOne(fromHeaderAddr)
	if err != nil {
		return false
	}

	validatedDomain, err := publicsuffix.EffectiveTLDPlusOne(validatedAddr)
	if err != nil {
		return false
	}

	return strings.EqualFold(fromHeaderDomain, validatedDomain)
}
