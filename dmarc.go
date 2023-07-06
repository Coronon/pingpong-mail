package main

import (
	"bytes"
	"fmt"
	"net"
	"strings"

	"blitiri.com.ar/go/spf"
	"github.com/chrj/smtpd"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
	"golang.org/x/net/publicsuffix"
)

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
