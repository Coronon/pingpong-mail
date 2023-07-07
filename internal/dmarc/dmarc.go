package dmarc

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"strings"

	"blitiri.com.ar/go/spf"
	"github.com/chrj/smtpd"
	"github.com/coronon/pingpong-mail/internal/util"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
	"go.uber.org/zap"
	"golang.org/x/net/publicsuffix"
)

var (
	ErrFromHeaderInvalid = errors.New("<From:> header is invalid")
	ErrSPFCantValidate   = errors.New("SPF can not be validated")
	ErrDKIMCantValidate  = errors.New("DKIM can not be validated")
	ErrDMARCFailed       = errors.New("DMARC failed or sender could not be validated")
)

// Fully validate DMARC compliance including alignment
func CheckDmarc(
	peer *smtpd.Peer,
	env *smtpd.Envelope,
	parsedMail *mail.Message,
	senderDomain string,
) error {
	// Determine sender <From:> header domain
	fromHeaderParsed, err := util.GetFromAddress(parsedMail.Header.Get("From"))
	if err != nil {
		zap.S().Debugw("Can't get <From:> address", "error", err)
		return err
	}
	fromHeaderAddr := util.GetDomainOrFallback(fromHeaderParsed, "")
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

	validSPFDomain, err := getValidSPF(peer, env)
	if err != nil {
		zap.S().Debugw("SPF validation failed", "error", err)
		return err
	}
	isSPFValid := checkAlignment(fromHeaderAddr, validSPFDomain, dmarcRecord.SPFAlignment)

	validDKIMDomains, err := getValidDKIM(peer, env)
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
		zap.S().Debug("DMARC validation failed")
		return ErrDMARCFailed
	}

	// All checks passed -> no error
	zap.S().Debug("DMARC passed")
	return nil
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
		return util.GetDomainOrFallback(env.Sender, peer.HeloName), nil
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
