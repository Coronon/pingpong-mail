package dmarc

import (
	"bytes"
	"fmt"
	"net"
	"strings"

	"blitiri.com.ar/go/spf"
	"github.com/chrj/smtpd"
	"github.com/coronon/pingpong-mail/internal/config"
	"github.com/coronon/pingpong-mail/internal/util"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
	"go.uber.org/zap"
	"golang.org/x/net/publicsuffix"
)

// Fully validate DMARC compliance including alignment
func CheckDmarc(
	peer *smtpd.Peer,
	env *smtpd.Envelope,
	fromHeaderDomain string,
	senderDomain string,
) error {
	// Check DMARC framework
	dmarcRecord, err := dmarc.Lookup(senderDomain)
	if err != nil {
		zap.S().Debugw("DMARC lookup failed", "error", err)
		return config.ErrDMARCFailed
	}

	validSPFDomain, err := getValidSPF(peer, env)
	if err != nil {
		zap.S().Debugw("SPF validation failed", "error", err)
		return err
	}
	isSPFValid := checkAlignment(fromHeaderDomain, validSPFDomain, dmarcRecord.SPFAlignment)

	validDKIMDomains, err := getValidDKIM(peer, env)
	if err != nil {
		zap.S().Debugw("DKIM validation failed", "error", err)
		return err
	}
	isDKIMValid := false
	for i := range validDKIMDomains {
		if checkAlignment(fromHeaderDomain, validDKIMDomains[i], dmarcRecord.DKIMAlignment) {
			isDKIMValid = true
			break
		}
	}

	zap.S().Debugf("SPF valid: %v, DKIM valid: %v -> %v\n", isSPFValid, isDKIMValid, isSPFValid || isDKIMValid)

	if !isSPFValid && !isDKIMValid {
		zap.S().Debug("DMARC validation failed")
		return config.ErrDMARCFailed
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
		return "", config.ErrSPFCantValidate
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
		return validSignatures, config.ErrDKIMCantValidate
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
	fromHeaderDomain string,
	validatedDomain string,
	mode dmarc.AlignmentMode,
) bool {
	// Can't validate empty domains
	if fromHeaderDomain == "" || validatedDomain == "" {
		return false
	}

	// Strict mode -> exact match
	if mode == dmarc.AlignmentStrict {
		return strings.EqualFold(fromHeaderDomain, validatedDomain)
	}

	// Relaxed mode -> main domain match
	fromHeaderBaseDomain, err := publicsuffix.EffectiveTLDPlusOne(fromHeaderDomain)
	if err != nil {
		return false
	}

	validatedBaseDomain, err := publicsuffix.EffectiveTLDPlusOne(validatedDomain)
	if err != nil {
		return false
	}

	return strings.EqualFold(fromHeaderBaseDomain, validatedBaseDomain)
}
