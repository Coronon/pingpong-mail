package util

import (
	"net"
	"net/mail"
	"strings"

	"github.com/coronon/pingpong-mail/internal/config"
	"go.uber.org/zap"
)

// Detmine the domain of an email sender or fallback.
// While technically an address could have multiple '@' signs, we will fallback
// if there isn't exactly one!
func GetDomainOrFallback(address string, fallback string) string {
	domainParts := strings.SplitN(address, "@", 2)
	if len(domainParts) == 2 {
		return domainParts[1]
	} else {
		// Sketchy address
		return fallback
	}
}

// Get raw from address from RFC 5322 address
func GetRawFromHeaderAddress(fromHeader string) (string, error) {
	// Check exists
	if fromHeader == "" {
		return "", config.ErrFromHeaderMissing
	}

	// Check valid RFC 5322 address, e.g. "Barry Gibbs <bg@example.com>"
	fromHeaderParsed, err := mail.ParseAddress(fromHeader)
	if err != nil {
		return "", config.ErrFromHeaderInvalid
	}

	return fromHeaderParsed.Address, nil
}

// Lookup MX records for `domain`, sorted by preference
func GetMXDomains(domain string) []*net.MX {
	zap.S().Debugw("Looking up MX records", "domain", domain)

	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		zap.S().Infow("Can't lookup MX records", "domain", domain)
		return make([]*net.MX, 0)
	}
	if len(mxRecords) == 0 {
		zap.S().Infow("No MX records found", "domain", domain)
		return mxRecords
	}

	zap.S().Debugw("Found MX records",
		"domain", domain,
		"records", mxRecords,
	)

	return mxRecords
}

// Used to pipe normal log.Logger output into the zap logger
type ZapLogWrapper struct{}

func (_ ZapLogWrapper) Write(p []byte) (n int, err error) {
	l := len(p)
	msg := string(p[:l])
	// The last byte would be the newline the client terminated its command with
	trimmed := strings.TrimSuffix(msg, "\n")

	// Split into direction (sending/received) and message (text)
	parts := strings.SplitN(trimmed, ":", 2)

	var direction string
	var text string
	if len(parts) == 2 {
		direction = parts[0]
		text = parts[1][1:]
	} else {
		text = parts[0][1:]
	}

	// Actually log to output
	zap.S().Debugw("SMTP",
		"direction", direction,
		"text", text,
	)

	return l, nil
}
