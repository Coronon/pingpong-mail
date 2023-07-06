package main

import (
	"net/mail"
	"strings"
)

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
