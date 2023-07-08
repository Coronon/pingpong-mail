package config

import (
	"crypto/tls"
	"crypto/x509"
	"time"

	"go.uber.org/zap"
)

var (
	TLSConfig *tls.Config

	tlsCert        *tls.Certificate
	tlsExpiresSoon bool
	tlsNextReload  time.Time
)

// Attempt to setup dynamic TLS configuration
//
// Must be called AFTER the configuration was initialized.
func LoadTLS() {
	// Check paths configured
	if Cnf.TLSCertPath == "" || Cnf.TLSKeyPath == "" {
		zap.S().Debugw("TLS not configured",
			"cert_path", Cnf.TLSCertPath,
			"key_path", Cnf.TLSKeyPath,
		)

		return
	}

	// Configure static TLS certificates
	if Cnf.TLSCacheDuration == -1 {
		zap.S().Debugw("TLS configured in static mode",
			"cert_path", Cnf.TLSCertPath,
			"key_path", Cnf.TLSKeyPath,
		)

		cert, err := tls.LoadX509KeyPair(Cnf.TLSCertPath, Cnf.TLSKeyPath)
		if err != nil {
			zap.S().Fatalw("Could not load certificate",
				"cert_path", Cnf.TLSCertPath,
				"key_path", Cnf.TLSKeyPath,
				"error", err,
			)
		}

		TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	} else {
		zap.S().Debugw("TLS configured in dynamic mode",
			"cert_path", Cnf.TLSCertPath,
			"key_path", Cnf.TLSKeyPath,
			"cache_duration", Cnf.TLSCacheDuration,
		)

		TLSConfig = &tls.Config{
			GetCertificate: loadCertificate,
		}
	}
}

// Dynamically loads the required TLS certificate
func loadCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	now := time.Now()

	//? Attempt to use cached certificate
	if tlsCert != nil && !tlsExpiresSoon && tlsNextReload.After(now) {
		zap.S().Debugw("Using cached TLS certificate",
			"cert_path", Cnf.TLSCertPath,
			"key_path", Cnf.TLSKeyPath,
			"next_reload", tlsNextReload,
		)

		return tlsCert, nil
	}

	//? Reload certificate
	zap.S().Debugw("Loading TLS certificate",
		"cert_path", Cnf.TLSCertPath,
		"key_path", Cnf.TLSKeyPath,
	)

	cert, err := tls.LoadX509KeyPair(Cnf.TLSCertPath, Cnf.TLSKeyPath)
	if err != nil {
		zap.S().Debugw("Could not load TLS certificate",
			"cert_path", Cnf.TLSCertPath,
			"key_path", Cnf.TLSKeyPath,
			"error", err,
		)
		return nil, err
	}

	// Parse leaf cert again to access details
	parsedCert, err := x509.ParseCertificate(cert.Certificate[0])

	// Only enable caching if the certificate does not expire in the next 48 hours
	tlsExpiresSoon = parsedCert.
		NotAfter.
		Add(-time.Duration(Cnf.TLSCacheExpiryThreshold) * time.Minute).
		Before(now)

	tlsNextReload = now.Add(time.Duration(Cnf.TLSCacheDuration) * time.Second)
	tlsCert = &cert

	zap.S().Debugw("TLS certificate loaded",
		"cert_path", Cnf.TLSCertPath,
		"key_path", Cnf.TLSKeyPath,
		"expires_soon", tlsExpiresSoon,
		"next_reload", tlsNextReload,
	)

	return &cert, nil
}
