package config

import (
	"errors"
	"os"
	"regexp"

	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
)

// Uniform error messages used throughout the application
var (
	ErrInvalidRcpt       = errors.New("Test emails are not accepted for that inbox")
	ErrCantParseBody     = errors.New("Could not parse message body")
	ErrFromHeaderMissing = errors.New("<From:> header is missing")
	ErrFromHeaderInvalid = errors.New("<From:> header is invalid")
	ErrSPFCantValidate   = errors.New("SPF can not be validated")
	ErrDKIMCantValidate  = errors.New("DKIM can not be validated")
	ErrDMARCFailed       = errors.New("DMARC failed or sender could not be validated")
)

// Current configuration of the application
var Cnf Config
var RestrictInboxRegex *regexp.Regexp

type Config struct {
	BindHost                string `yaml:"bind_host"`
	BindPort                int    `yaml:"bind_port"`
	TLSCertPath             string `yaml:"tls_cert_path,omitempty"`
	TLSKeyPath              string `yaml:"tls_key_path,omitempty"`
	TLSCacheDuration        int    `yaml:"tls_cache_duration,omitempty"`
	TLSCacheExpiryThreshold int    `yaml:"tls_cache_expiry_threshold,omitempty"`
	SMTPWelcomeMessage      string `yaml:"smtp_welcome_message"`
	ServerName              string `yaml:"server_name"`
	DeliveryPorts           []int  `yaml:"delivery_ports"`
	RestrictInbox           string `yaml:"restrict_inbox"`
	ForceSubjectPrefix      string `yaml:"force_subject_prefix"`
	MaxMessageSize          int    `yaml:"max_message_size"`
	EnableDmarc             bool   `yaml:"enable_dmarc"`
	ReplyAddress            string `yaml:"reply_address"`
	ReplyFrom               string `yaml:"reply_from"`
	ReplySubject            string `yaml:"reply_subject"`
	ReplyMessage            string `yaml:"reply_message"`
}

// Read and parse a yaml config at path
func ReadConfig(path string) Config {
	data, err := os.ReadFile(path)
	if err != nil {
		zap.S().Fatalf("Error reading config: %v", err)
	}

	c := Config{}

	err = yaml.Unmarshal(data, &c)
	if err != nil {
		zap.S().Fatalf("Error parsing config: %v", err)
	}

	// Handle RestrictInboxRegex
	if c.RestrictInbox != "" {
		RestrictInboxRegex, err = regexp.Compile(c.RestrictInbox)
		if err != nil {
			zap.S().Fatalw("Error parsing inbox restriction regex",
				"restrict_inbox", c.RestrictInbox,
				"error", err,
			)
		}
	}

	return c
}
