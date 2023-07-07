package config

import (
	"os"

	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
)

// Current configuration of the application
var Cnf Config

type Config struct {
	BindHost           string `yaml:"bind_host"`
	BindPort           int    `yaml:"bind_port"`
	SMTPWelcomeMessage string `yaml:"smtp_welcome_message"`
	ServerName         string `yaml:"server_name"`
	DeliveryPorts      []int  `yaml:"delivery_ports"`
	RestrictInbox      string `yaml:"restrict_inbox"`
	ForceSubjectPrefix string `yaml:"force_subject_prefix"`
	EnableDmarc        bool   `yaml:"enable_dmarc"`
	ReplyAddress       string `yaml:"reply_address"`
	ReplyFrom          string `yaml:"reply_from"`
	ReplySubject       string `yaml:"reply_subject"`
	ReplyMessage       string `yaml:"reply_message"`
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

	return c
}
