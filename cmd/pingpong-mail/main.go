package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/chrj/smtpd"
	"go.uber.org/zap"

	"github.com/coronon/pingpong-mail/internal/app"
	"github.com/coronon/pingpong-mail/internal/config"
	"github.com/coronon/pingpong-mail/internal/util"
)

var (
	isVerbose  = flag.Bool("v", false, "Enable debug output (might include sensitive data!)")
	configPath = flag.String("c", "pingpong.yml", "Path to a configuration file to use")
)

func init() {
	// Setup logging
	cfg := zap.NewProductionConfig()

	logger, _ := cfg.Build()
	defer logger.Sync()

	zap.ReplaceGlobals(logger)
}

func main() {
	flag.Parse()

	var protocolLogger *log.Logger
	// Setup verbose logging
	if *isVerbose {
		verboseCfg := zap.NewDevelopmentConfig()

		verboseLogger, _ := verboseCfg.Build()
		defer verboseLogger.Sync()

		zap.ReplaceGlobals(verboseLogger)

		protocolLogger = log.New(util.ZapLogWrapper{}, "", 0)
	}

	// Load configuration
	config.Cnf = config.ReadConfig(*configPath)
	config.LoadTLS()

	// Start STMP server
	server := &smtpd.Server{
		Hostname:       config.Cnf.ServerName,
		WelcomeMessage: config.Cnf.SMTPWelcomeMessage,

		MaxRecipients:  1,
		MaxMessageSize: config.Cnf.MaxMessageSize,
		TLSConfig:      config.TLSConfig,

		RecipientChecker: app.CheckRecipient,
		Handler:          app.HandleIncoming,

		ProtocolLogger: protocolLogger,
	}

	bindAddr := fmt.Sprintf("%v:%v", config.Cnf.BindHost, config.Cnf.BindPort)

	zap.S().Infof("Starting server on: %v", bindAddr)
	server.ListenAndServe(bindAddr)
}
