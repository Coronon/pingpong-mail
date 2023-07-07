package main

import (
	"flag"
	"fmt"

	"github.com/chrj/smtpd"
	"go.uber.org/zap"

	"github.com/coronon/pingpong-mail/internal/app"
	"github.com/coronon/pingpong-mail/internal/config"
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

	// Load configuration
	config.Cnf = config.ReadConfig(*configPath)

	// Setup verbose logging
	if *isVerbose {
		verboseCfg := zap.NewDevelopmentConfig()

		verboseLogger, _ := verboseCfg.Build()
		defer verboseLogger.Sync()

		zap.ReplaceGlobals(verboseLogger)
	}

	// Start STMP server
	server := &smtpd.Server{
		WelcomeMessage:   config.Cnf.SMTPWelcomeMessage,
		RecipientChecker: app.CheckRecipient,
		Handler:          app.HandleIncoming,
	}

	bindAddr := fmt.Sprintf("%v:%v", config.Cnf.BindHost, config.Cnf.BindPort)

	zap.S().Infof("Starting server on: %v", bindAddr)
	server.ListenAndServe(bindAddr)
}