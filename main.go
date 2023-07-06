package main

import (
	"flag"
	"fmt"

	"github.com/chrj/smtpd"
)

var (
	welcomeMsg = flag.String("welcome", "PingPong email tester", "Welcome message for SMTP session")
	inAddr     = flag.String("inaddr", "localhost:25", "Address to listen for incoming SMTP on")
	inbox      = flag.String("inbox", "*", "Inbox address to receive email for")
)

// Check valid recipient (if limited)
func recipientChecker(peer smtpd.Peer, addr string) error {
	if *inbox != "*" && addr != *inbox {
		return fmt.Errorf("Please send your test emails to: %v", *inbox)
	}

	return nil
}

func handler(peer smtpd.Peer, env smtpd.Envelope) error {
	return nil
}

func main() {
	flag.Parse()

	server := &smtpd.Server{
		WelcomeMessage:   *welcomeMsg,
		RecipientChecker: recipientChecker,
		Handler:          handler,
	}

	fmt.Println("Starting server...")
	server.ListenAndServe(*inAddr)
}
