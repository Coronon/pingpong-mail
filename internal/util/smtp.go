package util

import (
	"net"
	_ "unsafe"
)

type SendableMail interface{}

//go:linkname SmtpExchange mailyak.smtpExchange
func SmtpExchange(m SendableMail, conn net.Conn, serverName string, tryTLSUpgrade bool) error
