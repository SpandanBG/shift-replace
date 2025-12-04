package server

import (
	"context"
	"fmt"
	"net"
	"runtime/debug"

	"sudocoding.xyz/shiftReplace/handlers"
)

const (
	net_type = "tcp"
	port     = ":1080"
)

// Setup_SOCKS5H_Server - sets up the `socks5h://` server for proxy connections
func Setup_SOCKS5H_Server() {
	listener, err := net.Listen(net_type, port)
	if err != nil {
		panic(err)
	}

	fmt.Println("socks5h:// started on port", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			panic(err)
		}

		go func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Printf("Recovered from panic: %v\nStack Trace:\n%s\n", r, debug.Stack())
				}
			}()

			if err := handlers.Handle_SOCKS5H_Connection(conn, context.Background()); err != nil {
				fmt.Println(err)
			}
		}()
	}
}
