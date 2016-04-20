package sshd

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

// Listener contains information related to the ssh socket
type Listener struct {
	net.Listener
	config *ssh.ServerConfig
}

// Listen will set up a tcp-listener
func Listen(addr string, config *ssh.ServerConfig) (*Listener, error) {
	socket, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Listener{Listener: socket, config: config}, nil
}

func (l *Listener) handleConnection(conn net.Conn) (*Terminal, error) {
	// TODO: limit num connections?
	// Upgrade TCP conn to SSH conn
	sshConn, channels, requests, err := ssh.NewServerConn(conn, l.config)
	if err != nil {
		return nil, err
	}

	// TODO: Research what this does...
	go ssh.DiscardRequests(requests)
	return NewTerminalSession(sshConn, channels)
}

func (l *Listener) ServeTerminal() <-chan *Terminal {
	ch := make(chan *Terminal)

	go func() {
		defer l.Close()
		defer close(ch)
		for {
			conn, err := l.Accept()
			if err != nil {
				// TODO: Log accept failed
				fmt.Fprintf(os.Stderr, "wat, accept failed")
				return
			}

			term, err := l.handleConnection(conn)
			if err != nil {
				// TODO: Log SSH handshake failed
				fmt.Fprintf(os.Stderr, "wat, handshake failed")
				return
			}
			ch <- term
		}
	}()
	return ch
}
