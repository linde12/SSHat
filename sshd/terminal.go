package sshd

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

type sshConn struct {
	*ssh.ServerConn
}

func (c sshConn) PublicKey() ssh.PublicKey {
	if c.Permissions == nil {
		return nil
	}

	str, ok := c.Permissions.Extensions["pubkey"]
	if !ok {
		return nil
	}

	key, err := ssh.ParsePublicKey([]byte(str))
	if err != nil {
		return nil
	}
	return key
}

func NewTerminalSession(conn *ssh.ServerConn, channels <-chan ssh.NewChannel) (term *Terminal, err error) {
	// Go through available channels
	for ch := range channels {
		if t := ch.ChannelType(); t != "session" {
			ch.Reject(ssh.UnknownChannelType, fmt.Sprintf("Unknown channel type '%s'", t))
			continue
		}

		term, err = NewTerminal(conn, ch)
		if err == nil {
			break
		}
	}

	return term, err
}

type Terminal struct {
	terminal.Terminal
	Conn    sshConn
	Channel ssh.Channel
}

func NewTerminal(conn *ssh.ServerConn, ch ssh.NewChannel) (*Terminal, error) {
	if ch.ChannelType() != "session" {
		return nil, errors.New("Terminal requires SSH session channel")
	}

	channel, requests, err := ch.Accept()
	if err != nil {
		return nil, err
	}

	term := Terminal{
		Terminal: *terminal.NewTerminal(channel, "Connecting"),
		Conn:     sshConn{conn},
		Channel:  channel,
	}
	go term.listen(requests)
	go func() {
		conn.Wait()
		conn.Close()
	}()

	return &term, nil
}

func (t *Terminal) listen(requests <-chan *ssh.Request) {
	var hasShell bool

	for req := range requests {
		var width, height int
		var ok bool

		switch req.Type {
		case "shell":
			if !hasShell {
				ok = true
				hasShell = true
			}
		case "pty-req":
			width, height, ok = parsePtyReq(req.Payload)
			if ok {
				err := t.SetSize(width, height)
				ok = err == nil
			}
		case "window-change":
			width, height, ok = parseWindowChangeReq(req.Payload)
			if ok {
				err := t.SetSize(width, height)
				ok = err == nil
			}
		}

		if req.WantReply {
			req.Reply(ok, nil)
		}
	}
}

func (t *Terminal) Close() error {
	return t.Conn.Close()
}
